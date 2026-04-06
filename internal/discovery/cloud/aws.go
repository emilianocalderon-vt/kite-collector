package cloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// AWS implements discovery.Source by listing EC2 instances across one or more
// AWS regions using direct HTTP calls to the EC2 Query API with SigV4 signing.
// No external SDK is required.
type AWS struct{}

// NewAWS returns a new AWS discovery source.
func NewAWS() *AWS {
	return &AWS{}
}

// Name returns the stable identifier for this source.
func (a *AWS) Name() string { return "aws_ec2" }

// Discover lists EC2 instances in the configured regions and returns them
// as assets. Credentials are read from standard AWS environment variables.
// If credentials are not available, the method logs a warning and returns nil
// (graceful degradation).
//
// When assume_role is set, STS AssumeRole is called first to obtain temporary
// credentials for cross-account access. The source identity credentials must
// have sts:AssumeRole permission on the target role ARN.
//
// Supported config keys:
//
//	regions     – []any of AWS region strings (e.g. ["us-east-1", "eu-west-1"])
//	assume_role – string ARN of the IAM role to assume for cross-account access
func (a *AWS) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	regions := toStringSlice(cfg["regions"])
	role := toString(cfg["assume_role"])

	slog.Info("aws_ec2: starting discovery",
		"regions", regions,
		"assume_role_set", role != "",
	)

	creds := loadAWSCredentials()
	if creds.accessKey == "" || creds.secretKey == "" {
		slog.Warn("aws_ec2: AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set, skipping discovery")
		return nil, nil
	}

	// AssumeRole for cross-account access when configured.
	if role != "" {
		slog.Info("aws_ec2: assuming role via STS", "role_arn", role)
		stsRegion := creds.region
		if stsRegion == "" {
			stsRegion = "us-east-1"
		}
		assumed, err := a.assumeRole(ctx, creds, stsRegion, role)
		if err != nil {
			slog.Error("aws_ec2: AssumeRole failed, falling back to source credentials",
				"role_arn", role,
				"error", err,
			)
			// Graceful degradation: continue with source credentials.
		} else {
			creds = assumed
			slog.Info("aws_ec2: using assumed role credentials")
		}
	}

	if len(regions) == 0 {
		if creds.region != "" {
			regions = []string{creds.region}
		} else {
			regions = []string{"us-east-1"}
		}
		slog.Info("aws_ec2: no regions configured, using default", "regions", regions)
	}

	var assets []model.Asset

	for _, region := range regions {
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		slog.Info("aws_ec2: discovering instances", "region", region)

		instances, err := a.describeInstances(ctx, creds, region)
		if err != nil {
			slog.Error("aws_ec2: DescribeInstances failed, returning partial results",
				"region", region,
				"error", err,
			)
			continue
		}

		now := time.Now().UTC()
		for _, inst := range instances {
			hostname := inst.instanceID
			if inst.nameTag != "" {
				hostname = inst.nameTag
			}

			osFamily := "linux"
			if strings.EqualFold(inst.platform, "windows") {
				osFamily = "windows"
			}

			asset := model.Asset{
				ID:              uuid.Must(uuid.NewV7()),
				AssetType:       model.AssetTypeCloudInstance,
				Hostname:        hostname,
				OSFamily:        osFamily,
				DiscoverySource: "aws_ec2",
				FirstSeenAt:     now,
				LastSeenAt:      now,
				IsAuthorized:    model.AuthorizationUnknown,
				IsManaged:       model.ManagedUnknown,
				Environment:     region,
			}
			asset.ComputeNaturalKey()
			assets = append(assets, asset)
		}

		slog.Info("aws_ec2: region complete",
			"region", region,
			"instances_found", len(instances),
		)
	}

	slog.Info("aws_ec2: discovery complete", "total_assets", len(assets))
	return assets, nil
}

// awsCredentials holds AWS authentication material read from the environment.
type awsCredentials struct {
	accessKey    string
	secretKey    string
	sessionToken string
	region       string
}

// loadAWSCredentials reads credentials from standard environment variables.
func loadAWSCredentials() awsCredentials {
	return awsCredentials{
		accessKey:    os.Getenv("AWS_ACCESS_KEY_ID"),
		secretKey:    os.Getenv("AWS_SECRET_ACCESS_KEY"),
		sessionToken: os.Getenv("AWS_SESSION_TOKEN"),
		region:       os.Getenv("AWS_REGION"),
	}
}

// ec2Instance holds the fields we extract from an EC2 DescribeInstances response.
type ec2Instance struct {
	instanceID string
	platform   string
	nameTag    string
	state      string
}

// describeInstances calls the EC2 DescribeInstances API for the given region
// and returns parsed instance records. The call is wrapped with retry logic
// for transient failures.
func (a *AWS) describeInstances(ctx context.Context, creds awsCredentials, region string) ([]ec2Instance, error) {
	endpoint := fmt.Sprintf("https://ec2.%s.amazonaws.com/", region)

	params := url.Values{}
	params.Set("Action", "DescribeInstances")
	params.Set("Version", "2016-11-15")
	// Only discover running instances.
	params.Set("Filter.1.Name", "instance-state-name")
	params.Set("Filter.1.Value.1", "running")

	body := params.Encode()

	resp, err := doWithRetry(ctx, "aws_ec2", func() (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
		if reqErr != nil {
			return nil, fmt.Errorf("creating request: %w", reqErr)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

		if signErr := signV4(req, []byte(body), creds, region, "ec2"); signErr != nil {
			return nil, fmt.Errorf("signing request: %w", signErr)
		}
		return http.DefaultClient.Do(req)
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return parseDescribeInstancesResponse(respBody)
}

// ---------------------------------------------------------------------------
// AWS STS AssumeRole
// ---------------------------------------------------------------------------

// stsAssumeRoleResponse holds the fields parsed from an STS AssumeRole XML
// response.
type stsAssumeRoleResponse struct {
	XMLName     xml.Name `xml:"AssumeRoleResponse"`
	Credentials struct {
		AccessKeyID     string `xml:"AccessKeyId"`
		SecretAccessKey string `xml:"SecretAccessKey"`
		SessionToken    string `xml:"SessionToken"`
	} `xml:"AssumeRoleResult>Credentials"`
}

// assumeRole calls the STS AssumeRole API and returns temporary credentials.
// The source credentials must have sts:AssumeRole permission on the given
// roleARN.
func (a *AWS) assumeRole(ctx context.Context, creds awsCredentials, region, roleARN string) (awsCredentials, error) {
	endpoint := fmt.Sprintf("https://sts.%s.amazonaws.com/", region)

	params := url.Values{}
	params.Set("Action", "AssumeRole")
	params.Set("Version", "2011-06-15")
	params.Set("RoleArn", roleARN)
	params.Set("RoleSessionName", "kite-collector")
	params.Set("DurationSeconds", "3600")

	body := params.Encode()

	resp, err := doWithRetry(ctx, "aws_sts", func() (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
		if reqErr != nil {
			return nil, fmt.Errorf("creating request: %w", reqErr)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

		if signErr := signV4(req, []byte(body), creds, region, "sts"); signErr != nil {
			return nil, fmt.Errorf("signing request: %w", signErr)
		}
		return http.DefaultClient.Do(req)
	})
	if err != nil {
		return awsCredentials{}, fmt.Errorf("STS AssumeRole: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("reading STS response: %w", err)
	}

	var stsResp stsAssumeRoleResponse
	if err := xml.Unmarshal(respBody, &stsResp); err != nil {
		return awsCredentials{}, fmt.Errorf("parsing STS response: %w", err)
	}

	if stsResp.Credentials.AccessKeyID == "" {
		return awsCredentials{}, fmt.Errorf("STS AssumeRole returned empty credentials")
	}

	return awsCredentials{
		accessKey:    stsResp.Credentials.AccessKeyID,
		secretKey:    stsResp.Credentials.SecretAccessKey,
		sessionToken: stsResp.Credentials.SessionToken,
		region:       region,
	}, nil
}

// ---------------------------------------------------------------------------
// EC2 XML response structures
// ---------------------------------------------------------------------------

type describeInstancesResponse struct {
	XMLName        xml.Name         `xml:"DescribeInstancesResponse"`
	ReservationSet []reservationSet `xml:"reservationSet>item"`
}

type reservationSet struct {
	InstancesSet []instanceItem `xml:"instancesSet>item"`
}

type instanceItem struct {
	InstanceID string   `xml:"instanceId"`
	Platform   string   `xml:"platform"`
	State      stateXML `xml:"instanceState"`
	TagSet     []tagXML `xml:"tagSet>item"`
}

type stateXML struct {
	Name string `xml:"name"`
}

type tagXML struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}

// parseDescribeInstancesResponse parses the EC2 XML response into ec2Instance
// records.
func parseDescribeInstancesResponse(data []byte) ([]ec2Instance, error) {
	var resp describeInstancesResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing EC2 XML response: %w", err)
	}

	var instances []ec2Instance
	for _, res := range resp.ReservationSet {
		for _, item := range res.InstancesSet {
			inst := ec2Instance{
				instanceID: item.InstanceID,
				platform:   item.Platform,
				state:      item.State.Name,
			}
			for _, tag := range item.TagSet {
				if tag.Key == "Name" {
					inst.nameTag = tag.Value
					break
				}
			}
			instances = append(instances, inst)
		}
	}
	return instances, nil
}

// ---------------------------------------------------------------------------
// AWS SigV4 signing
// ---------------------------------------------------------------------------

// signV4 computes the AWS Signature Version 4 for an HTTP request and sets
// the Authorization header. This is a minimal implementation that supports
// the POST-based EC2 Query API.
func signV4(req *http.Request, payload []byte, creds awsCredentials, region, service string) error {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Set required headers before canonical header computation.
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Host", req.URL.Host)
	if creds.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.sessionToken)
	}

	// Step 1: Create canonical request.
	payloadHash := sha256Hex(payload)

	canonicalHeaders, signedHeaders := buildCanonicalHeaders(req)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQueryString(req.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// Step 2: Create string to sign.
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// Step 3: Calculate signing key.
	signingKey := deriveSigningKey(creds.secretKey, dateStamp, region, service)

	// Step 4: Calculate signature.
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Step 5: Build Authorization header.
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.accessKey,
		credentialScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", authHeader)

	return nil
}

// buildCanonicalHeaders produces the canonical headers string and the
// signed-headers list. Headers are lowercased, sorted, and trimmed per the
// SigV4 specification.
func buildCanonicalHeaders(req *http.Request) (canonicalHeaders, signedHeaders string) {
	type kv struct {
		key, value string
	}

	var headers []kv
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		// Only sign content-type, host, and x-amz-* headers.
		if lk == "content-type" || lk == "host" || strings.HasPrefix(lk, "x-amz-") {
			headers = append(headers, kv{
				key:   lk,
				value: strings.TrimSpace(strings.Join(vs, ",")),
			})
		}
	}

	sort.Slice(headers, func(i, j int) bool {
		return headers[i].key < headers[j].key
	})

	var chBuf, shBuf strings.Builder
	for i, h := range headers {
		chBuf.WriteString(h.key)
		chBuf.WriteByte(':')
		chBuf.WriteString(h.value)
		chBuf.WriteByte('\n')
		if i > 0 {
			shBuf.WriteByte(';')
		}
		shBuf.WriteString(h.key)
	}

	return chBuf.String(), shBuf.String()
}

// canonicalURI returns the URI-encoded path component. For EC2 the path is
// always "/".
func canonicalURI(u *url.URL) string {
	path := u.Path
	if path == "" {
		path = "/"
	}
	return path
}

// canonicalQueryString returns the sorted query string. For POST requests
// the query string is typically empty.
func canonicalQueryString(u *url.URL) string {
	params := u.Query()
	if len(params) == 0 {
		return ""
	}
	// Sort by key, then by value for multi-value keys.
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf strings.Builder
	first := true
	for _, k := range keys {
		vs := params[k]
		sort.Strings(vs)
		for _, v := range vs {
			if !first {
				buf.WriteByte('&')
			}
			first = false
			buf.WriteString(url.QueryEscape(k))
			buf.WriteByte('=')
			buf.WriteString(url.QueryEscape(v))
		}
	}
	return buf.String()
}

// deriveSigningKey produces the SigV4 signing key via the HMAC chain:
// kDate -> kRegion -> kService -> kSigning.
func deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// hmacSHA256 computes HMAC-SHA256.
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// sha256Hex returns the lowercase hex-encoded SHA-256 digest of data.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// truncate returns at most maxLen characters from s.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ensure AWS satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*AWS)(nil)
