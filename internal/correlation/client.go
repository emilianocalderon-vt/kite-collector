package correlation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MaxCPEsPerRequest is the server-enforced limit on CPEs per correlation
// request (RFC-0077 §4.1.1).
const MaxCPEsPerRequest = 10_000

// Client calls the SaaS CPE-to-CVE correlation API.
type Client struct {
	endpoint   string
	httpClient *http.Client
}

// NewClient creates a correlation API client. The endpoint should be the
// base URL of the SaaS (e.g. "https://api.vulnertrack.dev"). TLS config
// is optional; pass nil for default system roots.
func NewClient(endpoint string, tlsConfig *tls.Config) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	return &Client{
		endpoint: endpoint,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// Correlate sends a deduplicated CPE list to the SaaS and returns enriched
// CVE matches. The SaaS sees only the CPE set — never which hosts run
// which software. If the CPE list exceeds MaxCPEsPerRequest, it is
// truncated and a warning is logged.
func (c *Client) Correlate(ctx context.Context, cpes []string) (*Response, error) {
	if len(cpes) == 0 {
		return &Response{ComputedAt: time.Now()}, nil
	}
	if len(cpes) > MaxCPEsPerRequest {
		cpes = cpes[:MaxCPEsPerRequest]
	}

	body, err := json.Marshal(Request{CPEs: cpes})
	if err != nil {
		return nil, fmt.Errorf("correlation: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.endpoint+"/v1/correlate",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("correlation: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("correlation: send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("correlation: API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("correlation: decode response: %w", err)
	}
	return &result, nil
}
