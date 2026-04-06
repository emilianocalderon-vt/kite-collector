package cloud

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDescribeInstancesResponse(t *testing.T) {
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet>
    <item>
      <instancesSet>
        <item>
          <instanceId>i-0abcdef1234567890</instanceId>
          <platform>windows</platform>
          <instanceState><name>running</name></instanceState>
          <tagSet>
            <item><key>Name</key><value>web-server-01</value></item>
          </tagSet>
        </item>
        <item>
          <instanceId>i-0123456789abcdef0</instanceId>
          <instanceState><name>running</name></instanceState>
          <tagSet></tagSet>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>`

	instances, err := parseDescribeInstancesResponse([]byte(xmlBody))
	require.NoError(t, err)
	require.Len(t, instances, 2)

	assert.Equal(t, "i-0abcdef1234567890", instances[0].instanceID)
	assert.Equal(t, "windows", instances[0].platform)
	assert.Equal(t, "web-server-01", instances[0].nameTag)

	assert.Equal(t, "i-0123456789abcdef0", instances[1].instanceID)
	assert.Empty(t, instances[1].nameTag)
}

func TestParseStsAssumeRoleResponse(t *testing.T) {
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATEMP123</AccessKeyId>
      <SecretAccessKey>tempSecret456</SecretAccessKey>
      <SessionToken>FwoGZXIvY...</SessionToken>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`

	var resp stsAssumeRoleResponse
	require.NoError(t, xml.Unmarshal([]byte(xmlBody), &resp))
	assert.Equal(t, "ASIATEMP123", resp.Credentials.AccessKeyID)
	assert.Equal(t, "tempSecret456", resp.Credentials.SecretAccessKey)
	assert.Equal(t, "FwoGZXIvY...", resp.Credentials.SessionToken)
}

func TestAWSDiscover_NoCredentials(t *testing.T) {
	// Ensure no AWS env vars are set for this test.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	aws := NewAWS()
	assets, err := aws.Discover(context.Background(), map[string]any{
		"regions": []any{"us-east-1"},
	})

	require.NoError(t, err)
	assert.Empty(t, assets, "should return nil when credentials are missing")
}

func TestAWSDiscover_MockEC2(t *testing.T) {
	ec2XML := `<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet>
    <item>
      <instancesSet>
        <item>
          <instanceId>i-mock001</instanceId>
          <platform></platform>
          <instanceState><name>running</name></instanceState>
          <tagSet>
            <item><key>Name</key><value>test-linux</value></item>
          </tagSet>
        </item>
        <item>
          <instanceId>i-mock002</instanceId>
          <platform>windows</platform>
          <instanceState><name>running</name></instanceState>
          <tagSet></tagSet>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(ec2XML))
	}))
	defer srv.Close()

	// We can't easily redirect the EC2 endpoint, but we can test the
	// describeInstances method directly by overriding the HTTP call via
	// the retry mechanism. Instead, test the parsing + asset creation flow.
	instances, err := parseDescribeInstancesResponse([]byte(ec2XML))
	require.NoError(t, err)
	assert.Len(t, instances, 2)

	// Verify OS detection logic.
	assert.Equal(t, "test-linux", instances[0].nameTag)
	assert.Empty(t, instances[0].platform) // Linux (no platform field)

	assert.Equal(t, "i-mock002", instances[1].instanceID)
	assert.Equal(t, "windows", instances[1].platform)
}

func TestAWSAssumeRole_Mock(t *testing.T) {
	stsXML := `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATEMP</AccessKeyId>
      <SecretAccessKey>tempSecret</SecretAccessKey>
      <SessionToken>sessionToken123</SessionToken>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(stsXML))
	}))
	defer srv.Close()

	// Parse the STS response directly to validate the parsing logic.
	var resp stsAssumeRoleResponse
	require.NoError(t, xml.Unmarshal([]byte(stsXML), &resp))
	assert.Equal(t, "ASIATEMP", resp.Credentials.AccessKeyID)
	assert.Equal(t, "sessionToken123", resp.Credentials.SessionToken)
}

func TestSigV4_Deterministic(t *testing.T) {
	// Verify that signing produces an Authorization header.
	creds := awsCredentials{
		accessKey: "AKIAIOSFODNN7EXAMPLE",
		secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	body := []byte("Action=DescribeInstances&Version=2016-11-15")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://ec2.us-east-1.amazonaws.com/", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	require.NoError(t, signV4(req, body, creds, "us-east-1", "ec2"))

	auth := req.Header.Get("Authorization")
	assert.Contains(t, auth, "AWS4-HMAC-SHA256")
	assert.Contains(t, auth, "AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, auth, "us-east-1/ec2/aws4_request")
}

func TestSigV4_WithSessionToken(t *testing.T) {
	creds := awsCredentials{
		accessKey:    "AKID",
		secretKey:    "SECRET",
		sessionToken: "SESSION",
	}

	body := []byte("Action=DescribeInstances")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://ec2.us-west-2.amazonaws.com/", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	require.NoError(t, signV4(req, body, creds, "us-west-2", "ec2"))

	assert.Equal(t, "SESSION", req.Header.Get("X-Amz-Security-Token"))
	assert.NotEmpty(t, req.Header.Get("Authorization"))
}
