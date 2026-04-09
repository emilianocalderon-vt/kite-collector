package safenet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
		opts    []Option
	}{
		{
			name: "valid https with public IP",
			raw:  "https://8.8.8.8/api/v1",
		},
		{
			name: "valid https with public IP and port",
			raw:  "https://8.8.8.8:443/",
		},
		{
			name:    "http rejected by default",
			raw:     "http://8.8.8.8/api",
			wantErr: "uses HTTP; HTTPS required",
		},
		{
			name: "http allowed with opt-in",
			raw:  "http://8.8.8.8/api",
			opts: []Option{AllowHTTP()},
		},
		{
			name:    "file scheme rejected",
			raw:     "file:///etc/passwd",
			wantErr: "disallowed scheme",
		},
		{
			name:    "gopher scheme rejected",
			raw:     "gopher://evil.com/",
			wantErr: "disallowed scheme",
		},
		{
			name:    "ftp scheme rejected",
			raw:     "ftp://files.example.com/",
			wantErr: "disallowed scheme",
		},
		{
			name:    "empty string",
			raw:     "",
			wantErr: "has no scheme",
		},
		{
			name:    "no scheme",
			raw:     "example.com/api",
			wantErr: "has no scheme",
		},
		{
			name:    "loopback IP rejected",
			raw:     "https://127.0.0.1/",
			wantErr: "private/local address",
		},
		{
			name:    "private IP 10.x rejected",
			raw:     "https://10.0.0.1/",
			wantErr: "private/local address",
		},
		{
			name:    "private IP 172.16.x rejected",
			raw:     "https://172.16.0.1/",
			wantErr: "private/local address",
		},
		{
			name:    "private IP 192.168.x rejected",
			raw:     "https://192.168.1.1/",
			wantErr: "private/local address",
		},
		{
			name:    "link-local 169.254.169.254 rejected (AWS metadata)",
			raw:     "https://169.254.169.254/latest/meta-data/",
			wantErr: "private/local address",
		},
		{
			name: "private IP allowed with opt-in",
			raw:  "https://192.168.1.100:55000/",
			opts: []Option{AllowPrivate()},
		},
		{
			name: "loopback allowed with opt-in",
			raw:  "https://127.0.0.1:8443/",
			opts: []Option{AllowPrivate()},
		},
		{
			name:    "unresolvable host",
			raw:     "https://this-host-does-not-exist.invalid/",
			wantErr: "cannot resolve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ValidateEndpoint(tt.raw, tt.opts...)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, u)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, u)
			}
		})
	}
}

func TestSanitizePathSegment(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		want    string
		wantErr string
	}{
		{
			name: "simple alphanumeric",
			id:   "abc123",
			want: "abc123",
		},
		{
			name: "with dots",
			id:   "agent.001",
			want: "agent.001",
		},
		{
			name: "with dashes",
			id:   "vm-node-01",
			want: "vm-node-01",
		},
		{
			name: "with underscores",
			id:   "site_default",
			want: "site_default",
		},
		{
			name: "uppercase",
			id:   "NodeA",
			want: "NodeA",
		},
		{
			name:    "empty",
			id:      "",
			wantErr: "empty path segment",
		},
		{
			name:    "path traversal dot-dot",
			id:      "../../../etc/passwd",
			wantErr: "path traversal detected",
		},
		{
			name:    "URL-encoded traversal",
			id:      "%2e%2e/admin",
			wantErr: "path traversal detected",
		},
		{
			name:    "double URL-encoded traversal rejected by allowlist",
			id:      "%252e%252e",
			wantErr: "unsafe character",
		},
		{
			name:    "forward slash",
			id:      "a/b",
			wantErr: "path traversal detected",
		},
		{
			name:    "backslash",
			id:      "a\\b",
			wantErr: "path traversal detected",
		},
		{
			name:    "space",
			id:      "hello world",
			wantErr: "unsafe character",
		},
		{
			name:    "null byte encoded",
			id:      "abc%00def",
			wantErr: "unsafe character",
		},
		{
			name:    "unicode",
			id:      "caf\u00e9",
			wantErr: "unsafe character",
		},
		{
			name:    "at sign",
			id:      "user@host",
			wantErr: "unsafe character",
		},
		{
			name:    "colon",
			id:      "host:8080",
			wantErr: "unsafe character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizePathSegment(tt.id)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
