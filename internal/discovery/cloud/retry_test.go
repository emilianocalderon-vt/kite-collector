package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// doGet is a test helper that builds a context-aware GET request.
func doGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func TestDoWithRetry_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx := context.Background()
	resp, err := doWithRetry(ctx, "test", func() (*http.Response, error) {
		return doGet(ctx, srv.URL)
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDoWithRetry_RetryOn500(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := callCount.Add(1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx := context.Background()
	resp, err := doWithRetry(ctx, "test", func() (*http.Response, error) {
		return doGet(ctx, srv.URL)
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(3), callCount.Load())
}

func TestDoWithRetry_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("access denied"))
	}))
	defer srv.Close()

	ctx := context.Background()
	resp, err := doWithRetry(ctx, "test", func() (*http.Response, error) {
		return doGet(ctx, srv.URL)
	})
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	require.Error(t, err)

	var ae *authError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, 403, ae.statusCode)
}

func TestDoWithRetry_RateLimited(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := callCount.Add(1)
		if count == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("slow down"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx := context.Background()
	resp, err := doWithRetry(ctx, "test", func() (*http.Response, error) {
		return doGet(ctx, srv.URL)
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(2), callCount.Load())
}

func TestDoWithRetry_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	resp, err := doWithRetry(ctx, "test", func() (*http.Response, error) {
		return nil, context.Canceled
	})
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name     string
		val      string
		expected time.Duration
	}{
		{"empty", "", 0},
		{"seconds", "5", 5 * time.Second},
		{"invalid", "abc", 0},
		{"zero", "0", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, parseRetryAfter(tc.val))
		})
	}
}

func TestIAMHint(t *testing.T) {
	assert.Contains(t, iamHint("aws_ec2"), "AWS_ACCESS_KEY_ID")
	assert.Contains(t, iamHint("gcp_compute"), "compute.instances.list")
	assert.Contains(t, iamHint("azure_vm"), "Reader role")
	assert.Contains(t, iamHint("unknown"), "Check credentials")
}
