package safenet

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
)

// TLSConfig builds a tls.Config based on environment variables.
//
// Three modes:
//  1. insecureEnv="true" -> InsecureSkipVerify (dev/localhost)
//  2. caCertEnv=path     -> custom CA certificate pool
//  3. default            -> system CA pool
func TLSConfig(insecureEnv, caCertEnv string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // min version is explicitly set

	insecure, _ := strconv.ParseBool(os.Getenv(insecureEnv))
	if insecure {
		slog.Warn("TLS verification disabled",
			"env", insecureEnv,
			"warning", "not recommended for production")
		cfg.InsecureSkipVerify = true //nolint:gosec // user-controlled opt-in via env var
		return cfg, nil
	}

	caPath := os.Getenv(caCertEnv)
	if caPath != "" {
		caCert, err := os.ReadFile(filepath.Clean(caPath))
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("no valid certificates in %s", caPath)
		}
		cfg.RootCAs = pool
		return cfg, nil
	}

	return cfg, nil
}
