package autodiscovery

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	k8sServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //#nosec G101 -- standard K8s path, not a credential
	k8sAPIServer               = "https://kubernetes.default.svc"
)

// probeK8s performs in-cluster Kubernetes service discovery by querying the
// Kubernetes API for services in the current namespace.  It matches service
// names against known service signatures.
//
// This probe only works when running inside a Kubernetes pod with a service
// account that has permission to list services.
func probeK8s(ctx context.Context, services []ServiceSignature) []DiscoveredService {
	token, err := os.ReadFile(k8sServiceAccountTokenPath)
	if err != nil {
		slog.Debug("autodiscovery: not running in Kubernetes (no service account token)")
		return nil
	}

	namespace, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		namespace = []byte("default")
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //#nosec G402 -- in-cluster API with service account token
			},
		},
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/services", k8sAPIServer, strings.TrimSpace(string(namespace)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //#nosec G107 -- Kubernetes API URL
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("autodiscovery: kubernetes API request failed", "error", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		slog.Debug("autodiscovery: kubernetes API returned non-200", "status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var svcList k8sServiceList
	if err = json.Unmarshal(body, &svcList); err != nil {
		return nil
	}

	sigByName := make(map[string]ServiceSignature, len(services))
	for _, s := range services {
		sigByName[s.Name] = s
	}

	var results []DiscoveredService

	for _, k8sSvc := range svcList.Items {
		svcName := strings.ToLower(k8sSvc.Metadata.Name)

		for _, sig := range services {
			if !matchK8sService(svcName, sig) {
				continue
			}

			endpoint := k8sEndpoint(k8sSvc, sig)
			status, missing := determineStatus(sig)

			results = append(results, DiscoveredService{
				Name:        sig.Name,
				DisplayName: sig.DisplayName,
				Endpoint:    endpoint,
				Method:      "kubernetes",
				Status:      status,
				SetupHint:   fmt.Sprintf("[k8s:%s/%s] %s", strings.TrimSpace(string(namespace)), k8sSvc.Metadata.Name, sig.SetupHint),
				Credentials: missing,
			})
			break
		}
	}

	return results
}

func matchK8sService(svcName string, sig ServiceSignature) bool {
	if svcName == sig.Name {
		return true
	}
	for _, name := range sig.DockerNames {
		if strings.Contains(svcName, strings.ToLower(name)) {
			return true
		}
	}
	return false
}

func k8sEndpoint(svc k8sService, sig ServiceSignature) string {
	host := svc.Metadata.Name
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
		host = svc.Spec.ClusterIP
	}

	// Match a port from the service spec against known ports.
	for _, p := range svc.Spec.Ports {
		for _, dp := range sig.DefaultPorts {
			if p.Port == dp {
				return buildEndpoint(host, p.Port, sig.TLS)
			}
		}
	}

	// Fall back to first port.
	if len(svc.Spec.Ports) > 0 {
		return buildEndpoint(host, svc.Spec.Ports[0].Port, sig.TLS)
	}

	if len(sig.DefaultPorts) > 0 {
		return buildEndpoint(host, sig.DefaultPorts[0], sig.TLS)
	}

	return host
}

// Minimal Kubernetes API types.

type k8sServiceList struct {
	Items []k8sService `json:"items"`
}

type k8sService struct {
	Metadata k8sMetadata    `json:"metadata"`
	Spec     k8sServiceSpec `json:"spec"`
}

type k8sMetadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type k8sServiceSpec struct {
	ClusterIP string       `json:"clusterIP"`
	Ports     []k8sPortDef `json:"ports"`
}

type k8sPortDef struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}
