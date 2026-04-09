package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/copilot/schema"
)

func newEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New()
	require.NoError(t, err)
	return e
}

func TestStringLiteral(t *testing.T) {
	e := newEngine(t)
	require.NoError(t, e.Compile("log_level", "'info'"))
	result, err := e.Evaluate("log_level", map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, "info", result)
}

func TestBoolLiteralTrue(t *testing.T) {
	e := newEngine(t)
	require.NoError(t, e.Compile("agent", "true"))
	result, err := e.Evaluate("agent", map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestBoolLiteralFalse(t *testing.T) {
	e := newEngine(t)
	require.NoError(t, e.Compile("network", "false"))
	result, err := e.Evaluate("network", map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, false, result)
}

func TestConditionalString(t *testing.T) {
	e := newEngine(t)
	expr := "ctx['audit.enabled'] ? 'standard' : 'minimal'"
	require.NoError(t, e.Compile("profile", expr))

	// audit.enabled = true -> "standard"
	result, err := e.Evaluate("profile", map[string]any{"audit.enabled": true})
	require.NoError(t, err)
	assert.Equal(t, "standard", result)

	// audit.enabled = false -> "minimal"
	result, err = e.Evaluate("profile", map[string]any{"audit.enabled": false})
	require.NoError(t, err)
	assert.Equal(t, "minimal", result)
}

func TestConditionalBool(t *testing.T) {
	e := newEngine(t)
	expr := "ctx['discovery.agent.enabled'] == true"
	require.NoError(t, e.Compile("collect_sw", expr))

	result, err := e.Evaluate("collect_sw", map[string]any{"discovery.agent.enabled": true})
	require.NoError(t, err)
	assert.Equal(t, true, result)

	result, err = e.Evaluate("collect_sw", map[string]any{"discovery.agent.enabled": false})
	require.NoError(t, err)
	assert.Equal(t, false, result)
}

func TestBoolReference(t *testing.T) {
	e := newEngine(t)
	require.NoError(t, e.Compile("posture", "ctx['audit.enabled']"))
	result, err := e.Evaluate("posture", map[string]any{"audit.enabled": true})
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestEmptyList(t *testing.T) {
	e := newEngine(t)
	require.NoError(t, e.Compile("vps", "[]"))
	result, err := e.Evaluate("vps", map[string]any{})
	require.NoError(t, err)
	list, ok := result.([]any)
	require.True(t, ok, "expected []any, got %T", result)
	assert.Empty(t, list)
}

func TestStringList(t *testing.T) {
	e := newEngine(t)
	require.NoError(t, e.Compile("frameworks", "['none']"))
	result, err := e.Evaluate("frameworks", map[string]any{})
	require.NoError(t, err)
	list, ok := result.([]any)
	require.True(t, ok, "expected []any, got %T", result)
	assert.Equal(t, []any{"none"}, list)
}

func TestConditionalList(t *testing.T) {
	e := newEngine(t)
	expr := "ctx['classification.allowlist_file'] != '' ? ['hostname', 'mac_address'] : []"
	require.NoError(t, e.Compile("match_fields", expr))

	result, err := e.Evaluate("match_fields", map[string]any{"classification.allowlist_file": "/path/to/file"})
	require.NoError(t, err)
	list := result.([]any)
	assert.Equal(t, []any{"hostname", "mac_address"}, list)

	result, err = e.Evaluate("match_fields", map[string]any{"classification.allowlist_file": ""})
	require.NoError(t, err)
	list = result.([]any)
	assert.Empty(t, list)
}

func TestAutoDiscoveryDetected(t *testing.T) {
	e := newEngine(t)
	expr := "has(ctx.autodiscovery) && ctx.autodiscovery.exists(s, s == 'docker')"
	require.NoError(t, e.Compile("docker_enabled", expr))

	// Docker detected
	result, err := e.Evaluate("docker_enabled", map[string]any{
		"autodiscovery": []any{"docker", "otel_collector"},
	})
	require.NoError(t, err)
	assert.Equal(t, true, result)

	// Docker not detected
	result, err = e.Evaluate("docker_enabled", map[string]any{
		"autodiscovery": []any{"wazuh"},
	})
	require.NoError(t, err)
	assert.Equal(t, false, result)
}

func TestAutoDiscoveryMissing(t *testing.T) {
	e := newEngine(t)
	expr := "has(ctx.autodiscovery) && ctx.autodiscovery.exists(s, s == 'docker')"
	require.NoError(t, e.Compile("docker_enabled", expr))

	// No autodiscovery key at all
	result, err := e.Evaluate("docker_enabled", map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, false, result)
}

func TestAutoDiscoveryConditionalEndpoint(t *testing.T) {
	e := newEngine(t)
	expr := "has(ctx.autodiscovery) && ctx.autodiscovery.exists(s, s == 'otel_collector') ? 'localhost:4318' : ''"
	require.NoError(t, e.Compile("endpoint", expr))

	result, err := e.Evaluate("endpoint", map[string]any{
		"autodiscovery": []any{"otel_collector"},
	})
	require.NoError(t, err)
	assert.Equal(t, "localhost:4318", result)

	result, err = e.Evaluate("endpoint", map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestSkipWhenExpression(t *testing.T) {
	e := newEngine(t)
	expr := "ctx['discovery.docker.enabled'] == false"
	require.NoError(t, e.Compile("skip_docker_host", expr))

	result, err := e.Evaluate("skip_docker_host", map[string]any{
		"discovery.docker.enabled": false,
	})
	require.NoError(t, err)
	assert.Equal(t, true, result)

	result, err = e.Evaluate("skip_docker_host", map[string]any{
		"discovery.docker.enabled": true,
	})
	require.NoError(t, err)
	assert.Equal(t, false, result)
}

func TestBusinessCriticalityConditional(t *testing.T) {
	e := newEngine(t)
	expr := "ctx['business.environment'] == 'production' ? 'high' : 'low'"
	require.NoError(t, e.Compile("criticality", expr))

	result, err := e.Evaluate("criticality", map[string]any{"business.environment": "production"})
	require.NoError(t, err)
	assert.Equal(t, "high", result)

	result, err = e.Evaluate("criticality", map[string]any{"business.environment": "development"})
	require.NoError(t, err)
	assert.Equal(t, "low", result)
}

func TestDockerHostConditional(t *testing.T) {
	e := newEngine(t)
	expr := "ctx['discovery.docker.enabled'] ? 'unix:///var/run/docker.sock' : ''"
	require.NoError(t, e.Compile("docker_host", expr))

	result, err := e.Evaluate("docker_host", map[string]any{"discovery.docker.enabled": true})
	require.NoError(t, err)
	assert.Equal(t, "unix:///var/run/docker.sock", result)
}

func TestStreamingOTLPFallback(t *testing.T) {
	e := newEngine(t)
	expr := "has(ctx.autodiscovery) && ctx.autodiscovery.exists(s, s == 'otel_collector') ? 'http://localhost:4318' : ctx['endpoint.primary.address']"
	require.NoError(t, e.Compile("otlp", expr))

	// With autodiscovery
	result, err := e.Evaluate("otlp", map[string]any{
		"autodiscovery":            []any{"otel_collector"},
		"endpoint.primary.address": "ingest.example.com:443",
	})
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:4318", result)

	// Without autodiscovery, falls back to endpoint
	result, err = e.Evaluate("otlp", map[string]any{
		"endpoint.primary.address": "ingest.example.com:443",
	})
	require.NoError(t, err)
	assert.Equal(t, "ingest.example.com:443", result)
}

func TestCompileInvalidExpression(t *testing.T) {
	e := newEngine(t)
	err := e.Compile("bad", "ctx[[[invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compile")
}

func TestEvaluateUnknownRule(t *testing.T) {
	e := newEngine(t)
	_, err := e.Evaluate("nonexistent", map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no compiled rule")
}

func TestHasRule(t *testing.T) {
	e := newEngine(t)
	assert.False(t, e.HasRule("x"))
	require.NoError(t, e.Compile("x", "true"))
	assert.True(t, e.HasRule("x"))
}

func TestRuleCount(t *testing.T) {
	e := newEngine(t)
	assert.Equal(t, 0, e.RuleCount())
	require.NoError(t, e.Compile("a", "true"))
	require.NoError(t, e.Compile("b", "false"))
	assert.Equal(t, 2, e.RuleCount())
}

func TestEvaluateWithTrace(t *testing.T) {
	e := newEngine(t)
	require.NoError(t, e.Compile("log_level", "'info'"))

	result, trace, err := e.EvaluateWithTrace("log_level", "environment", "'info'", map[string]any{"foo": "bar"})
	require.NoError(t, err)
	assert.Equal(t, "info", result)
	assert.Equal(t, "log_level", trace.NodeID)
	assert.Equal(t, "environment", trace.GroupID)
	assert.Equal(t, "'info'", trace.Expression)
	assert.Equal(t, "info", trace.Result)
	assert.Equal(t, "rule_strict", trace.Reason)
	assert.Equal(t, map[string]any{"foo": "bar"}, trace.InputFacts)
}

// TestCompileAllSchemaExpressions verifies that every CEL expression in the
// default schema compiles without error.
func TestCompileAllSchemaExpressions(t *testing.T) {
	s, err := schema.LoadDefault()
	require.NoError(t, err)

	e := newEngine(t)
	for _, node := range s.AllNodes() {
		err := e.Compile(node.ID, node.DefaultRule)
		require.NoError(t, err, "failed to compile default_rule for node %q: %s", node.ID, node.DefaultRule)

		if node.SkipWhen != "" {
			err := e.Compile(node.ID+"__skip", node.SkipWhen)
			require.NoError(t, err, "failed to compile skip_when for node %q: %s", node.ID, node.SkipWhen)
		}
	}
}

// TestEvaluateAllSchemaDefaults evaluates every default_rule with an empty
// context to verify that expressions with no dependencies produce valid output.
func TestEvaluateAllSchemaDefaults(t *testing.T) {
	s, err := schema.LoadDefault()
	require.NoError(t, err)

	e := newEngine(t)
	for _, node := range s.AllNodes() {
		require.NoError(t, e.Compile(node.ID, node.DefaultRule))
	}

	// Nodes with no dependencies should evaluate cleanly against empty ctx.
	for _, node := range s.AllNodes() {
		if len(node.DependsOn) > 0 {
			continue
		}
		result, err := e.Evaluate(node.ID, map[string]any{})
		require.NoError(t, err, "node %q failed to evaluate with empty ctx", node.ID)
		require.NotNil(t, result, "node %q returned nil", node.ID)
	}
}

// BenchmarkCompileAndEvaluateFullSchema measures the cold-start overhead
// of compiling and evaluating all schema rules. RFC requirement: <= 50ms.
func BenchmarkCompileAndEvaluateFullSchema(b *testing.B) {
	s, err := schema.LoadDefault()
	if err != nil {
		b.Fatal(err)
	}
	nodes := s.AllNodes()

	b.ResetTimer()
	for range b.N {
		e, err := New()
		if err != nil {
			b.Fatal(err)
		}
		for _, node := range nodes {
			if err := e.Compile(node.ID, node.DefaultRule); err != nil {
				b.Fatal(err)
			}
		}
		for _, node := range nodes {
			if len(node.DependsOn) > 0 {
				continue
			}
			if _, err := e.Evaluate(node.ID, map[string]any{}); err != nil {
				b.Fatal(err)
			}
		}
	}
}
