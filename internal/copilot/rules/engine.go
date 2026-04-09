// Package rules implements the CEL-based rule engine for computing default
// values in the copilot wizard. CEL expressions are compiled once at schema
// load time and evaluated against a context map (map[string]any).
package rules

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// Engine holds pre-compiled CEL programs for a set of named rules.
type Engine struct {
	env      *cel.Env
	programs map[string]cel.Program // ruleID -> compiled program
}

// TraceEntry records a single rule evaluation for the --explain audit log.
type TraceEntry struct {
	NodeID     string         `json:"node_id"`
	GroupID    string         `json:"group_id"`
	Expression string         `json:"expression"`
	InputFacts map[string]any `json:"input_facts"`
	Result     any            `json:"result"`
	Reason     string         `json:"reason"` // "flag_provided", "rule_strict", "user_input", "skip_when", "autodiscovery"
	Skipped    bool           `json:"skipped"`
}

// New creates a CEL engine with the standard wizard environment.
// The environment exposes a single variable "ctx" of type map(string, dyn).
func New() (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("ctx", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("rules: failed to create CEL env: %w", err)
	}
	return &Engine{
		env:      env,
		programs: make(map[string]cel.Program),
	}, nil
}

// Compile parses and type-checks a CEL expression, storing the resulting
// program under the given ID. Returns an error if the expression is invalid.
func (e *Engine) Compile(id, expression string) error {
	ast, issues := e.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("rules: compile %q: %w", id, issues.Err())
	}
	prg, err := e.env.Program(ast)
	if err != nil {
		return fmt.Errorf("rules: program %q: %w", id, err)
	}
	e.programs[id] = prg
	return nil
}

// Evaluate runs the pre-compiled rule for the given ID against the provided
// context map. Returns the native Go value (string, bool, []string, etc.)
// or an error if evaluation fails.
func (e *Engine) Evaluate(id string, ctx map[string]any) (any, error) {
	prg, ok := e.programs[id]
	if !ok {
		return nil, fmt.Errorf("rules: no compiled rule for %q", id)
	}
	out, _, err := prg.Eval(map[string]any{"ctx": ctx})
	if err != nil {
		return nil, fmt.Errorf("rules: eval %q: %w", id, err)
	}
	return toNative(out), nil
}

// EvaluateWithTrace runs the rule and returns both the result and a TraceEntry.
func (e *Engine) EvaluateWithTrace(nodeID, groupID, expression string, ctx map[string]any) (any, TraceEntry, error) {
	trace := TraceEntry{
		NodeID:     nodeID,
		GroupID:    groupID,
		Expression: expression,
		InputFacts: copyMap(ctx),
	}
	result, err := e.Evaluate(nodeID, ctx)
	if err != nil {
		return nil, trace, err
	}
	trace.Result = result
	trace.Reason = "rule_strict"
	return result, trace, nil
}

// HasRule returns true if a rule with the given ID has been compiled.
func (e *Engine) HasRule(id string) bool {
	_, ok := e.programs[id]
	return ok
}

// RuleCount returns the number of compiled rules.
func (e *Engine) RuleCount() int {
	return len(e.programs)
}

// toNative converts a CEL ref.Val to a native Go type.
func toNative(v ref.Val) any {
	switch v.Type() {
	case types.BoolType:
		return v.Value().(bool)
	case types.StringType:
		return v.Value().(string)
	case types.IntType:
		return v.Value().(int64)
	case types.DoubleType:
		return v.Value().(float64)
	case types.ListType:
		return convertList(v)
	default:
		return v.Value()
	}
}

// convertList converts a CEL list value to a native Go []any slice.
func convertList(v ref.Val) []any {
	lister, ok := v.(traits.Lister)
	if !ok {
		return nil
	}
	size, ok := lister.Size().Value().(int64)
	if !ok {
		return nil
	}
	result := make([]any, size)
	for i := int64(0); i < size; i++ {
		elem := lister.Get(types.Int(i))
		result[i] = toNative(elem)
	}
	return result
}

func copyMap(m map[string]any) map[string]any {
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
