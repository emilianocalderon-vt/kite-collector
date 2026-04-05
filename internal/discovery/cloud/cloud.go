// Package cloud provides discovery sources for major cloud providers.
//
// Each source implements [discovery.Source] and enumerates compute instances
// (EC2, Compute Engine, Azure VMs) as [model.Asset] values. The current
// implementations are stubs that document the expected configuration keys
// and return empty results; full cloud SDK integration is planned for a
// future release.
package cloud

// toStringSlice converts an any value (expected []any of strings or []string)
// to []string. This mirrors the helper used in other discovery packages and
// is used to extract config values like region lists from the untyped
// configuration map.
func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	if ss, ok := v.([]string); ok {
		return ss
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// toString extracts a string value from an any, returning empty string if
// the value is nil or not a string.
func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
