package software

import (
	"fmt"
	"strings"
	"unicode"
)

// BuildCPE23 constructs a best-effort CPE 2.3 formatted string for an
// application. Fields that cannot be determined are set to "*" (ANY).
// Returns empty string when both product and version are empty.
func BuildCPE23(vendor, product, version string) string {
	return BuildCPE23Full(vendor, product, version, "", "")
}

// BuildCPE23WithArch constructs a CPE 2.3 string with an optional target
// hardware architecture in the target_hw field (position 10).
func BuildCPE23WithArch(vendor, product, version, arch string) string {
	return BuildCPE23Full(vendor, product, version, "", arch)
}

// BuildCPE23WithTargetSW constructs a CPE 2.3 string with a target software
// platform in the target_sw field (position 9). Used for language-specific
// packages (e.g. "python" for pip, "node.js" for npm).
func BuildCPE23WithTargetSW(vendor, product, version, targetSW string) string {
	return BuildCPE23Full(vendor, product, version, targetSW, "")
}

// BuildCPE23Full constructs a CPE 2.3 string with optional target_sw and
// target_hw fields.
func BuildCPE23Full(vendor, product, version, targetSW, targetHW string) string {
	p := normalizeComponent(product)
	v := normalizeComponent(version)

	if p == "" && v == "" {
		return ""
	}

	ven := normalizeComponent(vendor)
	if ven == "" {
		ven = "*"
	}
	if p == "" {
		p = "*"
	}
	if v == "" {
		v = "*"
	}

	tsw := "*"
	if s := normalizeComponent(targetSW); s != "" {
		tsw = s
	}

	thw := "*"
	if a := normalizeComponent(targetHW); a != "" {
		thw = a
	}

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:%s:%s:*", ven, p, v, tsw, thw)
}

// normalizeComponent lowercases and sanitises a single CPE component value.
// Spaces become underscores; characters outside [a-z0-9_\-.] are removed.
func normalizeComponent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			return r
		}
		return -1
	}, s)
}
