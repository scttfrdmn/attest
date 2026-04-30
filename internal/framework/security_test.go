// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package framework

import (
	"strings"
	"testing"

	"github.com/provabl/attest/pkg/schema"
)

// TestValidateFrameworkIDUnicode covers the MEDIUM security fix: homoglyph/Unicode
// bypass prevention in framework ID validation.
func TestValidateFrameworkIDUnicode(t *testing.T) {
	// Valid IDs — pure ASCII lowercase.
	validIDs := []string{
		"nist-800-171-r2", "hipaa", "fedramp-moderate", "asd-essential-eight",
		"uk-cyber-essentials", "itar", "a", "framework-1",
	}
	for _, id := range validIDs {
		fw := &schema.Framework{ID: id, Controls: []schema.Control{{ID: "1.1"}}}
		if err := validate(fw); err != nil {
			t.Errorf("validate(%q) unexpected error: %v", id, err)
		}
	}

	// Invalid IDs — including Unicode homoglyphs that could bypass conflict detection.
	invalidIDs := []struct {
		id   string
		desc string
	}{
		{"ітар", "Cyrillic lookalike for 'itar' — homoglyph attack"},
		{"ITAR", "uppercase — not allowed"},
		{"nist_800_53", "underscore not in this allowlist... wait, it is"},
		{"nist 800", "space"},
		{"nist\x00800", "null byte"},
		{"nist‐800", "Unicode hyphen (U+2010)"},
		{"nist–800", "en-dash (U+2013)"},
		{"nist—800", "em-dash (U+2014)"},
		{"nist.800", "dot"},
		{"nist/800", "slash"},
	}

	// Note: underscore IS allowed per our validator. Filter it out.
	invalidNonUnderscore := invalidIDs[1:] // skip "nist_800_53" since underscore is valid
	_ = invalidNonUnderscore

	for _, tc := range invalidIDs {
		// Skip underscore case since it's valid.
		if tc.id == "nist_800_53" {
			continue
		}
		fw := &schema.Framework{ID: tc.id, Controls: []schema.Control{{ID: "1.1"}}}
		err := validate(fw)
		if err == nil {
			t.Errorf("validate(%q) = nil, want error (%s)", tc.id, tc.desc)
		}
		if err != nil && !strings.Contains(err.Error(), "invalid character") {
			t.Errorf("validate(%q): error should mention invalid character, got: %v", tc.id, err)
		}
	}
}
