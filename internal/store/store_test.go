// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"strings"
	"testing"
)

// TestValidateRef covers the CRITICAL security fix: git ref injection prevention.
func TestValidateRef(t *testing.T) {
	valid := []string{
		"main",
		"applied-20260416-143022",
		"assessment-2026-q1",
		"v0.8.1",
		"feat/my-feature",
		"checkpoint_1",
		"a",
		strings.Repeat("a", 255), // max length
	}
	for _, ref := range valid {
		if err := validateRef(ref); err != nil {
			t.Errorf("validateRef(%q) = %v, want nil", ref, err)
		}
	}

	invalid := []struct {
		ref  string
		desc string
	}{
		{"", "empty ref"},
		{strings.Repeat("a", 256), "too long (256 chars)"},
		{"../etc/passwd", "path traversal with .."},
		{"foo/../bar", "embedded .."},
		{"refs/../../secret", "deeper traversal"},
		{"tag;rm -rf .", "semicolon shell injection"},
		{"tag&id", "ampersand shell injection"},
		{"tag|cat /etc/passwd", "pipe injection"},
		{"tag`id`", "backtick injection"},
		{"tag$(id)", "command substitution"},
		{"tag!foo", "exclamation mark"},
		{"tag\ninjection", "newline injection"},
		{"tag\x00null", "null byte injection"},
		{"tag space", "space in ref"},
	}
	for _, tc := range invalid {
		if err := validateRef(tc.ref); err == nil {
			t.Errorf("validateRef(%q) = nil, want error (%s)", tc.ref, tc.desc)
		}
	}
}

// TestTagValidatesRef verifies that Tag() rejects unsafe names.
func TestTagValidatesRef(t *testing.T) {
	s := &Store{noCommit: true} // no-commit mode skips actual git calls

	// Valid tag: should not error (noCommit skips git call).
	if err := s.Tag("applied-20260416", "test message"); err != nil {
		t.Errorf("Tag(valid) = %v, want nil", err)
	}

	// Invalid tags: should error before reaching git.
	for _, bad := range []string{"../escape", "tag;inject", ""} {
		if err := s.Tag(bad, "msg"); err == nil {
			t.Errorf("Tag(%q) = nil, want error", bad)
		}
	}
}

// TestCheckoutValidatesRef verifies that Checkout() rejects unsafe refs.
func TestCheckoutValidatesRef(t *testing.T) {
	s := &Store{noCommit: true}

	// Valid ref.
	if err := s.Checkout("main"); err != nil {
		t.Errorf("Checkout(main) = %v, want nil", err)
	}

	// Invalid refs.
	for _, bad := range []string{"../../etc", "main;rm -rf .", "..", ""} {
		if err := s.Checkout(bad); err == nil {
			t.Errorf("Checkout(%q) = nil, want error", bad)
		}
	}
}
