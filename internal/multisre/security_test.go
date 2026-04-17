package multisre

import (
	"testing"
)

// TestIsValidSREID covers the CRITICAL security fix: SRE ID path traversal prevention.
func TestIsValidSREID(t *testing.T) {
	valid := []string{
		"production", "dev", "prod-01", "sre_1", "SRE", "a", "my-sre-name",
		"Production123",
	}
	for _, id := range valid {
		if !isValidSREID(id) {
			t.Errorf("isValidSREID(%q) = false, want true", id)
		}
	}

	invalid := []struct {
		id   string
		desc string
	}{
		{"", "empty"},
		{"../../../etc", "path traversal with .."},
		{"../../tmp", "double dot escape"},
		{"..", "bare double dot"},
		{"prod/dev", "forward slash"},
		{"prod\\dev", "backslash"},
		{"prod;rm", "semicolon"},
		{"prod&id", "ampersand"},
		{"prod|cat", "pipe"},
		{"prod`cmd`", "backtick"},
		{"prod$(id)", "command substitution"},
		{"prod name", "space"},
		{"ітар", "Cyrillic lookalike (homoglyph attack)"},
		{"nist‐800", "Unicode hyphen (not ASCII dash)"},
		{" leading-space", "leading space"},
		{"trailing-space ", "trailing space"},
		{string(make([]byte, 65)), "65 chars — over limit"},
	}
	for _, tc := range invalid {
		if isValidSREID(tc.id) {
			t.Errorf("isValidSREID(%q) = true, want false (%s)", tc.id, tc.desc)
		}
	}
}

// TestAddRejectsUnsafeID verifies Add() enforces ID validation before persisting.
func TestAddRejectsUnsafeID(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	unsafe := []string{
		"../../etc", "../tmp", "prod;inject", "prod/sub", "",
	}
	for _, id := range unsafe {
		err := mgr.Add(SREEntry{ID: id, OrgID: "o-1"})
		if err == nil {
			t.Errorf("Add(%q) should have been rejected (path traversal/injection risk)", id)
		}
	}
}

// TestStoreDirWithSafeID verifies StoreDir produces a path within storeRoot.
func TestStoreDirWithSafeID(t *testing.T) {
	mgr := NewManager("/base/.attest")
	got := mgr.StoreDir("production")
	// Path must start with storeRoot and contain ".sre-production".
	if got != "/base/.attest/.sre-production" {
		t.Errorf("StoreDir = %q, want /base/.attest/.sre-production", got)
	}
}
