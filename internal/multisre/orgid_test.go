// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package multisre

import (
	"testing"
)

// TestIsValidOrgID covers the HIGH security fix: OrgID markdown injection prevention.
func TestIsValidOrgID(t *testing.T) {
	valid := []string{
		"o-abc1234567",         // typical AWS org ID
		"o-abcdefghij",         // all alpha
		"o-1234567890",         // all digits
		"o-abc123def456",       // mixed
		"o-" + repeat('a', 34), // 34 char suffix — max (36 - 2)
		"o-ab",                 // minimum valid (o- + 2 chars = 4 total)
	}
	for _, id := range valid {
		if !isValidOrgID(id) {
			t.Errorf("isValidOrgID(%q) = false, want true", id)
		}
	}

	invalid := []struct {
		id   string
		desc string
	}{
		{"", "empty"},
		{"o-", "no suffix"},
		{"o-" + repeat('a', 35), "too long (> 34 char suffix)"},
		{"o-" + repeat('a', 36), "also too long"},
		{"p-abc1234567", "wrong prefix (p- not o-)"},
		{"o_abc1234567", "underscore separator"},
		{"o-ABC1234567", "uppercase"},
		{"o-abc123456!", "exclamation"},
		{"o-abc](http://evil.com)", "markdown injection attempt"},
		{"o-abc\ninjected", "newline injection"},
		{"o-abc<script>", "script tag injection"},
		{"o-abc 123456", "space"},
	}
	for _, tc := range invalid {
		if isValidOrgID(tc.id) {
			t.Errorf("isValidOrgID(%q) = true, want false (%s)", tc.id, tc.desc)
		}
	}
}

// TestAddRejectsInvalidOrgID verifies Add() enforces OrgID format.
func TestAddRejectsInvalidOrgID(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	invalidOrgIDs := []string{
		"o-abc](https://evil.com)",
		"o-abc<script>alert(1)</script>",
		"ORGID-UPPERCASE",
		"",
		"not-an-org-id",
	}
	for _, orgID := range invalidOrgIDs {
		err := mgr.Add(SREEntry{ID: "prod", OrgID: orgID})
		if err == nil {
			t.Errorf("Add with OrgID=%q should fail (potential injection)", orgID)
		}
	}
}

// TestIsValidSREIDExported verifies the exported wrapper works correctly.
func TestIsValidSREIDExported(t *testing.T) {
	if !IsValidSREID("production") {
		t.Error("IsValidSREID(production) = false, want true")
	}
	if IsValidSREID("../../etc") {
		t.Error("IsValidSREID(../../etc) = true, want false")
	}
}

func repeat(r rune, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = r
	}
	return string(b)
}
