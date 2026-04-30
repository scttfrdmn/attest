// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package iac

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsValidSCPID covers the CRITICAL security fix: CDK code injection prevention.
func TestIsValidSCPID(t *testing.T) {
	valid := []string{
		"attest-scp-01", "my-policy", "scp_1", "a", "policy-name-here",
	}
	for _, id := range valid {
		if !isValidSCPID(id) {
			t.Errorf("isValidSCPID(%q) = false, want true", id)
		}
	}

	invalid := []struct {
		id   string
		desc string
	}{
		{"", "empty"},
		{"scp`inject`", "backtick injection"},
		{"scp${FOO}", "template literal"},
		{"scp'};evil", "quote + code injection"},
		{"scp\"inject", "double quote"},
		{"SCP-UPPER", "uppercase (TypeScript identifier safety)"},
		{"scp name", "space"},
		{"scp;rm", "semicolon"},
		{strings.Repeat("a", 129), "too long"},
		{"scp/../etc", "path traversal"},
	}
	for _, tc := range invalid {
		if isValidSCPID(tc.id) {
			t.Errorf("isValidSCPID(%q) = true, want false (%s)", tc.id, tc.desc)
		}
	}
}

// TestCDKRejectsInjectionSCPID verifies GenerateCDK refuses unsafe SCP IDs.
func TestCDKRejectsInjectionSCPID(t *testing.T) {
	compiledDir := t.TempDir()
	scpDir := filepath.Join(compiledDir, "scps")
	if err := os.MkdirAll(scpDir, 0750); err != nil {
		t.Fatal(err)
	}

	// Write a SCP with a dangerous name.
	dangerous := "attest-scp`inject`"
	data, _ := json.Marshal(map[string]any{"Version": "2012-10-17"})
	if err := os.WriteFile(filepath.Join(scpDir, dangerous+".json"), data, 0640); err != nil {
		t.Fatal(err)
	}

	g := NewGenerator(FormatCDK, t.TempDir())
	err := g.Generate(compiledDir)
	if err == nil {
		t.Error("GenerateCDK should reject SCP ID with backtick (code injection risk)")
	}
	if err != nil && !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("error message should mention 'unsafe', got: %v", err)
	}
}
