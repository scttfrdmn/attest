// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package multisre

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadRejectsUnsafeIDInRegistry covers the CRITICAL TOCTOU fix:
// IDs loaded from a hand-edited registry file are re-validated on Load().
func TestLoadRejectsUnsafeIDInRegistry(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	// Manually write a registry with an unsafe ID (bypasses Add() validation).
	maliciousYAML := `sres:
  - id: "../../etc"
    org_id: "o-abc12345"
    region: "us-east-1"
`
	if err := os.WriteFile(
		filepath.Join(dir, "sres.yaml"),
		[]byte(maliciousYAML),
		0640,
	); err != nil {
		t.Fatal(err)
	}

	// Load() should reject the unsafe ID.
	_, err := mgr.Load()
	if err == nil {
		t.Fatal("Load() should reject registry with path-traversal ID")
	}
	if err != nil {
		t.Logf("correctly rejected: %v", err)
	}
}

// TestLoadRejectsShellMetacharactersInRegistry verifies other unsafe IDs are caught.
func TestLoadRejectsShellMetacharactersInRegistry(t *testing.T) {
	unsafeIDs := []string{
		"prod;ls", "prod|cat /etc/passwd", "prod`id`",
		"prod$(whoami)", "prod name", "prod\n../../evil",
	}

	for _, unsafeID := range unsafeIDs {
		dir := t.TempDir()
		mgr := NewManager(dir)

		yaml := "sres:\n  - id: " + `"` + unsafeID + `"` + "\n    org_id: o-abc12345\n    region: us-east-1\n"
		_ = os.WriteFile(filepath.Join(dir, "sres.yaml"), []byte(yaml), 0640)

		_, err := mgr.Load()
		if err == nil {
			t.Errorf("Load() accepted unsafe ID %q — should have been rejected", unsafeID)
		}
	}
}

// TestLoadAcceptsValidRegistry verifies normal registry files still work.
func TestLoadAcceptsValidRegistry(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	// Add a legitimate SRE (goes through validation).
	_ = mgr.Add(SREEntry{ID: "production", OrgID: "o-abc12345"})

	// Re-load should succeed.
	reg, err := mgr.Load()
	if err != nil {
		t.Fatalf("Load() of valid registry failed: %v", err)
	}
	if len(reg.SREs) != 1 || reg.SREs[0].ID != "production" {
		t.Errorf("expected 1 SRE with ID=production, got %v", reg.SREs)
	}
}
