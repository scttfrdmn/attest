// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package framework

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/provabl/attest/pkg/schema"
)

// makeFrameworkWithControls creates a framework with n controls for limit testing.
func makeFrameworkWithControls(id string, n int) *schema.Framework {
	controls := make([]schema.Control, n)
	for i := range controls {
		controls[i] = schema.Control{ID: fmt.Sprintf("%d.%d", i/100+1, i%100+1)}
	}
	return &schema.Framework{ID: id, Controls: controls}
}

// writeFramework writes a framework YAML file to a temp directory.
func writeFramework(t *testing.T, dir, id, content string) string {
	t.Helper()
	fw := filepath.Join(dir, id)
	if err := os.MkdirAll(fw, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", fw, err)
	}
	path := filepath.Join(fw, "framework.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

const minimalFramework = `
id: test-fw
name: Test Framework
version: "1.0"
source: "https://example.com"
controls:
  - id: "1.1"
    family: "Access Control"
    title: "Control 1"
    responsibility:
      aws: "AWS manages the underlying infra"
      customer: "Customer must configure IAM"
`

const frameworkWithControls = `
id: nist-test
name: NIST Test
version: "2.0"
source: "https://example.com"
controls:
  - id: "3.1.1"
    family: "Access Control"
    title: "Limit system access"
    responsibility:
      aws: "IAM service"
      customer: "IAM policies"
    structural:
      - id: "scp-require-mfa"
        description: "Deny without MFA"
        actions: ["*"]
        conditions: ["aws:MultiFactorAuthPresent != true"]
        effect: "Deny"
    monitoring:
      - id: "config-mfa"
        resource_type: "AWS::IAM::User"
        check: "MFA enabled"
  - id: "3.1.3"
    family: "Access Control"
    title: "Control CUI flow"
    responsibility:
      aws: "VPC, S3"
      customer: "Data flow policies"
    structural:
      - id: "scp-require-mfa"
        description: "Reused SCP"
        actions: ["*"]
        effect: "Deny"
`

// secondFramework shares the scp-require-mfa structural ID with frameworkWithControls.
const secondFramework = `
id: hipaa-test
name: HIPAA Test
version: "1.0"
source: "https://example.com"
controls:
  - id: "164.312"
    family: "Technical Safeguards"
    title: "Access control"
    responsibility:
      aws: "IAM"
      customer: "IAM policies"
    structural:
      - id: "scp-require-mfa"
        description: "Shared SCP"
        actions: ["*"]
        effect: "Deny"
`

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name        string
		id          string
		content     string
		wantID      string
		wantControls int
		wantErr     bool
	}{
		{
			name:         "loads minimal framework",
			id:           "test-fw",
			content:      minimalFramework,
			wantID:       "test-fw",
			wantControls: 1,
		},
		{
			name:         "loads framework with full control spec",
			id:           "nist-test",
			content:      frameworkWithControls,
			wantID:       "nist-test",
			wantControls: 2,
		},
		{
			name:    "missing framework returns error",
			id:      "nonexistent",
			wantErr: true,
		},
	}

	// Write test frameworks to temp dir.
	writeFramework(t, dir, "test-fw", minimalFramework)
	writeFramework(t, dir, "nist-test", frameworkWithControls)

	loader := NewLoader(dir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw, err := loader.Load(tt.id)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Load(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if fw.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", fw.ID, tt.wantID)
			}
			if len(fw.Controls) != tt.wantControls {
				t.Errorf("Controls = %d, want %d", len(fw.Controls), tt.wantControls)
			}
		})
	}
}

func TestLoadAll(t *testing.T) {
	dir := t.TempDir()
	writeFramework(t, dir, "fw-a", minimalFramework)
	writeFramework(t, dir, "fw-b", `
id: fw-b
name: Framework B
version: "1.0"
source: "https://b.com"
controls:
  - id: "b.1"
    family: "Family B"
    title: "Control B"
    responsibility:
      aws: "a"
      customer: "b"
`)

	loader := NewLoader(dir)
	frameworks, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() error = %v", err)
	}
	if len(frameworks) != 2 {
		t.Errorf("got %d frameworks, want 2", len(frameworks))
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		fw      *schema.Framework
		wantErr bool
	}{
		{
			name:    "valid framework",
			fw:      &schema.Framework{ID: "test", Controls: []schema.Control{{ID: "1.1"}}},
			wantErr: false,
		},
		{
			name:    "missing ID",
			fw:      &schema.Framework{Controls: []schema.Control{{ID: "1.1"}}},
			wantErr: true,
		},
		{
			name:    "no controls",
			fw:      &schema.Framework{ID: "test", Controls: []schema.Control{}},
			wantErr: true,
		},
		{
			name:    "control missing ID",
			fw:      &schema.Framework{ID: "test", Controls: []schema.Control{{ID: ""}}},
			wantErr: true,
		},
		// v0.8.1 security fix: size limit validation
		{
			name:    "framework ID too long",
			fw:      &schema.Framework{ID: strings.Repeat("a", 129), Controls: []schema.Control{{ID: "1.1"}}},
			wantErr: true,
		},
		{
			name:    "framework ID at max length",
			fw:      &schema.Framework{ID: strings.Repeat("a", 128), Controls: []schema.Control{{ID: "1.1"}}},
			wantErr: false,
		},
		{
			name:    "control ID too long",
			fw:      &schema.Framework{ID: "test", Controls: []schema.Control{{ID: strings.Repeat("c", 65)}}},
			wantErr: true,
		},
		{
			name:    "control ID at max length",
			fw:      &schema.Framework{ID: "test", Controls: []schema.Control{{ID: strings.Repeat("c", 64)}}},
			wantErr: false,
		},
		{
			name: "control title too long",
			fw: &schema.Framework{ID: "test", Controls: []schema.Control{
				{ID: "1.1", Title: strings.Repeat("t", 513)},
			}},
			wantErr: true,
		},
		{
			name: "control title at max length",
			fw: &schema.Framework{ID: "test", Controls: []schema.Control{
				{ID: "1.1", Title: strings.Repeat("t", 512)},
			}},
			wantErr: false,
		},
		{
			name:    "too many controls (10001)",
			fw:      makeFrameworkWithControls("test", 10001),
			wantErr: true,
		},
		{
			name:    "controls at max count (10000)",
			fw:      makeFrameworkWithControls("test", 10000),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(tt.fw)
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResolve_Deduplication(t *testing.T) {
	dir := t.TempDir()
	writeFramework(t, dir, "nist-test", frameworkWithControls)
	writeFramework(t, dir, "hipaa-test", secondFramework)

	loader := NewLoader(dir)
	nist, _ := loader.Load("nist-test")
	hipaa, _ := loader.Load("hipaa-test")

	rcs, err := Resolve([]*schema.Framework{nist, hipaa})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	// "scp-require-mfa" appears in both frameworks; it should be grouped under one key.
	key := "scp-require-mfa"
	group, ok := rcs.Controls[key]
	if !ok {
		t.Fatalf("expected deduplication key %q in resolved controls", key)
	}
	if len(group) < 2 {
		t.Errorf("expected at least 2 controls under key %q, got %d", key, len(group))
	}

	// Each entry should carry its framework ID.
	fwIDs := make(map[string]bool)
	for _, rc := range group {
		fwIDs[rc.FrameworkID] = true
	}
	if !fwIDs["nist-test"] {
		t.Error("expected nist-test in resolved controls for scp-require-mfa")
	}
	if !fwIDs["hipaa-test"] {
		t.Error("expected hipaa-test in resolved controls for scp-require-mfa")
	}
}

func TestLoadRealNIST800171(t *testing.T) {
	// Integration test: load the real framework definition from the repo.
	loader := NewLoader("../../frameworks")
	fw, err := loader.Load("nist-800-171-r2")
	if err != nil {
		t.Fatalf("Load(nist-800-171-r2) error = %v", err)
	}
	if fw.ID != "nist-800-171-r2" {
		t.Errorf("ID = %q, want nist-800-171-r2", fw.ID)
	}
	if len(fw.Controls) == 0 {
		t.Error("expected at least one control")
	}
	// All controls must have IDs.
	for _, ctrl := range fw.Controls {
		if ctrl.ID == "" {
			t.Errorf("control with no ID in %s", fw.ID)
		}
	}
}
