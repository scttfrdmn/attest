package iac

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSCPFixtures writes SCP JSON files to a temp dir for testing.
func writeSCPFixtures(t *testing.T, dir string, scps map[string]any) {
	t.Helper()
	scpDir := filepath.Join(dir, "scps")
	if err := os.MkdirAll(scpDir, 0750); err != nil {
		t.Fatal(err)
	}
	for id, content := range scps {
		data, _ := json.Marshal(content)
		if err := os.WriteFile(filepath.Join(scpDir, id+".json"), data, 0640); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenerateTerraform(t *testing.T) {
	compiledDir := t.TempDir()
	writeSCPFixtures(t, compiledDir, map[string]any{
		"attest-scp-01": map[string]any{"Version": "2012-10-17", "Statement": []any{}},
	})

	outDir := t.TempDir()
	g := NewGenerator(FormatTerraform, outDir)
	if err := g.Generate(compiledDir); err != nil {
		t.Fatalf("GenerateTerraform() error: %v", err)
	}

	// Verify main.tf exists.
	mainTF, err := os.ReadFile(filepath.Join(outDir, "main.tf"))
	if err != nil {
		t.Fatalf("main.tf not found: %v", err)
	}
	content := string(mainTF)
	if !strings.Contains(content, "aws_organizations_policy") {
		t.Error("main.tf missing aws_organizations_policy resource")
	}
	if !strings.Contains(content, "attest-scp-01") {
		t.Error("main.tf missing SCP name")
	}
	if !strings.Contains(content, "aws_organizations_policy_attachment") {
		t.Error("main.tf missing attachment resource")
	}

	// Verify SCP files copied.
	if _, err := os.Stat(filepath.Join(outDir, "scps", "attest-scp-01.json")); err != nil {
		t.Error("SCP JSON not copied to terraform dir")
	}
}

func TestGenerateCDK(t *testing.T) {
	compiledDir := t.TempDir()
	writeSCPFixtures(t, compiledDir, map[string]any{
		"attest-scp-01": map[string]any{"Version": "2012-10-17", "Statement": []any{}},
		"attest-scp-02": map[string]any{"Version": "2012-10-17", "Statement": []any{}},
	})

	outDir := t.TempDir()
	g := NewGenerator(FormatCDK, outDir)
	if err := g.Generate(compiledDir); err != nil {
		t.Fatalf("GenerateCDK() error: %v", err)
	}

	// Verify stack.ts exists and contains CDK constructs.
	stackTS, err := os.ReadFile(filepath.Join(outDir, "stack.ts"))
	if err != nil {
		t.Fatalf("stack.ts not found: %v", err)
	}
	ts := string(stackTS)
	if !strings.Contains(ts, "aws-cdk-lib") {
		t.Error("stack.ts missing aws-cdk-lib import")
	}
	if !strings.Contains(ts, "CfnPolicy") {
		t.Error("stack.ts missing CfnPolicy construct")
	}
	if !strings.Contains(ts, "CfnPolicyAttachment") {
		t.Error("stack.ts missing CfnPolicyAttachment")
	}
	if !strings.Contains(ts, "attest-scp-01") {
		t.Error("stack.ts missing first SCP name")
	}
	if !strings.Contains(ts, "attest-scp-02") {
		t.Error("stack.ts missing second SCP name")
	}

	// Verify supporting files.
	for _, f := range []string{"cdk.json", "package.json", "tsconfig.json"} {
		if _, err := os.Stat(filepath.Join(outDir, f)); err != nil {
			t.Errorf("%s not found: %v", f, err)
		}
	}

	// Verify SCP files copied.
	if _, err := os.Stat(filepath.Join(outDir, "scps", "attest-scp-01.json")); err != nil {
		t.Error("SCP JSON not copied to CDK dir")
	}
}

func TestToCDKResourceID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"attest-scp-01", "AttestScp01"},
		{"my-policy", "MyPolicy"},
		{"single", "Single"},
		{"a-b-c", "ABC"},
	}
	for _, tt := range tests {
		got := toCDKResourceID(tt.input)
		if got != tt.want {
			t.Errorf("toCDKResourceID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGenerateUnsupportedFormat(t *testing.T) {
	g := NewGenerator("unknown", t.TempDir())
	if err := g.Generate(t.TempDir()); err == nil {
		t.Error("unsupported format should return error")
	}
}

func TestGenerateMissingSCPDir(t *testing.T) {
	compiledDir := t.TempDir() // no scps/ subdirectory
	g := NewGenerator(FormatTerraform, t.TempDir())
	if err := g.Generate(compiledDir); err == nil {
		t.Error("missing scps/ dir should return error")
	}
}
