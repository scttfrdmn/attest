package iac

import (
	"testing"
)

// TestGenerateRejectsRelativeTraversal covers the HIGH security fix:
// relative path traversal in Generator.Generate() outputDir is blocked.
func TestGenerateRejectsRelativeTraversal(t *testing.T) {
	cases := []string{
		"../../etc/passwd",
		"../sibling",
		"../../../tmp",
	}
	for _, dir := range cases {
		g := NewGenerator(FormatTerraform, dir)
		if err := g.Generate(t.TempDir()); err == nil {
			t.Errorf("Generate(%q) should reject relative traversal", dir)
		}
	}
}

func TestGenerateAcceptsAbsoluteDir(t *testing.T) {
	// Absolute paths from programmatic use should be accepted.
	compiledDir := t.TempDir()
	writeSCPFixtures(t, compiledDir, map[string]interface{}{
		"attest-scp-01": map[string]interface{}{"Version": "2012-10-17"},
	})
	g := NewGenerator(FormatTerraform, t.TempDir()) // t.TempDir() is absolute — OK
	if err := g.Generate(compiledDir); err != nil {
		t.Errorf("Generate with absolute outputDir failed: %v", err)
	}
}
