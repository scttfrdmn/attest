package assessment

import (
	"strings"
	"testing"
	"time"

	"github.com/provabl/attest/pkg/schema"
)

func makeTestData() (*schema.SRE, *schema.Framework, *schema.Crosswalk) {
	sre := &schema.SRE{OrgID: "o-test", Name: "Test SRE"}
	fw := &schema.Framework{
		ID:   "nist-test",
		Name: "NIST Test",
		Controls: []schema.Control{
			{ID: "3.1.1", Family: "Access Control", Title: "Limit system access"},
			{ID: "3.1.3", Family: "Access Control", Title: "Control CUI flow"},
			{ID: "3.13.11", Family: "Sys & Comms", Title: "FIPS crypto"},
			{ID: "3.14.1", Family: "Integrity", Title: "System flaws"},
		},
	}
	cw := &schema.Crosswalk{
		SRE:         "o-test",
		Framework:   "nist-test",
		GeneratedAt: time.Now(),
		Entries: []schema.CrosswalkEntry{
			{ControlID: "3.1.1", Status: "enforced"},
			{ControlID: "3.1.3", Status: "partial"},
			{ControlID: "3.13.11", Status: "aws_covered"},
			{ControlID: "3.14.1", Status: "gap"},
		},
	}
	return sre, fw, cw
}

func TestScoring(t *testing.T) {
	sre, fw, cw := makeTestData()
	gen := NewGenerator()
	doc, err := gen.Generate(sre, fw, cw)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// enforced=5 + partial=3 + aws_covered=5 + gap=0 = 13/20
	wantScore := 13
	if doc.TotalScore != wantScore {
		t.Errorf("TotalScore = %d, want %d", doc.TotalScore, wantScore)
	}
	wantMax := 20 // 4 controls × 5
	if doc.MaxScore != wantMax {
		t.Errorf("MaxScore = %d, want %d", doc.MaxScore, wantMax)
	}
	wantPct := 65.0
	if doc.ScorePercent < wantPct-0.5 || doc.ScorePercent > wantPct+0.5 {
		t.Errorf("ScorePercent = %.1f, want %.1f", doc.ScorePercent, wantPct)
	}
}

func TestCounts(t *testing.T) {
	sre, fw, cw := makeTestData()
	gen := NewGenerator()
	doc, _ := gen.Generate(sre, fw, cw)

	if doc.Implemented != 2 { // enforced + aws_covered
		t.Errorf("Implemented = %d, want 2", doc.Implemented)
	}
	if doc.Partial != 1 {
		t.Errorf("Partial = %d, want 1", doc.Partial)
	}
	if doc.Gaps != 1 {
		t.Errorf("Gaps = %d, want 1", doc.Gaps)
	}
}

func TestReadinessNotReady(t *testing.T) {
	// All gaps → Not Ready
	sre := &schema.SRE{OrgID: "o-test"}
	fw := &schema.Framework{
		ID: "test",
		Controls: []schema.Control{
			{ID: "1.1", Family: "Fam"}, {ID: "1.2", Family: "Fam"}, {ID: "1.3", Family: "Fam"},
		},
	}
	cw := &schema.Crosswalk{
		Entries: []schema.CrosswalkEntry{
			{ControlID: "1.1", Status: "gap"},
			{ControlID: "1.2", Status: "gap"},
			{ControlID: "1.3", Status: "gap"},
		},
	}
	gen := NewGenerator()
	doc, _ := gen.Generate(sre, fw, cw)
	if doc.Readiness != "Not Ready" {
		t.Errorf("Readiness = %q, want Not Ready", doc.Readiness)
	}
}

func TestRender(t *testing.T) {
	sre, fw, cw := makeTestData()
	gen := NewGenerator()
	doc, _ := gen.Generate(sre, fw, cw)

	md := doc.Render()
	wantStrings := []string{
		"Self-Assessment",
		"Score",
		"Summary",
		"Access Control",
		"3.1.1",
	}
	for _, want := range wantStrings {
		if !strings.Contains(md, want) {
			t.Errorf("Render() missing %q", want)
		}
	}
}
