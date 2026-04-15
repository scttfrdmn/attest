package ssp

import (
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/attest/pkg/schema"
)

func makeTestSSP() *SSP {
	sre := &schema.SRE{OrgID: "o-test", Name: "Test SRE"}
	fw := &schema.Framework{ID: "test-fw", Name: "Test Framework", Version: "1.0"}
	cw := &schema.Crosswalk{SRE: "o-test", Framework: "test-fw", GeneratedAt: time.Now()}
	return &SSP{
		Title:         "Test SSP",
		SRE:           sre,
		Framework:     fw,
		Crosswalk:     cw,
		GeneratedAt:   time.Now(),
		OverallStatus: "Partial",
		Score:         15,
		Sections: []Section{
			{
				Family: "Access Control",
				Controls: []ControlNarrative{
					{
						ControlID:       "3.1.1",
						Title:           "Limit system access",
						Status:          "Implemented",
						AssessmentScore: 5,
						AWSCoverage:     "IAM service",
						CustomerImpl:    "Enforced via SCP scp-require-mfa.",
						Enforcement:     EnforcementSummary{SCPs: []string{"scp-require-mfa"}},
					},
					{
						ControlID:       "3.1.2",
						Title:           "Limit access to transactions",
						Status:          "Partially Implemented",
						AssessmentScore: 3,
						CustomerImpl:    "SCP deployed, Cedar policy pending.",
					},
					{
						ControlID:       "3.1.4",
						Title:           "Separate duties",
						Status:          "Planned",
						AssessmentScore: 1,
					},
				},
			},
		},
	}
}

func TestRender(t *testing.T) {
	s := makeTestSSP()
	md, err := s.Render()
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	checks := []string{
		"# System Security Plan",
		"o-test",
		"Test Framework",
		"Partial",
		"CMMC Score",
		"Access Control",
		"3.1.1",
		"Limit system access",
		"scp-require-mfa",
		"3.1.2",
		"3.1.4",
		"Executive Summary",
	}
	for _, want := range checks {
		if !strings.Contains(md, want) {
			t.Errorf("Render() missing %q", want)
		}
	}
}

func TestRenderEmptySSP(t *testing.T) {
	s := &SSP{
		SRE:         &schema.SRE{OrgID: "o-empty"},
		Framework:   &schema.Framework{ID: "fw", Name: "FW"},
		Crosswalk:   &schema.Crosswalk{GeneratedAt: time.Now()},
		GeneratedAt: time.Now(),
	}
	md, err := s.Render()
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if !strings.Contains(md, "# System Security Plan") {
		t.Error("empty SSP missing header")
	}
}
