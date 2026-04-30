// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package oscal

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/provabl/attest/internal/document/assessment"
	"github.com/provabl/attest/internal/document/ssp"
	"github.com/provabl/attest/pkg/schema"
)

// uuidRE matches a UUID — essential for OSCAL document interoperability with GRC tools.
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// TestNewUUID verifies UUID format (required by OSCAL 1.1.2 specification).
func TestNewUUID(t *testing.T) {
	for i := 0; i < 100; i++ {
		u := newUUID()
		if !uuidRE.MatchString(u) {
			t.Errorf("newUUID() = %q does not match UUID format", u)
		}
	}
}

// TestNewUUID_Uniqueness verifies no two consecutive UUIDs collide.
func TestNewUUID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		u := newUUID()
		if seen[u] {
			t.Fatalf("newUUID() returned duplicate at iteration %d: %s", i, u)
		}
		seen[u] = true
	}
}

// TestOSCALStatus covers all status mapping paths — correct OSCAL values are
// required for ServiceNow GRC and other receivers to interpret findings correctly.
func TestOSCALStatus(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"enforced", "implemented"},
		{"aws_covered", "implemented"},
		{"Implemented", "implemented"},
		{"partial", "partially-implemented"},
		{"Partially Implemented", "partially-implemented"},
		{"planned", "planned"},
		{"Planned", "planned"},
		{"gap", "not-implemented"},
		{"", "not-implemented"},
		{"unknown", "not-implemented"},
	}
	for _, tt := range tests {
		got := oscalStatus(tt.input)
		if got != tt.want {
			t.Errorf("oscalStatus(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestExportSSP_Structure verifies the SSP export produces valid OSCAL 1.1.2 JSON.
func TestExportSSP_Structure(t *testing.T) {
	sre := &schema.SRE{
		OrgID: "o-abc12345",
		Name:  "Test Research SRE",
	}
	s := &ssp.SSP{
		Title:         "Test SSP",
		Framework:     &schema.Framework{ID: "nist-800-171-r2", Name: "NIST SP 800-171 R2"},
		GeneratedAt:   time.Now(),
		SRE:           sre,
		OverallStatus: "Partial",
		Sections: []ssp.Section{
			{
				Family: "Access Control",
				Controls: []ssp.ControlNarrative{
					{ControlID: "3.1.1", Title: "AC", Status: "Implemented",           CustomerImpl: "MFA via SCP"},
					{ControlID: "3.1.2", Title: "AC", Status: "Partially Implemented", CustomerImpl: "Partial"},
					{ControlID: "3.1.3", Title: "AC", Status: "Planned",               CustomerImpl: "Planned"},
				},
			},
		},
	}

	exporter := NewSSPExporter()
	data, err := exporter.ExportSSP(s)
	if err != nil {
		t.Fatalf("ExportSSP() error: %v", err)
	}

	// Must parse as valid JSON.
	var doc SSPDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("ExportSSP() produced invalid JSON: %v\nOutput: %s", err, string(data))
	}

	sp := doc.SystemSecurityPlan

	// Top-level UUID must be valid.
	if !uuidRE.MatchString(sp.UUID) {
		t.Errorf("SSP UUID %q is not valid", sp.UUID)
	}

	// Metadata must carry title and OSCAL version.
	if sp.Metadata.Title != "Test SSP" {
		t.Errorf("Metadata.Title = %q, want Test SSP", sp.Metadata.Title)
	}
	if sp.Metadata.OSCALVersion != oscalVersion {
		t.Errorf("OSCAL version = %q, want %q", sp.Metadata.OSCALVersion, oscalVersion)
	}

	// All 3 controls must be exported.
	if len(sp.ControlImplementation) != 3 {
		t.Fatalf("got %d control implementations, want 3", len(sp.ControlImplementation))
	}

	// Every control implementation must have valid UUID and status.
	validStatuses := map[string]bool{
		"implemented": true, "partially-implemented": true,
		"planned": true, "not-implemented": true,
	}
	for i, ci := range sp.ControlImplementation {
		if !uuidRE.MatchString(ci.UUID) {
			t.Errorf("ControlImplementation[%d].UUID %q invalid", i, ci.UUID)
		}
		for _, bc := range ci.ByComponents {
			if !validStatuses[bc.ImplementationStatus] {
				t.Errorf("ControlImplementation[%d] has invalid OSCAL status %q", i, bc.ImplementationStatus)
			}
		}
	}

	// SystemCharacteristics must reference org.
	if !strings.Contains(sp.SystemCharacteristics.SystemName, "Test Research") {
		t.Errorf("SystemName = %q, should contain SRE name", sp.SystemCharacteristics.SystemName)
	}
}

// TestExportAssessment_Structure verifies Assessment Results OSCAL export.
func TestExportAssessment_Structure(t *testing.T) {
	a := &assessment.Assessment{
		Title:        "CMMC Assessment",
		Framework:    "nist-800-171-r2",
		TotalScore:   440,
		MaxScore:     550,
		ScorePercent: 80.0,
		GeneratedAt:  time.Now(),
		FamilyScores: []assessment.FamilyScore{
			{
				Family:   "3.1",
				Score:    8,
				MaxScore: 10,
				Controls: []assessment.ControlScore{
					{ControlID: "3.1.1", ControlTitle: "Access control",   Status: "enforced", Score: 5, MaxScore: 5, Rationale: "MFA SCP"},
					{ControlID: "3.1.2", ControlTitle: "Transaction priv", Status: "partial",  Score: 3, MaxScore: 5, Rationale: "Partial impl"},
				},
			},
		},
	}

	exporter := NewAssessmentExporter()
	data, err := exporter.ExportAssessment(a)
	if err != nil {
		t.Fatalf("ExportAssessment() error: %v", err)
	}

	var doc AssessmentResultsDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("ExportAssessment() invalid JSON: %v", err)
	}

	ar := doc.AssessmentResults
	if !uuidRE.MatchString(ar.UUID) {
		t.Errorf("AssessmentResults UUID %q invalid", ar.UUID)
	}
	if ar.Metadata.OSCALVersion != oscalVersion {
		t.Errorf("OSCAL version = %q, want %q", ar.Metadata.OSCALVersion, oscalVersion)
	}
	if len(ar.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(ar.Results))
	}

	result := ar.Results[0]
	if len(result.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(result.Findings))
	}

	// Status mapping must be applied.
	if result.Findings[0].ImplementationStatus != "implemented" {
		t.Errorf("enforced → %q, want implemented", result.Findings[0].ImplementationStatus)
	}
	if result.Findings[1].ImplementationStatus != "partially-implemented" {
		t.Errorf("partial → %q, want partially-implemented", result.Findings[1].ImplementationStatus)
	}

	// Control IDs must be preserved.
	if result.Findings[0].TargetControlID != "3.1.1" {
		t.Errorf("TargetControlID = %q, want 3.1.1", result.Findings[0].TargetControlID)
	}
}

// TestExportSSP_EmptyControls verifies graceful handling of empty sections.
func TestExportSSP_EmptyControls(t *testing.T) {
	s := &ssp.SSP{
		Title:       "Empty SSP",
		GeneratedAt: time.Now(),
		SRE:         &schema.SRE{OrgID: "o-test"},
		Sections:    nil,
	}
	data, err := NewSSPExporter().ExportSSP(s)
	if err != nil {
		t.Fatalf("ExportSSP(empty) error: %v", err)
	}
	var doc SSPDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("empty SSP invalid JSON: %v", err)
	}
	if len(doc.SystemSecurityPlan.ControlImplementation) != 0 {
		t.Error("empty SSP should produce no control implementations")
	}
}
