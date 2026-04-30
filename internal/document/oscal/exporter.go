// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package oscal exports compliance documents in NIST OSCAL format.
// OSCAL (Open Security Controls Assessment Language) provides
// interoperability with the federal GRC ecosystem — auditors and
// C3PAOs can ingest this directly.
//
// Implements OSCAL version 1.1.2.
// Exports:
//   - SSP → OSCAL System Security Plan model
//   - Assessment Results → OSCAL Assessment Results model
package oscal

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/provabl/attest/internal/document/assessment"
	"github.com/provabl/attest/internal/document/ssp"
)

const oscalVersion = "1.1.2"

// --- OSCAL SSP types ---

// SSPDocument is the top-level OSCAL SSP wrapper.
type SSPDocument struct {
	SystemSecurityPlan SSPModel `json:"system-security-plan"`
}

// SSPModel is the OSCAL System Security Plan model.
type SSPModel struct {
	UUID                string                   `json:"uuid"`
	Metadata            Metadata                 `json:"metadata"`
	SystemCharacteristics SystemCharacteristics  `json:"system-characteristics"`
	ControlImplementation []ControlImplementation `json:"control-implementation,omitempty"`
}

// Metadata is OSCAL document metadata, common across all models.
type Metadata struct {
	Title        string    `json:"title"`
	LastModified time.Time `json:"last-modified"`
	Version      string    `json:"version"`
	OSCALVersion string    `json:"oscal-version"`
}

// SystemCharacteristics describes the system boundary.
type SystemCharacteristics struct {
	SystemName          string `json:"system-name"`
	Description         string `json:"description"`
	SecuritySensitivityLevel string `json:"security-sensitivity-level"`
}

// ControlImplementation describes how a single control is implemented.
type ControlImplementation struct {
	UUID        string               `json:"uuid"`
	Description string               `json:"description"`
	ByComponents []ByComponent        `json:"by-components,omitempty"`
}

// ByComponent describes implementation by a system component.
type ByComponent struct {
	ComponentUUID        string `json:"component-uuid"`
	Description          string `json:"description"`
	ImplementationStatus string `json:"implementation-status"`
}

// --- OSCAL Assessment Results types ---

// AssessmentResultsDocument is the top-level OSCAL Assessment Results wrapper.
type AssessmentResultsDocument struct {
	AssessmentResults AssessmentResultsModel `json:"assessment-results"`
}

// AssessmentResultsModel is the OSCAL Assessment Results model.
type AssessmentResultsModel struct {
	UUID     string   `json:"uuid"`
	Metadata Metadata `json:"metadata"`
	Results  []Result `json:"results,omitempty"`
}

// Result is a single assessment result set.
type Result struct {
	UUID        string        `json:"uuid"`
	Title       string        `json:"title"`
	Start       time.Time     `json:"start"`
	End         time.Time     `json:"end"`
	Findings    []Finding     `json:"findings,omitempty"`
}

// Finding is a single control assessment finding.
type Finding struct {
	UUID              string `json:"uuid"`
	Title             string `json:"title"`
	TargetControlID   string `json:"target-control-id"`
	ImplementationStatus string `json:"implementation-status"`
	Description       string `json:"description"`
}

// --- Exporters ---

// SSPExporter converts an internal SSP to OSCAL format.
type SSPExporter struct{}

// NewSSPExporter creates an SSP exporter.
func NewSSPExporter() *SSPExporter { return &SSPExporter{} }

// ExportSSP converts an internal SSP to OSCAL SSP JSON.
func (e *SSPExporter) ExportSSP(s *ssp.SSP) ([]byte, error) {
	doc := SSPDocument{
		SystemSecurityPlan: SSPModel{
			UUID: newUUID(),
			Metadata: Metadata{
				Title:        s.Title,
				LastModified: s.GeneratedAt,
				Version:      "1.0",
				OSCALVersion: oscalVersion,
			},
			SystemCharacteristics: SystemCharacteristics{
				SystemName:               s.SRE.Name,
				Description:              fmt.Sprintf("AWS SRE for org %s", s.SRE.OrgID),
				SecuritySensitivityLevel: "moderate",
			},
		},
	}

	// Build control implementations from SSP sections.
	for _, section := range s.Sections {
		for _, ctrl := range section.Controls {
			ci := ControlImplementation{
				UUID:        newUUID(),
				Description: ctrl.CustomerImpl,
			}
			status := oscalStatus(ctrl.Status)
			ci.ByComponents = []ByComponent{{
				ComponentUUID:        newUUID(),
				Description:          ctrl.CustomerImpl,
				ImplementationStatus: status,
			}}
			doc.SystemSecurityPlan.ControlImplementation = append(
				doc.SystemSecurityPlan.ControlImplementation, ci)
		}
	}

	return json.MarshalIndent(doc, "", "  ")
}

// AssessmentExporter converts a self-assessment to OSCAL format.
type AssessmentExporter struct{}

// NewAssessmentExporter creates an assessment exporter.
func NewAssessmentExporter() *AssessmentExporter { return &AssessmentExporter{} }

// ExportAssessment converts an internal Assessment to OSCAL Assessment Results JSON.
func (e *AssessmentExporter) ExportAssessment(a *assessment.Assessment) ([]byte, error) {
	now := time.Now()
	doc := AssessmentResultsDocument{
		AssessmentResults: AssessmentResultsModel{
			UUID: newUUID(),
			Metadata: Metadata{
				Title:        a.Title,
				LastModified: a.GeneratedAt,
				Version:      "1.0",
				OSCALVersion: oscalVersion,
			},
			Results: []Result{{
				UUID:  newUUID(),
				Title: fmt.Sprintf("%s Assessment Results", a.Framework),
				Start: now,
				End:   now,
			}},
		},
	}

	var findings []Finding
	for _, fs := range a.FamilyScores {
		for _, cs := range fs.Controls {
			findings = append(findings, Finding{
				UUID:                 newUUID(),
				Title:                fmt.Sprintf("%s — %s", cs.ControlID, cs.ControlTitle),
				TargetControlID:      cs.ControlID,
				ImplementationStatus: oscalStatus(cs.Status),
				Description:          cs.Rationale,
			})
		}
	}
	doc.AssessmentResults.Results[0].Findings = findings

	return json.MarshalIndent(doc, "", "  ")
}

// --- helpers ---

// oscalStatus maps crosswalk/assessment status to OSCAL implementation-status values.
func oscalStatus(status string) string {
	switch status {
	case "enforced", "aws_covered", "Implemented":
		return "implemented"
	case "partial", "Partially Implemented":
		return "partially-implemented"
	case "planned", "Planned":
		return "planned"
	default:
		return "not-implemented"
	}
}

// newUUID generates a random UUID v4.
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
