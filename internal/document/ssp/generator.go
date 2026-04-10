// Package ssp generates System Security Plans from the SRE state.
// The SSP is not a document someone writes — it's a document the system emits
// from the crosswalk, deployed policy state, and Cedar evaluation logs.
package ssp

import (
	"fmt"
	"strings"
	"time"

	"github.com/scttfrdmn/attest/pkg/schema"
)

// SSP is a generated System Security Plan.
type SSP struct {
	Title           string
	SRE             *schema.SRE
	Framework       *schema.Framework
	Crosswalk       *schema.Crosswalk
	GeneratedAt     time.Time
	Sections        []Section
	OverallStatus   string  // "Compliant", "Partial", "Non-Compliant"
	Score           float64 // For CMMC scoring (110 points possible for 800-171)
}

// Section is a control family section within the SSP.
type Section struct {
	Family   string
	Controls []ControlNarrative
}

// ControlNarrative is the SSP entry for a single control.
type ControlNarrative struct {
	ControlID       string
	Title           string
	Status          string // "Implemented", "Partially Implemented", "Planned", "Not Applicable"
	AWSCoverage     string // What AWS covers (from shared responsibility)
	CustomerImpl    string // Auto-generated narrative of customer implementation
	Enforcement     EnforcementSummary
	Evidence        []EvidenceRef
	AssessmentScore int // For CMMC: points awarded (0, 1, 3, or 5)
}

// EnforcementSummary describes how the control is enforced.
type EnforcementSummary struct {
	SCPs          []string // Deployed SCP IDs
	CedarPolicies []string // Active Cedar policy IDs
	ConfigRules   []string // Active Config rule names
}

// EvidenceRef links to audit evidence for a control.
type EvidenceRef struct {
	Type        string // "artifact_report", "cedar_log", "config_eval", "scp_deployment"
	Description string
	Reference   string // ARN, S3 path, Artifact report ID
}

// Generator produces SSPs from the SRE state and crosswalk.
type Generator struct{}

func NewGenerator() *Generator { return &Generator{} }

// Generate creates an SSP for a specific framework from the current SRE state.
// Every fact in the SSP is derived from system state — nothing is hand-written.
func (g *Generator) Generate(
	sre *schema.SRE,
	fw *schema.Framework,
	crosswalk *schema.Crosswalk,
	evalStats map[string]EvalStats, // Cedar evaluation statistics per policy
) (*SSP, error) {
	ssp := &SSP{
		Title:       fmt.Sprintf("System Security Plan — %s — %s", sre.Name, fw.Name),
		SRE:         sre,
		Framework:   fw,
		Crosswalk:   crosswalk,
		GeneratedAt: time.Now(),
	}

	// Group controls by family.
	families := make(map[string][]schema.Control)
	for _, ctrl := range fw.Controls {
		families[ctrl.Family] = append(families[ctrl.Family], ctrl)
	}

	var totalScore float64
	var maxScore float64

	for family, controls := range families {
		section := Section{Family: family}
		for _, ctrl := range controls {
			narrative := g.generateNarrative(ctrl, crosswalk, evalStats)
			section.Controls = append(section.Controls, narrative)
			totalScore += float64(narrative.AssessmentScore)
			maxScore += 5 // Each control worth up to 5 points in CMMC
		}
		ssp.Sections = append(ssp.Sections, section)
	}

	ssp.Score = totalScore
	if totalScore == maxScore {
		ssp.OverallStatus = "Compliant"
	} else if totalScore >= maxScore*0.8 {
		ssp.OverallStatus = "Partial"
	} else {
		ssp.OverallStatus = "Non-Compliant"
	}

	return ssp, nil
}

// generateNarrative produces the SSP entry for a single control.
// The narrative is mechanically derived from the crosswalk and evaluation data.
func (g *Generator) generateNarrative(
	ctrl schema.Control,
	crosswalk *schema.Crosswalk,
	evalStats map[string]EvalStats,
) ControlNarrative {
	cn := ControlNarrative{
		ControlID:   ctrl.ID,
		Title:       ctrl.Title,
		AWSCoverage: ctrl.Responsibility.AWS,
	}

	// Find crosswalk entry for this control.
	var entry *schema.CrosswalkEntry
	for i := range crosswalk.Entries {
		if crosswalk.Entries[i].ControlID == ctrl.ID {
			entry = &crosswalk.Entries[i]
			break
		}
	}

	if entry == nil {
		cn.Status = "Planned"
		cn.CustomerImpl = fmt.Sprintf(
			"Control %s (%s) is not yet enforced. Customer responsibility: %s",
			ctrl.ID, ctrl.Title, ctrl.Responsibility.Customer,
		)
		cn.AssessmentScore = 0
		return cn
	}

	// Build the narrative from deployed artifacts.
	var parts []string
	cn.Enforcement.SCPs = entry.SCPs
	cn.Enforcement.CedarPolicies = entry.CedarPolicies
	cn.Enforcement.ConfigRules = entry.ConfigRules

	if len(entry.SCPs) > 0 {
		parts = append(parts, fmt.Sprintf(
			"Structural enforcement via SCP(s) %s applied at the organization level, "+
				"ensuring all environments within the SRE inherit this control.",
			strings.Join(entry.SCPs, ", "),
		))
		cn.Evidence = append(cn.Evidence, EvidenceRef{
			Type:        "scp_deployment",
			Description: "SCP attached to SRE organization root",
			Reference:   strings.Join(entry.SCPs, ", "),
		})
	}

	if len(entry.CedarPolicies) > 0 {
		parts = append(parts, fmt.Sprintf(
			"Operational enforcement via Cedar policy/policies %s providing "+
				"context-dependent runtime evaluation of data classification, "+
				"destination attributes, and principal qualifications.",
			strings.Join(entry.CedarPolicies, ", "),
		))

		// Add evaluation statistics as evidence.
		for _, pid := range entry.CedarPolicies {
			if stats, ok := evalStats[pid]; ok {
				cn.Evidence = append(cn.Evidence, EvidenceRef{
					Type: "cedar_log",
					Description: fmt.Sprintf(
						"Cedar evaluation log: %d evaluations, %d permits, %d denies "+
							"over period %s to %s",
						stats.Total, stats.Permits, stats.Denies,
						stats.PeriodStart.Format("2006-01-02"),
						stats.PeriodEnd.Format("2006-01-02"),
					),
					Reference: stats.LogLocation,
				})
			}
		}
	}

	if len(entry.ConfigRules) > 0 {
		parts = append(parts, fmt.Sprintf(
			"Continuous monitoring via AWS Config rule(s) %s detecting "+
				"drift from the required configuration baseline.",
			strings.Join(entry.ConfigRules, ", "),
		))
	}

	if len(entry.ArtifactReports) > 0 {
		parts = append(parts, fmt.Sprintf(
			"AWS shared responsibility coverage evidenced by Artifact report(s) %s.",
			strings.Join(entry.ArtifactReports, ", "),
		))
		for _, r := range entry.ArtifactReports {
			cn.Evidence = append(cn.Evidence, EvidenceRef{
				Type:        "artifact_report",
				Description: "AWS compliance report from Artifact",
				Reference:   r,
			})
		}
	}

	cn.CustomerImpl = strings.Join(parts, " ")

	// Score based on enforcement depth.
	switch entry.Status {
	case "enforced":
		cn.Status = "Implemented"
		cn.AssessmentScore = 5
	case "partial":
		cn.Status = "Partially Implemented"
		cn.AssessmentScore = 3
	case "aws_covered":
		cn.Status = "Implemented"
		cn.AssessmentScore = 5
	default:
		cn.Status = "Planned"
		cn.AssessmentScore = 1
	}

	return cn
}

// EvalStats holds Cedar evaluation statistics for a policy over a period.
type EvalStats struct {
	PolicyID    string
	Total       int
	Permits     int
	Denies      int
	PeriodStart time.Time
	PeriodEnd   time.Time
	LogLocation string // S3 path to evaluation log
}
