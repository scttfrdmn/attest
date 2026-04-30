// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package ssp

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/provabl/attest/internal/framework"
	"github.com/provabl/attest/pkg/schema"
)

// MultiFrameworkSSP is a combined System Security Plan across all active frameworks.
type MultiFrameworkSSP struct {
	Title        string
	SRE          *schema.SRE
	Frameworks   []*schema.Framework
	Crosswalk    *schema.Crosswalk
	Posture      *schema.Posture
	Supersessions []SupersessionEntry
	Conflicts    []framework.Conflict
	GeneratedAt  time.Time
	Sections     []MultiFrameworkSection
}

// MultiFrameworkSection groups controls by family across all frameworks.
type MultiFrameworkSection struct {
	Family    string
	Controls  []MultiFrameworkControlNarrative
}

// MultiFrameworkControlNarrative is an SSP entry for a control that may be
// satisfied by enforcement from a different co-active framework.
type MultiFrameworkControlNarrative struct {
	ControlID      string
	FrameworkID    string
	Title          string
	Status         string
	AWSCoverage    string
	CustomerImpl   string
	Enforcement    EnforcementSummary
	Evidence       []EvidenceRef
	// CrossSatisfiedBy is non-empty when this control is satisfied via supersession.
	CrossSatisfiedBy *SupersessionEntry
}

// GenerateMultiFramework produces a combined SSP from all active frameworks.
// It applies the supersession registry to mark controls satisfied by stricter
// co-active framework requirements, and includes a conflict resolution record.
func (g *Generator) GenerateMultiFramework(
	sre *schema.SRE,
	frameworks []*schema.Framework,
	crosswalk *schema.Crosswalk,
	posture *schema.Posture,
	conflicts []framework.Conflict,
) (*MultiFrameworkSSP, error) {
	if len(frameworks) == 0 {
		return nil, fmt.Errorf("no frameworks provided")
	}

	supersessionMap := SupersessionMap()
	applicableSupersessions := findApplicableSupersessions(frameworks)

	// Build merged sections across all frameworks.
	sections := buildMergedSections(frameworks, crosswalk, supersessionMap, posture)

	return &MultiFrameworkSSP{
		Title: fmt.Sprintf("Multi-Framework System Security Plan — %s", sre.Name),
		SRE:          sre,
		Frameworks:   frameworks,
		Crosswalk:    crosswalk,
		Posture:      posture,
		Supersessions: applicableSupersessions,
		Conflicts:    conflicts,
		GeneratedAt:  time.Now(),
		Sections:     sections,
	}, nil
}

// Render produces the markdown representation of the combined SSP.
func (m *MultiFrameworkSSP) Render() string {
	var b strings.Builder

	b.WriteString("# " + m.Title + "\n\n")
	b.WriteString("**Generated:** " + m.GeneratedAt.Format("2006-01-02 15:04 UTC") + "\n\n")
	b.WriteString("---\n\n")

	// Section 1: System Overview
	b.WriteString("## 1. System Overview\n\n")
	b.WriteString(fmt.Sprintf("**Organization:** %s  \n", m.SRE.OrgID))
	b.WriteString(fmt.Sprintf("**SRE Name:** %s  \n", m.SRE.Name))
	b.WriteString(fmt.Sprintf("**Active Frameworks:** %d\n\n", len(m.Frameworks)))
	for _, fw := range m.Frameworks {
		b.WriteString(fmt.Sprintf("- **%s** v%s\n", fw.Name, fw.Version))
	}
	b.WriteString("\n")

	// Section 2: Posture Summary
	if m.Posture != nil {
		b.WriteString("## 2. Compliance Posture Summary\n\n")
		b.WriteString("| Framework | Enforced | Partial | Gaps | Cross-Satisfied |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, fw := range m.Frameworks {
			fp := m.Posture.Frameworks[fw.ID]
			enforced, partial, gaps := 0, 0, 0
			for _, status := range fp.Controls {
				switch status {
				case "enforced", "aws_covered":
					enforced++
				case "partial":
					partial++
				case "gap":
					gaps++
				}
			}
			xSat := len(fp.CrossSatisfiedFrom)
			b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d |\n",
				fw.Name, enforced, partial, gaps, xSat))
		}
		if m.Posture.CrossSatisfied > 0 {
			b.WriteString(fmt.Sprintf("\n*%d controls satisfied via cross-framework supersession*\n", m.Posture.CrossSatisfied))
		}
		b.WriteString("\n")
	}

	// Section 3: Merged Control Families
	b.WriteString("## 3. Control Families\n\n")
	for _, section := range m.Sections {
		b.WriteString(fmt.Sprintf("### %s\n\n", section.Family))
		for _, ctrl := range section.Controls {
			b.WriteString(fmt.Sprintf("**%s — %s** `[%s]` `[%s]`\n\n",
				ctrl.ControlID, ctrl.Title, ctrl.FrameworkID, ctrl.Status))
			if ctrl.CrossSatisfiedBy != nil {
				b.WriteString(fmt.Sprintf("> *Satisfied via supersession:* %s %s (%s) provides %s enforcement. No additional evidence required.\n\n",
					ctrl.CrossSatisfiedBy.SupersedingFramework,
					ctrl.CrossSatisfiedBy.SupersedingControl,
					ctrl.CrossSatisfiedBy.SupersedingTitle,
					ctrl.CrossSatisfiedBy.Mechanism))
			} else {
				if ctrl.AWSCoverage != "" {
					b.WriteString(fmt.Sprintf("**AWS:** %s\n\n", ctrl.AWSCoverage))
				}
				if ctrl.CustomerImpl != "" {
					b.WriteString(fmt.Sprintf("**Customer:** %s\n\n", ctrl.CustomerImpl))
				}
				if len(ctrl.Enforcement.SCPs) > 0 {
					b.WriteString("**SCPs:** " + strings.Join(ctrl.Enforcement.SCPs, ", ") + "\n\n")
				}
				if len(ctrl.Enforcement.CedarPolicies) > 0 {
					b.WriteString("**Cedar:** " + strings.Join(ctrl.Enforcement.CedarPolicies, ", ") + "\n\n")
				}
			}
		}
	}

	// Section 4: Supersession Registry
	b.WriteString("## 4. Supersession Registry\n\n")
	b.WriteString("Controls listed here require no additional evidence — they are satisfied by a stricter co-active framework requirement.\n\n")
	b.WriteString("| Superseded Control | Superseded Framework | Satisfied By | Mechanism | Auto-Verified |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, s := range Registry() {
		applicable := false
		for _, e := range m.Supersessions {
			if e.SupersededControl == s.SupersededControl && e.SupersededFramework == s.SupersededFramework {
				applicable = true
				break
			}
		}
		status := "N/A (framework not active)"
		if applicable {
			status = "✓ Active"
		}
		auto := "No"
		if s.AutoSatisfied {
			auto = "Yes"
		}
		b.WriteString(fmt.Sprintf("| %s %s | %s | %s %s | %s | %s |\n",
			s.SupersededControl, s.SupersededTitle,
			s.SupersededFramework,
			s.SupersedingControl, s.SupersedingTitle,
			s.Mechanism, auto))
		_ = status
	}
	b.WriteString("\n")

	// Section 5: Conflict Resolution Record
	if len(m.Conflicts) > 0 {
		b.WriteString("## 5. Conflict Resolution Record\n\n")
		for _, c := range m.Conflicts {
			icon := "ℹ"
			switch c.Severity {
			case "blocking":
				icon = "🛑"
			case "warning":
				icon = "⚠"
			}
			b.WriteString(fmt.Sprintf("### %s %s (%s)\n\n", icon, c.Type, c.Severity))
			b.WriteString(fmt.Sprintf("**Frameworks:** %s\n\n", strings.Join(c.Frameworks, ", ")))
			b.WriteString(fmt.Sprintf("**Description:** %s\n\n", c.Description))
			b.WriteString(fmt.Sprintf("**Resolution:** %s\n\n", c.Resolution))
		}
	}

	// Section 6: Evidence Package Index
	b.WriteString("## 6. Evidence Package Index\n\n")
	b.WriteString("| Evidence Type | Source | Notes |\n")
	b.WriteString("|---|---|---|\n")
	b.WriteString("| Compiled SCPs | `.attest/compiled/scps/` | All active frameworks merged |\n")
	b.WriteString("| Cedar policies | `.attest/compiled/cedar/` | Per-framework, AND semantics |\n")
	b.WriteString("| Config rules | `.attest/compiled/config/` | Per-framework deduped |\n")
	b.WriteString("| Crosswalk manifest | `.attest/compiled/crosswalk.yaml` | Control → artifact mapping |\n")
	b.WriteString("| Posture history | `.attest/history/posture-*.yaml` | Timestamped scan results |\n")
	for _, fw := range m.Frameworks {
		b.WriteString(fmt.Sprintf("| %s artifact reports | AWS Artifact | See artifact_reports in framework YAML |\n", fw.Name))
	}
	b.WriteString("\n")

	b.WriteString("---\n\n")
	b.WriteString(fmt.Sprintf("*Generated by attest. This document reflects the compliance posture as of %s.*\n",
		m.GeneratedAt.Format("2006-01-02")))

	return b.String()
}

// --- helpers ------------------------------------------------------------------

func findApplicableSupersessions(frameworks []*schema.Framework) []SupersessionEntry {
	fwSet := make(map[string]bool, len(frameworks))
	for _, fw := range frameworks {
		fwSet[fw.ID] = true
	}
	var applicable []SupersessionEntry
	for _, s := range Registry() {
		if fwSet[s.SupersedingFramework] && fwSet[s.SupersededFramework] {
			applicable = append(applicable, s)
		}
	}
	return applicable
}

func buildMergedSections(
	frameworks []*schema.Framework,
	_ *schema.Crosswalk,
	supersessionMap map[string]map[string]SupersessionEntry,
	posture *schema.Posture,
) []MultiFrameworkSection {
	// Group controls by family across all frameworks.
	type familyKey = string
	byFamily := make(map[familyKey][]MultiFrameworkControlNarrative)
	familyOrder := make([]string, 0)
	seen := make(map[string]bool)

	for _, fw := range frameworks {
		for _, ctrl := range fw.Controls {
			if !seen[ctrl.Family] {
				seen[ctrl.Family] = true
				familyOrder = append(familyOrder, ctrl.Family)
			}

			status := "Planned"
			if posture != nil {
				if fp, ok := posture.Frameworks[fw.ID]; ok {
					if s, ok := fp.Controls[ctrl.ID]; ok {
						switch s {
						case "enforced", "aws_covered":
							status = "Implemented"
						case "partial":
							status = "Partially Implemented"
						case "gap":
							status = "Planned"
						}
					}
				}
			}

			n := MultiFrameworkControlNarrative{
				ControlID:   ctrl.ID,
				FrameworkID: fw.ID,
				Title:       ctrl.Title,
				Status:      status,
				AWSCoverage: ctrl.Responsibility.AWS,
				CustomerImpl: ctrl.Responsibility.Customer,
			}

			// Check for supersession.
			if fwMap, ok := supersessionMap[fw.ID]; ok {
				if entry, ok := fwMap[ctrl.ID]; ok {
					n.CrossSatisfiedBy = &entry
					n.Status = "Satisfied via supersession"
				}
			}

			// Extract enforcement artifact IDs.
			for _, spec := range ctrl.Structural {
				n.Enforcement.SCPs = append(n.Enforcement.SCPs, spec.ID)
			}
			for _, spec := range ctrl.Operational {
				n.Enforcement.CedarPolicies = append(n.Enforcement.CedarPolicies, spec.ID)
			}
			for _, rule := range ctrl.Monitoring {
				n.Enforcement.ConfigRules = append(n.Enforcement.ConfigRules, rule.ID)
			}

			byFamily[ctrl.Family] = append(byFamily[ctrl.Family], n)
		}
	}

	sort.Strings(familyOrder)
	sections := make([]MultiFrameworkSection, 0, len(familyOrder))
	for _, family := range familyOrder {
		sections = append(sections, MultiFrameworkSection{
			Family:   family,
			Controls: byFamily[family],
		})
	}
	return sections
}
