// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package obligations provides deterministic compliance obligation mapping.
// Given a research project record and optional posture state, it derives the
// complete set of compliance obligations the project creates — deterministically,
// without AI. The AI navigator in internal/ai reads these obligations and
// provides explanation, prioritisation, and recommended actions on top.
package obligations

import (
	"fmt"
	"strings"
	"time"

	"github.com/provabl/attest/pkg/schema"
)

// Obligation is a single compliance obligation derived from project context.
type Obligation struct {
	// ID is a stable identifier for this obligation type (e.g. "cmmc-level-2").
	ID string
	// Framework is the compliance framework this obligation belongs to.
	Framework string
	// ControlFamily is the control family or domain (e.g. "AC", "SA").
	ControlFamily string
	// Title is a short human-readable description.
	Title string
	// Detail explains what must be done and why it was triggered.
	Detail string
	// Trigger describes what about the project triggered this obligation.
	Trigger string
	// Severity is "critical", "required", or "recommended".
	Severity string
	// DueDate is a deadline if applicable (e.g. annual renewals, 12-month training windows).
	DueDate *time.Time
	// Status is "unknown" until cross-referenced with posture; then "met", "partial", or "unmet".
	Status string
}

// Engine maps research project context to compliance obligations.
type Engine struct{}

// New creates an obligation mapping engine.
func New() *Engine { return &Engine{} }

// Map returns all obligations triggered by the given project.
// posture may be nil; if provided, obligations are cross-referenced to set Status.
func (e *Engine) Map(p schema.ResearchProject, posture *schema.Posture) []Obligation {
	var obs []Obligation
	obs = append(obs, mapFundingObligations(p)...)
	obs = append(obs, mapDataTypeObligations(p)...)
	obs = append(obs, mapCollaboratorObligations(p)...)
	obs = append(obs, mapIRBObligations(p)...)
	obs = append(obs, mapDBGaPObligations(p)...)

	if posture != nil {
		obs = crossReference(obs, posture)
	} else {
		for i := range obs {
			obs[i].Status = "unknown"
		}
	}
	return obs
}

// Titles returns a deduplicated list of obligation titles for quick display.
func (e *Engine) Titles(p schema.ResearchProject) []string {
	obs := e.Map(p, nil)
	seen := make(map[string]bool, len(obs))
	var out []string
	for _, o := range obs {
		if !seen[o.ID] {
			seen[o.ID] = true
			out = append(out, o.Title)
		}
	}
	return out
}

// --- funding obligations -------------------------------------------------------

func mapFundingObligations(p schema.ResearchProject) []Obligation {
	var obs []Obligation
	for _, g := range p.Funding {
		src := strings.ToUpper(g.Source)
		switch {
		case strings.Contains(src, "DOD") || strings.Contains(src, "DARPA") ||
			strings.Contains(src, "ONR") || strings.Contains(src, "AFOSR") ||
			strings.Contains(src, "ARO") || strings.Contains(src, "ARMY") ||
			strings.Contains(src, "NAVY") || strings.Contains(src, "AIR FORCE"):
			obs = append(obs, dodObligations(p, g)...)

		case strings.Contains(src, "NIH") || strings.Contains(src, "NATIONAL INSTITUTES"):
			obs = append(obs, nihObligations(p, g)...)

		case strings.Contains(src, "NSF"):
			obs = append(obs, nsfObligations(p, g)...)

		case strings.Contains(src, "FEDRAMP") || strings.Contains(src, "FED"):
			obs = append(obs, Obligation{
				ID: "fedramp-moderate", Framework: "fedramp-moderate",
				Title:    "FedRAMP Moderate ATO required",
				Detail:   "Federal funding requires FedRAMP authorization for cloud services.",
				Trigger:  fmt.Sprintf("Federal funding source: %s", g.Source),
				Severity: "required",
			})
		}
	}
	return obs
}

func dodObligations(p schema.ResearchProject, g schema.GrantRef) []Obligation {
	obs := []Obligation{
		{
			ID: "cmmc-level-2", Framework: "cmmc-level-2",
			Title:   "CMMC Level 2 — 110 practices (NIST SP 800-171 Rev 2)",
			Detail:  "DoD contracts require CMMC Level 2 certification. Activate nist-800-171-r2, compile, and apply. Submit SPRS score to PIEE.",
			Trigger: fmt.Sprintf("DoD funding: %s %s", g.Source, g.Award),
			Severity: "critical",
		},
		{
			ID: "sprs-reporting", Framework: "cmmc-level-2",
			Title:   "SPRS score submission required",
			Detail:  "Self-assessed SPRS score must be submitted to PIEE (piee.eb.mil) before contract award and updated annually. Run: attest generate sprs --level 2",
			Trigger: fmt.Sprintf("DoD contract: %s", g.Award),
			Severity: "required",
		},
	}

	// DoD + CUI = CMMC Level 2 is mandatory (not optional for non-critical programs)
	if hasCUI(p) {
		obs = append(obs, Obligation{
			ID: "cmmc-level-2-cui", Framework: "cmmc-level-2",
			Title:    "CMMC Level 2 mandatory (CUI + DoD funding)",
			Detail:   "CUI data combined with DoD funding makes CMMC Level 2 mandatory, not self-assessment eligible. C3PAO assessment required.",
			Trigger:  "DoD funding + CUI data type",
			Severity: "critical",
		})
	}

	// DoD contract type may require CMMC Level 3
	if strings.ToUpper(g.Type) == "CONTRACT" && hasCUI(p) {
		obs = append(obs, Obligation{
			ID: "cmmc-level-3-review", Framework: "cmmc-level-3",
			Title:    "CMMC Level 3 eligibility review",
			Detail:   "DoD contracts for CUI involving critical programs may require CMMC Level 3 (NIST 800-172 delta). Confirm with contracting officer.",
			Trigger:  "DoD contract type with CUI",
			Severity: "recommended",
		})
	}
	return obs
}

func nihObligations(p schema.ResearchProject, g schema.GrantRef) []Obligation {
	obs := []Obligation{
		{
			ID: "nih-dmsp", Framework: "nih-research-security",
			Title:   "NIH Data Management and Sharing Plan (DMSP) required",
			Detail:  "All NIH-funded research requires a DMSP under the 2023 NIH Data Management and Sharing Policy. Run: attest generate dmsp",
			Trigger: fmt.Sprintf("NIH funding: %s", g.Award),
			Severity: "required",
		},
		{
			ID: "nih-research-security-training", Framework: "nih-research-security",
			Title:   "NIH research security training (NOT-OD-26-017)",
			Detail:  "All key personnel on NIH awards must complete research security training within 12 months and annually thereafter. qualify module: nih-research-security",
			Trigger: fmt.Sprintf("NIH funding: %s", g.Award),
			Severity: "required",
		},
	}

	// NIH + genomic/sequencing data → dbGaP and GDS Policy
	if hasGenomicData(p) {
		obs = append(obs, Obligation{
			ID: "nih-gds-policy", Framework: "nih-research-security",
			Title:    "NIH Genomic Data Sharing (GDS) Policy",
			Detail:   "NIH-funded research generating large-scale genomic data must comply with the GDS Policy: submit to dbGaP, obtain DUC, follow Institutional Certification requirements.",
			Trigger:  "NIH funding + genomic/sequencing data type",
			Severity: "critical",
		})
		obs = append(obs, Obligation{
			ID: "dbgap-duc", Framework: "nih-research-security",
			Title:    "dbGaP Data Use Certification (DUC) required",
			Detail:   "Accessing controlled-access dbGaP datasets requires an active DUC. Annual renewal required. Run: attest attest pi-sign",
			Trigger:  "NIH funding + genomic data",
			Severity: "required",
		})
	}
	return obs
}

func nsfObligations(p schema.ResearchProject, g schema.GrantRef) []Obligation {
	return []Obligation{
		{
			ID: "nsf-dmp", Framework: "nih-research-security",
			Title:   "NSF Data Management Plan required",
			Detail:  "NSF grants require a Data Management Plan addressing data formats, retention, access, and sharing.",
			Trigger: fmt.Sprintf("NSF funding: %s", g.Award),
			Severity: "required",
		},
	}
}

// --- data type obligations -----------------------------------------------------

func mapDataTypeObligations(p schema.ResearchProject) []Obligation {
	var obs []Obligation
	for _, dt := range p.DataTypes {
		upper := strings.ToUpper(dt)
		switch {
		case upper == "PHI" || strings.Contains(upper, "HEALTH") || strings.Contains(upper, "MEDICAL"):
			obs = append(obs, Obligation{
				ID: "hipaa-baa", Framework: "hipaa",
				Title:    "HIPAA Business Associate Agreement required",
				Detail:   "PHI in AWS requires a BAA with AWS. Verify BAA is active in AWS Artifact. Activate the hipaa framework: attest frameworks add hipaa",
				Trigger:  fmt.Sprintf("Data type: %s", dt),
				Severity: "critical",
			})
		case upper == "SUD" || strings.Contains(upper, "SUBSTANCE") || strings.Contains(upper, "ADDICTION"):
			obs = append(obs, Obligation{
				ID: "42-cfr-part-2", Framework: "42-cfr-part-2",
				Title:    "42 CFR Part 2 (substance use disorder records)",
				Detail:   "SUD patient records have stricter protections than HIPAA. Consent required for most disclosures; re-disclosure restrictions apply to all recipients.",
				Trigger:  fmt.Sprintf("Data type: %s", dt),
				Severity: "critical",
			})
		case strings.Contains(upper, "STUDENT") || upper == "FERPA":
			obs = append(obs, Obligation{
				ID: "ferpa", Framework: "ferpa",
				Title:    "FERPA compliance required",
				Detail:   "Student education records require FERPA protections. Activate the ferpa framework and ensure researcher FERPA training is current.",
				Trigger:  fmt.Sprintf("Data type: %s", dt),
				Severity: "required",
			})
		case strings.Contains(upper, "GENOMIC") || strings.Contains(upper, "SEQUENCING") ||
			strings.Contains(upper, "GENETIC") || strings.Contains(upper, "WGS"):
			obs = append(obs, Obligation{
				ID: "genomic-privacy", Framework: "hipaa",
				Title:    "Genomic data privacy obligations",
				Detail:   "Genomic data may be re-identifiable. Treat as PHI-equivalent. If subject to NIH GDS Policy, dbGaP submission and DUC required.",
				Trigger:  fmt.Sprintf("Data type: %s", dt),
				Severity: "required",
			})
		}
	}
	return obs
}

// --- collaborator obligations --------------------------------------------------

// itatrControlledCountries are countries that trigger ITAR/EAR deemed-export review
// when combined with DoD funding or controlled technical data.
var itarControlledCountries = map[string]bool{
	"CN": true, "RU": true, "IR": true, "KP": true, "CU": true,
	"SY": true, "SD": true, "MM": true, "BY": true,
}

func mapCollaboratorObligations(p schema.ResearchProject) []Obligation {
	var obs []Obligation
	hasDoD := hasDoDFunding(p)

	for _, c := range p.Collaborators {
		country := strings.ToUpper(c.Country)

		// EU collaborators → GDPR
		if isEUCountry(country) {
			obs = append(obs, Obligation{
				ID: "gdpr-sccs", Framework: "gdpr",
				Title:    "GDPR Standard Contractual Clauses required",
				Detail:   "EU collaborator means personal data may flow from the EU. SCCs (or equivalent safeguard) required for transatlantic data transfers. Consult privacy officer.",
				Trigger:  fmt.Sprintf("EU collaborator: %s (%s)", c.Name, c.Country),
				Severity: "required",
			})
		}

		// ITAR-controlled country + DoD = Technology Control Plan
		if itarControlledCountries[country] && hasDoD {
			obs = append(obs, Obligation{
				ID: "itar-tcp", Framework: "itar",
				Title:    fmt.Sprintf("ITAR Technology Control Plan required — collaborator from %s", c.Country),
				Detail:   fmt.Sprintf("DoD-funded research with a collaborator from %s (%s) requires an ITAR Technology Control Plan. Consult your Export Control office before sharing any technical data.", c.Country, c.Name),
				Trigger:  fmt.Sprintf("DoD funding + collaborator country: %s", c.Country),
				Severity: "critical",
			})
			obs = append(obs, Obligation{
				ID: "deemed-export-review", Framework: "itar",
				Title:    fmt.Sprintf("Deemed export review required — %s", c.Name),
				Detail:   "Sharing controlled technical data with a foreign national in the US constitutes a deemed export. Export license determination required before data access.",
				Trigger:  fmt.Sprintf("Foreign national collaborator: %s (%s) + DoD funding", c.Name, c.Country),
				Severity: "critical",
			})
		}
	}
	return obs
}

// --- IRB obligations -----------------------------------------------------------

func mapIRBObligations(p schema.ResearchProject) []Obligation {
	if p.IRBProtocol == "" {
		return nil
	}
	return []Obligation{
		{
			ID: "irb-continuing-review", Framework: "hipaa",
			Title:   "IRB continuing review required (annual)",
			Detail:  "Active IRB protocol requires annual continuing review. Failure to renew suspends research activities. Track in attest calendar.",
			Trigger: fmt.Sprintf("IRB protocol: %s", p.IRBProtocol),
			Severity: "required",
		},
		{
			ID: "45-cfr-46", Framework: "hipaa",
			Title:   "45 CFR Part 46 (Common Rule) applies",
			Detail:  "Human subjects research requires ongoing IRB oversight, informed consent documentation, and adverse event reporting.",
			Trigger: fmt.Sprintf("IRB protocol: %s", p.IRBProtocol),
			Severity: "required",
		},
	}
}

// --- dbGaP obligations --------------------------------------------------------

func mapDBGaPObligations(p schema.ResearchProject) []Obligation {
	if len(p.DBGaPAccessions) == 0 {
		return nil
	}
	annual := time.Now().AddDate(1, 0, 0)
	return []Obligation{
		{
			ID: "dbgap-annual-renewal", Framework: "nih-research-security",
			Title:   "dbGaP annual DUC renewal",
			Detail:  fmt.Sprintf("dbGaP accessions %s require annual DUC renewal. Run: attest attest pi-sign", strings.Join(p.DBGaPAccessions, ", ")),
			Trigger: fmt.Sprintf("dbGaP accessions: %s", strings.Join(p.DBGaPAccessions, ", ")),
			Severity: "required",
			DueDate: &annual,
		},
	}
}

// --- helpers ------------------------------------------------------------------

func hasCUI(p schema.ResearchProject) bool {
	for _, dt := range p.DataTypes {
		if strings.ToUpper(dt) == "CUI" || strings.Contains(strings.ToUpper(dt), "CONTROLLED UNCLASSIFIED") {
			return true
		}
	}
	return false
}

func hasGenomicData(p schema.ResearchProject) bool {
	for _, dt := range p.DataTypes {
		u := strings.ToUpper(dt)
		if strings.Contains(u, "GENOMIC") || strings.Contains(u, "SEQUENCING") ||
			strings.Contains(u, "GENETIC") || strings.Contains(u, "WGS") || strings.Contains(u, "WES") {
			return true
		}
	}
	return false
}

func hasDoDFunding(p schema.ResearchProject) bool {
	for _, g := range p.Funding {
		src := strings.ToUpper(g.Source)
		if strings.Contains(src, "DOD") || strings.Contains(src, "DARPA") ||
			strings.Contains(src, "ONR") || strings.Contains(src, "AFOSR") ||
			strings.Contains(src, "ARO") || strings.Contains(src, "ARMY") ||
			strings.Contains(src, "NAVY") || strings.Contains(src, "AIR FORCE") {
			return true
		}
	}
	return false
}

var euCountries = map[string]bool{
	"AT": true, "BE": true, "BG": true, "CY": true, "CZ": true, "DE": true,
	"DK": true, "EE": true, "ES": true, "FI": true, "FR": true, "GR": true,
	"HR": true, "HU": true, "IE": true, "IT": true, "LT": true, "LU": true,
	"LV": true, "MT": true, "NL": true, "PL": true, "PT": true, "RO": true,
	"SE": true, "SI": true, "SK": true, "NO": true, "IS": true, "LI": true, // EEA
}

func isEUCountry(iso2 string) bool {
	return euCountries[strings.ToUpper(iso2)]
}

func crossReference(obs []Obligation, posture *schema.Posture) []Obligation {
	for i := range obs {
		fw, ok := posture.Frameworks[obs[i].Framework]
		if !ok {
			obs[i].Status = "unmet"
			continue
		}
		// Count statuses from the controls map.
		var enforced, gaps int
		for _, status := range fw.Controls {
			switch status {
			case "enforced", "aws_covered":
				enforced++
			case "gap":
				gaps++
			}
		}
		if gaps == 0 && enforced > 0 {
			obs[i].Status = "met"
		} else if enforced > 0 {
			obs[i].Status = "partial"
		} else {
			obs[i].Status = "unmet"
		}
	}
	return obs
}
