package framework

import (
	"fmt"
	"strings"

	"github.com/provabl/attest/pkg/schema"
)

// Conflict describes a detected contradiction, supersession, or gap between
// the requirements of two or more active compliance frameworks.
type Conflict struct {
	Type       string   // "contradiction", "supersession", "info"
	Severity   string   // "blocking", "warning", "info"
	Frameworks []string // which frameworks are involved
	ControlIDs []string // specific control IDs
	Description string
	Resolution  string
}

// DetectConflicts analyses the active frameworks in an SRE and returns any
// contradictions, supersessions, or notable interactions between their requirements.
//
// Contradiction: frameworks require mutually exclusive configurations.
// Supersession:  one framework's requirement is stricter than another's on the same topic.
// Info:          frameworks overlap in a way worth noting but doesn't block deployment.
func DetectConflicts(frameworks []*schema.Framework) []Conflict {
	if len(frameworks) < 2 {
		return nil // conflicts require at least two frameworks
	}

	ids := make([]string, len(frameworks))
	for i, f := range frameworks {
		ids[i] = f.ID
	}

	has := func(id string) bool {
		for _, fid := range ids {
			if fid == id {
				return true
			}
		}
		return false
	}

	var conflicts []Conflict

	// --- Region restriction conflicts ---

	// ITAR requires GovCloud (us-gov-*); NIST 800-171 R2 restricts to
	// commercial US regions. These are mutually exclusive in a single SCP.
	if has("itar") && (has("nist-800-171-r2") || has("nist-800-53-r5")) {
		conflicts = append(conflicts, Conflict{
			Type:       "contradiction",
			Severity:   "blocking",
			Frameworks: []string{"itar", fwOr("nist-800-171-r2", "nist-800-53-r5", ids)},
			ControlIDs: []string{"3.1.3", "AC-20"},
			Description: "ITAR requires AWS GovCloud (us-gov-east-1, us-gov-west-1) for export-controlled data. " +
				"NIST 800-171 §3.1.3 and 800-53 AC-20 region restriction SCPs reference commercial US regions. " +
				"A single org cannot satisfy both with the same SCP region allowlist.",
			Resolution: "Deploy ITAR workloads to a separate GovCloud SRE. " +
				"Use attest multi-SRE: `attest sre add` for the GovCloud org with itar framework only. " +
				"Keep NIST/HIPAA in the commercial org.",
		})
	}

	// UK Cyber Essentials allows EU regions (eu-west-1, eu-west-2) that
	// NIST 800-171 CUI restrictions prohibit.
	if has("uk-cyber-essentials") && has("nist-800-171-r2") {
		conflicts = append(conflicts, Conflict{
			Type:       "supersession",
			Severity:   "warning",
			Frameworks: []string{"nist-800-171-r2", "uk-cyber-essentials"},
			ControlIDs: []string{"3.1.3", "FW-1"},
			Description: "NIST 800-171 §3.1.3 restricts CUI to US regions only. " +
				"UK Cyber Essentials FW-1 permits EU regions (eu-west-1, eu-west-2) for UK-based research. " +
				"If CUI and UK CE apply to the same AWS accounts, NIST is stricter — UK CE region permission is superseded.",
			Resolution: "Apply US-only region restriction SCP (NIST wins). " +
				"UK CE is satisfied by the NIST SCP since it is a superset restriction. " +
				"Document this supersession in your SSP.",
		})
	}

	// --- Authentication standard interactions ---

	// HIPAA emergency access may require bypassing MFA in emergency scenarios,
	// conflicting with NIST 800-171 mandatory MFA for all access.
	if has("hipaa") && (has("nist-800-171-r2") || has("nist-800-53-r5")) {
		conflicts = append(conflicts, Conflict{
			Type:       "info",
			Severity:   "info",
			Frameworks: []string{"hipaa", fwOr("nist-800-171-r2", "nist-800-53-r5", ids)},
			ControlIDs: []string{"164.312(a)(2)(ii)", "3.5.3", "IA-2"},
			Description: "HIPAA §164.312(a)(2)(ii) requires an Emergency Access Procedure that may allow " +
				"bypassing normal authentication controls in emergency situations. " +
				"NIST 800-171 §3.5.3 and 800-53 IA-2 require MFA for all access without exception. " +
				"These are compatible but require explicit documentation of the emergency procedure.",
			Resolution: "Document the Emergency Access Procedure in your SSP. " +
				"The MFA SCP applies in all normal operations. " +
				"Emergency access (if ever invoked) must be logged, reviewed, and reported per the IR plan. " +
				"Implement a break-glass account process separate from the SCP-controlled path.",
		})
	}

	// --- Encryption standard interactions ---

	// NIST 800-171 requires FIPS-validated KMS; FERPA only requires encryption (not FIPS).
	// NIST is stricter — FERPA is automatically satisfied if NIST is enforced.
	if has("nist-800-171-r2") && has("ferpa") {
		conflicts = append(conflicts, Conflict{
			Type:       "supersession",
			Severity:   "info",
			Frameworks: []string{"nist-800-171-r2", "ferpa"},
			ControlIDs: []string{"3.13.11", "ferpa-data-encryption"},
			Description: "FERPA requires encryption of student records but does not mandate FIPS 140-2 validation. " +
				"NIST 800-171 §3.13.11 requires FIPS-validated KMS CMKs. " +
				"NIST is stricter — satisfying NIST automatically satisfies FERPA's encryption requirement.",
			Resolution: "No action needed. NIST 800-171 KMS enforcement satisfies FERPA encryption. " +
				"Note this supersession in the multi-framework SSP section.",
		})
	}

	// --- Framework comprehensiveness gaps ---

	// ASD Essential Eight ML1 does not include network boundary controls;
	// if it's the only framework, important controls are missing.
	if has("asd-essential-eight") && !has("nist-800-171-r2") && !has("nist-800-53-r5") && !has("fedramp-moderate") {
		conflicts = append(conflicts, Conflict{
			Type:       "info",
			Severity:   "warning",
			Frameworks: []string{"asd-essential-eight"},
			ControlIDs: []string{"E8-4"},
			Description: "ASD Essential Eight alone does not cover network boundary protection " +
				"(VPC isolation, region restrictions) or encryption at rest. " +
				"It is designed as a minimum baseline for endpoints, not a complete cloud security framework.",
			Resolution: "Pair ASD Essential Eight with NIST 800-53 R5 or NIST 800-171 R2 for complete " +
				"cloud coverage. ASD CE controls will be deduplicated (zero additional SCP cost).",
		})
	}

	// FedRAMP High without FedRAMP Moderate: fedramp-high is a delta framework
	// that only covers controls beyond Moderate; activating High alone leaves a
	// significant coverage gap across AC, AU, CM, IA, SC, and SI families.
	if has("fedramp-high") && !has("fedramp-moderate") {
		conflicts = append(conflicts, Conflict{
			Type:       "info",
			Severity:   "warning",
			Frameworks: []string{"fedramp-high"},
			ControlIDs: []string{"AC-2", "AU-2", "IA-2", "SC-8", "SI-2"},
			Description: "fedramp-high is a delta framework containing only the controls that are " +
				"specific to the FedRAMP High baseline beyond Moderate. It must be activated alongside " +
				"fedramp-moderate to achieve complete FedRAMP High coverage. " +
				"Activating fedramp-high alone leaves ~23 Moderate baseline controls unenforced.",
			Resolution: "Activate both fedramp-moderate and fedramp-high together: " +
				"`attest frameworks activate fedramp-moderate fedramp-high`. " +
				"The merged SCP compiler deduplicates all conditions — activating both costs minimal SCP budget.",
		})
	}

	// FedRAMP + ITAR: FedRAMP High workloads handling ITAR-controlled data typically
	// require AWS GovCloud, which creates the same region-restriction conflict as ITAR alone.
	if (has("fedramp-high") || has("fedramp-moderate")) && has("itar") {
		conflicts = append(conflicts, Conflict{
			Type:       "info",
			Severity:   "info",
			Frameworks: []string{fwOr("fedramp-high", "fedramp-moderate", ids), "itar"},
			ControlIDs: []string{"AC-20", "SC-7"},
			Description: "FedRAMP High workloads processing ITAR-controlled technical data often require " +
				"AWS GovCloud (us-gov-east-1, us-gov-west-1) for export compliance, while FedRAMP " +
				"commercial region restrictions reference us-east-*/us-west-* only. " +
				"See ITAR + NIST conflict above for full guidance.",
			Resolution: "Deploy ITAR workloads to a GovCloud SRE (itar framework only). " +
				"Keep FedRAMP-scoped workloads in the commercial SRE. " +
				"Use attest multi-SRE to manage both organizations.",
		})
	}

	// UK Cyber Essentials + ISO 27001: highly complementary, note the overlap.
	if has("uk-cyber-essentials") && has("iso27001-2022") {
		conflicts = append(conflicts, Conflict{
			Type:       "info",
			Severity:   "info",
			Frameworks: []string{"uk-cyber-essentials", "iso27001-2022"},
			ControlIDs: []string{"AC-1", "A.5.15"},
			Description: "UK Cyber Essentials is largely a subset of ISO 27001 Annex A technical controls. " +
				"Active together, UK CE requirements are fully covered by ISO 27001 enforcement — " +
				"the merged SCP budget cost is near-zero for UK CE additions.",
			Resolution: "No action needed. UK CE + ISO 27001 is a common UK research compliance combination. " +
				"The merged compiler will deduplicate all shared SCP conditions.",
		})
	}

	return conflicts
}

// FormatConflicts returns a human-readable summary of detected conflicts for CLI output.
func FormatConflicts(conflicts []Conflict) string {
	if len(conflicts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nFramework conflict analysis:\n")
	for _, c := range conflicts {
		icon := "ℹ"
		switch c.Severity {
		case "blocking":
			icon = "✗"
		case "warning":
			icon = "⚠"
		}
		b.WriteString(fmt.Sprintf("  %s [%s] %s vs %s\n",
			icon, c.Type, strings.Join(c.Frameworks, " + "), strings.Join(c.ControlIDs, ", ")))
		b.WriteString(fmt.Sprintf("     %s\n", c.Description))
		b.WriteString(fmt.Sprintf("     Resolution: %s\n\n", c.Resolution))
	}
	return b.String()
}

// HasBlockingConflicts returns true if any conflict would prevent safe SCP deployment.
func HasBlockingConflicts(conflicts []Conflict) bool {
	for _, c := range conflicts {
		if c.Severity == "blocking" {
			return true
		}
	}
	return false
}

// fwOr returns the first of two framework IDs that appears in the active list.
func fwOr(a, b string, active []string) string {
	for _, id := range active {
		if id == a || id == b {
			return id
		}
	}
	return a
}
