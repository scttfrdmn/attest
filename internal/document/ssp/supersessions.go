// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package ssp

// SupersessionEntry records a static cross-framework control supersession:
// the superseding control's stricter enforcement satisfies the superseded
// control's requirement — no additional evidence needed for the superseded control.
type SupersessionEntry struct {
	// SupersedingFramework is the framework with the stricter requirement.
	SupersedingFramework string
	// SupersedingControl is the control ID in the superseding framework.
	SupersedingControl string
	// SupersedingTitle is a short description of the superseding control.
	SupersedingTitle string
	// SupersededFramework is the framework whose requirement is satisfied.
	SupersededFramework string
	// SupersededControl is the control ID being satisfied.
	SupersededControl string
	// SupersededTitle is a short description of the superseded control.
	SupersededTitle string
	// AutoSatisfied is true when attest can mechanically verify satisfaction
	// (via a deployed SCP or Cedar policy artifact).
	AutoSatisfied bool
	// Mechanism is the SCP/Cedar artifact that provides the enforcement
	// (e.g. "scp-require-kms-encryption", "scp-require-mfa").
	Mechanism string
}

// Registry returns the static 14-entry supersession registry covering the most
// common R1 research computing framework combinations.
//
// Design principle: a supersession is only recorded when the superseding control
// is strictly stronger than the superseded one — not merely overlapping. The
// stricter requirement's enforcement artifact satisfies both, so the less-strict
// control needs no additional evidence.
func Registry() []SupersessionEntry {
	return []SupersessionEntry{
		// ── NIST 800-171 → HIPAA Technical Safeguards ─────────────────────────────

		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.13.11",
			SupersedingTitle:     "FIPS-validated cryptography for CUI",
			SupersededFramework:  "hipaa",
			SupersededControl:    "164.312(a)(2)(iv)",
			SupersededTitle:      "Encryption and decryption (addressable)",
			AutoSatisfied:        true,
			Mechanism:            "scp-require-kms-encryption",
		},
		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.5.3",
			SupersedingTitle:     "Phishing-resistant MFA for privileged access",
			SupersededFramework:  "hipaa",
			SupersededControl:    "164.312(d)",
			SupersededTitle:      "Entity authentication",
			AutoSatisfied:        true,
			Mechanism:            "scp-require-mfa",
		},
		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.3.1",
			SupersedingTitle:     "Audit and accountability — log generation",
			SupersededFramework:  "hipaa",
			SupersededControl:    "164.312(b)",
			SupersededTitle:      "Audit controls",
			AutoSatisfied:        true,
			Mechanism:            "scp-protect-cloudtrail",
		},
		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.3.1",
			SupersedingTitle:     "Audit and accountability — log review",
			SupersededFramework:  "hipaa",
			SupersededControl:    "164.308(a)(1)(ii)(D)",
			SupersededTitle:      "Information system activity review",
			AutoSatisfied:        true,
			Mechanism:            "config-cloudtrail-enabled",
		},
		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.1.1",
			SupersedingTitle:     "Limit system access to authorized users",
			SupersededFramework:  "hipaa",
			SupersededControl:    "164.308(a)(4)",
			SupersededTitle:      "Information access management",
			AutoSatisfied:        true,
			Mechanism:            "scp-deny-admin-star",
		},
		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.13.8",
			SupersedingTitle:     "Encryption of CUI in transit (TLS)",
			SupersededFramework:  "hipaa",
			SupersededControl:    "164.312(e)(1)",
			SupersededTitle:      "Transmission security (addressable)",
			AutoSatisfied:        true,
			Mechanism:            "scp-require-https",
		},
		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.6.1",
			SupersedingTitle:     "Incident response capability",
			SupersededFramework:  "hipaa",
			SupersededControl:    "164.308(a)(6)",
			SupersededTitle:      "Security incident procedures",
			AutoSatisfied:        false,
			Mechanism:            "",
		},
		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.4.2",
			SupersedingTitle:     "Security configuration baselines",
			SupersededFramework:  "hipaa",
			SupersededControl:    "164.308(a)(1)(ii)(B)",
			SupersededTitle:      "Risk management",
			AutoSatisfied:        false,
			Mechanism:            "",
		},
		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.5.3",
			SupersedingTitle:     "Multi-factor authentication",
			SupersededFramework:  "hipaa",
			SupersededControl:    "164.308(a)(3)(ii)(B)",
			SupersededTitle:      "Workforce clearance procedure",
			AutoSatisfied:        true,
			Mechanism:            "scp-require-mfa",
		},

		// ── NIST 800-171 → FERPA ──────────────────────────────────────────────────

		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.13.11",
			SupersedingTitle:     "FIPS-validated cryptography",
			SupersededFramework:  "ferpa",
			SupersededControl:    "ferpa-encryption",
			SupersededTitle:      "Encryption of student records (implied)",
			AutoSatisfied:        true,
			Mechanism:            "scp-require-kms-encryption",
		},
		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.3.1",
			SupersedingTitle:     "Audit logging",
			SupersededFramework:  "ferpa",
			SupersededControl:    "ferpa-access-logging",
			SupersededTitle:      "Access logging for education records (implied)",
			AutoSatisfied:        true,
			Mechanism:            "scp-protect-cloudtrail",
		},

		// ── FedRAMP → NIST 800-53 ─────────────────────────────────────────────────

		{
			SupersedingFramework: "fedramp-moderate",
			SupersedingControl:   "fedramp-moderate-csp-baseline",
			SupersedingTitle:     "FedRAMP Moderate CSP infrastructure authorization",
			SupersededFramework:  "nist-800-53-r5",
			SupersededControl:    "nist-800-53-r5-moderate-baseline",
			SupersededTitle:      "NIST 800-53 Moderate baseline (CSP layer only)",
			AutoSatisfied:        true,
			Mechanism:            "artifact_report:FedRAMP",
		},

		// ── CMMC / 800-171 → FedRAMP ──────────────────────────────────────────────

		{
			SupersedingFramework: "cmmc-level-2",
			SupersedingControl:   "cmmc-l2-ref",
			SupersedingTitle:     "CMMC Level 2 (= NIST 800-171) full enforcement",
			SupersededFramework:  "fedramp-moderate",
			SupersededControl:    "fedramp-moderate-tenant",
			SupersededTitle:      "FedRAMP Moderate tenant security controls",
			AutoSatisfied:        false,
			Mechanism:            "",
		},

		// ── NIST 800-171 → NIH GDS ────────────────────────────────────────────────

		{
			SupersedingFramework: "nist-800-171-r2",
			SupersedingControl:   "3.13.11",
			SupersedingTitle:     "FIPS KMS encryption + phishing-resistant MFA",
			SupersededFramework:  "nih-gds",
			SupersededControl:    "nih-gds-1.1",
			SupersededTitle:      "Infrastructure security for NIH approved user access",
			AutoSatisfied:        true,
			Mechanism:            "scp-require-kms-encryption + scp-require-mfa",
		},
	}
}

// SupersessionMap returns the registry indexed by (supersededFramework, supersededControl)
// for O(1) lookup during posture computation.
func SupersessionMap() map[string]map[string]SupersessionEntry {
	m := make(map[string]map[string]SupersessionEntry)
	for _, s := range Registry() {
		if m[s.SupersededFramework] == nil {
			m[s.SupersededFramework] = make(map[string]SupersessionEntry)
		}
		m[s.SupersededFramework][s.SupersededControl] = s
	}
	return m
}
