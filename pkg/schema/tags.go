// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package schema

// attest:* IAM role tag key constants — authoritative schema for the attest side.
//
// qualify (github.com/provabl/qualify) writes these tags to researchers' IAM roles
// on training completion. attest reads them via the principal resolver to populate
// Cedar evaluation attributes.
//
// Schema version: 1
//
// IMPORTANT: Both qualify (internal/training/tags.go) and attest (this file) must
// agree on these key strings. If any key changes, update BOTH repos in the same
// release and increment the schema version comment.
// See: https://github.com/provabl/qualify/issues/32
const (
	// Training completion tags — written by qualify on module pass.
	TagCUITraining              = "attest:cui-training"
	TagCUITrainingExpiry        = "attest:cui-training-expiry"
	TagHIPAATraining            = "attest:hipaa-training"
	TagHIPAATrainingExpiry      = "attest:hipaa-training-expiry"
	TagAwarenessTraining        = "attest:awareness-training"
	TagAwarenessTrainingExpiry  = "attest:awareness-training-expiry"
	TagFERPATraining            = "attest:ferpa-training"
	TagFERPATrainingExpiry      = "attest:ferpa-training-expiry"
	TagITARTraining             = "attest:itar-training"
	TagITARTrainingExpiry       = "attest:itar-training-expiry"
	TagDataClassTraining        = "attest:data-class-training"
	TagDataClassTrainingExpiry  = "attest:data-class-training-expiry"
	TagResearchSecurityTraining = "attest:research-security-training"
	TagResearchSecurityExpiry   = "attest:research-security-training-expiry"
	TagCOCCheckCurrent          = "attest:coc-check-current"
	TagCOCCheckExpiry           = "attest:coc-check-expiry"

	// Countries-of-concern check tags — written by qualify lab record-check.
	TagCountry = "attest:country" // ISO 3166-1 alpha-2 institutional affiliation

	// NIH DUA / Approved User tags — written by NIH DUA management workflow.
	TagNIHApproval       = "attest:nih-approval"
	TagNIHApprovalExpiry = "attest:nih-approval-expiry"
	TagNIHDUAID          = "attest:nih-dua-id"

	// Identity and lab tags — written by qualify lab setup.
	TagLabID      = "attest:lab-id"
	TagAdminLevel = "attest:admin-level" // "none" | "env" | "sre"

	// Legacy tag key written by older qualify versions — supported for backward compat.
	TagCUIExpiryLegacy = "attest:cui-expiry"
)
