// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package regulatory

// RelevanceResult is the AI-generated analysis of a regulatory notice.
type RelevanceResult struct {
	// IsRelevant indicates whether this notice impacts any attest framework.
	IsRelevant bool `yaml:"is_relevant" json:"is_relevant"`
	// AffectedFrameworks lists framework IDs impacted by this notice.
	AffectedFrameworks []string `yaml:"affected_frameworks,omitempty" json:"affected_frameworks,omitempty"`
	// Impact categorises the type of change required.
	// Values: "new-control" | "control-update" | "new-framework" | "conflict-update" | "info-only"
	Impact string `yaml:"impact,omitempty" json:"impact,omitempty"`
	// ActionRequired describes what must change in attest.
	ActionRequired string `yaml:"action_required,omitempty" json:"action_required,omitempty"`
	// IssueTitle is a concise GitHub issue title (< 72 chars).
	IssueTitle string `yaml:"issue_title,omitempty" json:"issue_title,omitempty"`
	// IssueBody is the full GitHub issue body in markdown.
	IssueBody string `yaml:"issue_body,omitempty" json:"issue_body,omitempty"`
	// Labels are GitHub labels to apply to the created issue.
	Labels []string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// Analyzer provides AI-powered relevance analysis for regulatory notices.
// The actual Bedrock calls are in internal/ai/analyst.go (AnalyzeRegulatoryNotice).
// This file contains only the data types used by both packages.
//
// Usage:
//   analyst := ai.NewAnalyst(cfg)
//   result, err := analyst.AnalyzeRegulatoryNotice(ctx, notice)
