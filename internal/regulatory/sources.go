// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package regulatory provides automated monitoring of regulatory sources
// (NIH Guide, NIST CSRC, Federal Register, FedRAMP) and AI-powered relevance
// analysis to surface compliance-impacting notices before they become gaps.
package regulatory

// FeedType identifies how to fetch a source's content.
type FeedType string

const (
	FeedTypeRSS                FeedType = "rss"
	FeedTypeAtom               FeedType = "atom"
	FeedTypeFederalRegisterAPI FeedType = "federal-register-api"
	FeedTypeGitHubReleases     FeedType = "github-releases"
)

// Source is a regulatory intelligence source to monitor.
type Source struct {
	// ID is a stable machine-readable identifier.
	ID string
	// Name is the human-readable source name.
	Name string
	// FeedURL is the RSS/Atom/API endpoint URL.
	FeedURL string
	// FeedType controls how the feed is parsed.
	FeedType FeedType
	// Label is the GitHub label applied to issues created from this source.
	// Format: "regulatory:<domain>" e.g. "regulatory:nih"
	Label string
	// Keywords filters feed items to those containing at least one keyword.
	// Empty means all items are fetched.
	Keywords []string
}

// DefaultSources returns the built-in set of regulatory sources.
// These cover the primary federal regulatory bodies relevant to US research computing.
func DefaultSources() []Source {
	return []Source{
		{
			ID:       "nih-guide",
			Name:     "NIH Guide for Grants & Contracts",
			FeedURL:  "https://grants.nih.gov/grants/guide/rss/",
			FeedType: FeedTypeRSS,
			Label:    "regulatory:nih",
			// NOT-OD-* = policy notices. NOT-MH-*, NOT-CA-* = institute-specific.
			// PA-* = program announcements. Filter to policy-level notices.
			Keywords: []string{"NOT-OD-", "data security", "data sharing", "genomic", "research security", "controlled access"},
		},
		{
			ID:       "nist-csrc",
			Name:     "NIST Computer Security Resource Center",
			FeedURL:  "https://csrc.nist.gov/feeds/publications.rss",
			FeedType: FeedTypeRSS,
			Label:    "regulatory:nist",
			Keywords: []string{"800-171", "800-53", "800-218", "800-223", "CMMC", "CUI", "cybersecurity framework"},
		},
		{
			ID:       "federal-register-hhs",
			Name:     "Federal Register — HHS (HIPAA, research policy)",
			FeedURL:  "https://www.federalregister.gov/api/v1/documents.json?agencies[]=health-and-human-services&type[]=Rule&type[]=Proposed+Rule&per_page=20",
			FeedType: FeedTypeFederalRegisterAPI,
			Label:    "regulatory:hipaa-hhs",
			Keywords: []string{"HIPAA", "research", "privacy", "security", "data", "genomic", "biobank"},
		},
		{
			ID:       "federal-register-dod",
			Name:     "Federal Register — DoD (CMMC, DFARS, CUI)",
			FeedURL:  "https://www.federalregister.gov/api/v1/documents.json?agencies[]=defense-department&type[]=Rule&type[]=Proposed+Rule&per_page=20&cfr[title]=32&cfr[title]=48",
			FeedType: FeedTypeFederalRegisterAPI,
			Label:    "regulatory:dod-cmmc",
			Keywords: []string{"CMMC", "CUI", "cybersecurity", "DFARS", "cloud", "information system", "NIST"},
		},
		{
			ID:       "fedramp-automation",
			Name:     "FedRAMP Automation (GSA GitHub releases)",
			FeedURL:  "https://api.github.com/repos/GSA/fedramp-automation/releases",
			FeedType: FeedTypeGitHubReleases,
			Label:    "regulatory:fedramp",
			Keywords: []string{}, // all releases relevant
		},
	}
}
