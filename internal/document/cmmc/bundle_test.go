// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package cmmc

import (
	"strings"
	"testing"
)

// TestSanitizeMarkdown covers the CRITICAL security fix: assessor org / OrgID markdown injection.
func TestSanitizeMarkdown(t *testing.T) {
	tests := []struct {
		input    string
		wantFree []string // these EXACT substrings must NOT appear (the unescaped attack vectors)
		desc     string
	}{
		{
			// Markdown link [text](url) — both [ and ] must be escaped so "](" never appears.
			input:    "[Evil Corp](https://phishing.com)",
			wantFree: []string{"]("},
			desc:     "markdown link injection — '](' sequence broken",
		},
		{
			// HTML tags — < and > must be escaped.
			input:    "<script>alert(1)</script>",
			wantFree: []string{"<script>", "</script>"},
			desc:     "HTML script tag — raw < > removed",
		},
		{
			// Newline — must be collapsed to prevent multi-line injection.
			input:    "Org\nInjected header",
			wantFree: []string{"\n"},
			desc:     "newline injection",
		},
		{
			// Raw backtick pair — would create code span in markdown.
			input:    "Corp `cmd`",
			wantFree: []string{"`cmd`"},
			desc:     "code span injection",
		},
		{
			// *text* — would render as bold in markdown.
			input:    "*bold*",
			wantFree: []string{"*bold*"},
			desc:     "markdown bold injection",
		},
	}

	for _, tt := range tests {
		got := sanitizeMarkdown(tt.input)
		for _, forbidden := range tt.wantFree {
			if strings.Contains(got, forbidden) {
				t.Errorf("[%s] sanitizeMarkdown(%q) still contains %q\n  output: %q",
					tt.desc, tt.input, forbidden, got)
			}
		}
		// Output must be non-empty (content is preserved, just escaped)
		if got == "" && tt.input != "" {
			t.Errorf("[%s] sanitizeMarkdown(%q) = empty string", tt.desc, tt.input)
		}
	}
}

// TestSanitizeMarkdownPreservesText verifies safe text is not mangled.
func TestSanitizeMarkdownPreservesText(t *testing.T) {
	safe := []string{
		"Acme Labs",
		"University of California",
		"DoD Research Division",
		"Meridian Research University",
	}
	for _, s := range safe {
		got := sanitizeMarkdown(s)
		// Safe text should pass through without adding noise
		// (letters, spaces, digits preserved — only metacharacters escaped)
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == ' ' {
				if !strings.ContainsRune(got, r) {
					t.Errorf("sanitizeMarkdown(%q) dropped safe character %q", s, r)
				}
			}
		}
	}
}
