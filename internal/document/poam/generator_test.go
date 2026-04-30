// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package poam

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/provabl/attest/pkg/schema"
)

func makeTestData() (*schema.SRE, *schema.Framework, *schema.Crosswalk) {
	sre := &schema.SRE{OrgID: "o-test", Name: "Test SRE"}
	fw := &schema.Framework{
		ID:   "nist-test",
		Name: "NIST Test",
		Controls: []schema.Control{
			{ID: "3.1.1", Family: "Access Control", Title: "Limit system access"},
			{ID: "3.1.3", Family: "Access Control", Title: "Control CUI flow"},
			{ID: "3.13.1", Family: "Sys & Comms", Title: "Protect comms boundaries"},
		},
	}
	cw := &schema.Crosswalk{
		SRE:         "o-test",
		Framework:   "nist-test",
		GeneratedAt: time.Now(),
		Entries: []schema.CrosswalkEntry{
			{ControlID: "3.1.1", Status: "enforced", SCPs: []string{"scp-mfa"}, CedarPolicies: []string{"cedar-auth"}},
			{ControlID: "3.1.3", Status: "partial", SCPs: []string{"scp-region"}},
			{ControlID: "3.13.1", Status: "gap"},
		},
	}
	return sre, fw, cw
}

func TestGeneratePOAM(t *testing.T) {
	sre, fw, cw := makeTestData()
	gen := NewGenerator()
	doc, err := gen.Generate(sre, fw, cw)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if doc.GapCount != 1 {
		t.Errorf("GapCount = %d, want 1", doc.GapCount)
	}
	if doc.PartialCount != 1 {
		t.Errorf("PartialCount = %d, want 1", doc.PartialCount)
	}
	if len(doc.Entries) != 2 {
		t.Errorf("Entries = %d, want 2 (enforced excluded)", len(doc.Entries))
	}
}

func TestPOAMScheduledDates(t *testing.T) {
	sre, fw, cw := makeTestData()
	gen := NewGenerator()
	doc, _ := gen.Generate(sre, fw, cw)

	now := time.Now()
	for _, e := range doc.Entries {
		if e.FindingType == "gap" {
			// Should be ~90 days out.
			days := int(e.ScheduledCompletion.Sub(now).Hours() / 24)
			if days < 85 || days > 95 {
				t.Errorf("gap scheduled %d days out, want ~90", days)
			}
		}
		if e.FindingType == "partial" {
			// Should be ~30 days out.
			days := int(e.ScheduledCompletion.Sub(now).Hours() / 24)
			if days < 25 || days > 35 {
				t.Errorf("partial scheduled %d days out, want ~30", days)
			}
		}
	}
}

func TestPOAMMilestoneIDs(t *testing.T) {
	sre, fw, cw := makeTestData()
	gen := NewGenerator()
	doc, _ := gen.Generate(sre, fw, cw)

	ids := make(map[string]bool)
	for _, e := range doc.Entries {
		if ids[e.MilestoneID] {
			t.Errorf("duplicate milestone ID: %s", e.MilestoneID)
		}
		ids[e.MilestoneID] = true
		if !strings.HasPrefix(e.MilestoneID, "POA-") {
			t.Errorf("milestone ID %q does not start with POA-", e.MilestoneID)
		}
	}
}

func TestPOAMRender(t *testing.T) {
	sre, fw, cw := makeTestData()
	gen := NewGenerator()
	doc, _ := gen.Generate(sre, fw, cw)
	_ = context.Background()

	md := doc.Render()
	if !strings.Contains(md, "Plan of Action") {
		t.Error("render missing 'Plan of Action'")
	}
	if !strings.Contains(md, "POA-001") {
		t.Error("render missing first milestone ID")
	}
}
