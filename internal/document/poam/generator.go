// Package poam generates Plan of Action & Milestones from the crosswalk.
// Every gap or partial control produces a POA&M entry with a milestone ID,
// finding description, scheduled completion, and remediation guidance.
// The POA&M is a computed artifact — every entry traces to a crosswalk status.
package poam

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/provabl/attest/pkg/schema"
)

// Entry is a single POA&M action item.
type Entry struct {
	MilestoneID         string    // e.g., "POA-001"
	ControlID           string    // e.g., "3.1.3"
	ControlTitle        string    // human-readable control title
	FindingType         string    // "gap" or "partial"
	FindingDescription  string
	ScheduledCompletion time.Time
	Remediation         string
	ResponsibleParty    string
}

// Document is a complete Plan of Action & Milestones.
type Document struct {
	Title       string
	SREID       string
	Framework   string
	GeneratedAt time.Time
	Entries     []Entry
	GapCount    int
	PartialCount int
}

// Generator produces POA&M documents from the crosswalk.
type Generator struct{}

// NewGenerator creates a POA&M generator.
func NewGenerator() *Generator { return &Generator{} }

// Generate produces a POA&M from the crosswalk for a given framework.
// Only gap and partial controls produce entries.
func (g *Generator) Generate(sre *schema.SRE, fw *schema.Framework, crosswalk *schema.Crosswalk) (*Document, error) {
	// Index framework controls by ID for title lookup.
	ctrlTitles := make(map[string]string)
	for _, ctrl := range fw.Controls {
		ctrlTitles[ctrl.ID] = ctrl.Title
	}

	doc := &Document{
		Title:       fmt.Sprintf("Plan of Action & Milestones — %s — %s", sre.OrgID, fw.Name),
		SREID:       sre.OrgID,
		Framework:   fw.ID,
		GeneratedAt: time.Now(),
	}

	// Sort crosswalk entries by control ID for deterministic output.
	entries := make([]schema.CrosswalkEntry, len(crosswalk.Entries))
	copy(entries, crosswalk.Entries)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ControlID < entries[j].ControlID
	})

	seq := 1
	now := time.Now()

	for _, entry := range entries {
		if entry.Status != "gap" && entry.Status != "partial" {
			continue
		}

		milestoneID := fmt.Sprintf("POA-%03d", seq)
		seq++

		var finding, remediation string
		var scheduled time.Time

		switch entry.Status {
		case "gap":
			finding = fmt.Sprintf("Control %s has no structural or operational enforcement artifacts compiled. "+
				"The control is defined in the framework but no SCPs or Cedar policies have been generated for it.",
				entry.ControlID)
			remediation = fmt.Sprintf("1. Review the framework definition for %s and add structural/operational enforcement specs. "+
				"2. Run `attest compile` to generate policy artifacts. "+
				"3. Run `attest apply` to deploy to the organization.", entry.ControlID)
			scheduled = now.AddDate(0, 3, 0) // 90 days
			doc.GapCount++

		case "partial":
			missing := []string{}
			if len(entry.SCPs) == 0 {
				missing = append(missing, "structural enforcement (SCP)")
			}
			if len(entry.CedarPolicies) == 0 {
				missing = append(missing, "operational enforcement (Cedar policy)")
			}
			finding = fmt.Sprintf("Control %s has partial enforcement. Missing: %s.",
				entry.ControlID, strings.Join(missing, " and "))
			remediation = fmt.Sprintf("Add %s for control %s to the framework definition, "+
				"then run `attest compile` and `attest apply`.", strings.Join(missing, " and "), entry.ControlID)
			scheduled = now.AddDate(0, 1, 0) // 30 days
			doc.PartialCount++
		}

		doc.Entries = append(doc.Entries, Entry{
			MilestoneID:         milestoneID,
			ControlID:           entry.ControlID,
			ControlTitle:        ctrlTitles[entry.ControlID],
			FindingType:         entry.Status,
			FindingDescription:  finding,
			ScheduledCompletion: scheduled,
			Remediation:         remediation,
			ResponsibleParty:    "Security Engineer",
		})
	}

	return doc, nil
}

// Render converts the POA&M to a markdown string.
func (d *Document) Render() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# %s\n\n", d.Title))
	b.WriteString(fmt.Sprintf("**Generated**: %s\n", d.GeneratedAt.Format("January 2, 2006")))
	b.WriteString(fmt.Sprintf("**Framework**: %s\n", d.Framework))
	b.WriteString(fmt.Sprintf("**Gaps**: %d | **Partial**: %d | **Total items**: %d\n\n", d.GapCount, d.PartialCount, len(d.Entries)))
	b.WriteString("---\n\n")

	if len(d.Entries) == 0 {
		b.WriteString("No POA&M items. All framework controls are enforced or AWS-covered.\n")
		return b.String()
	}

	b.WriteString("| ID | Control | Type | Scheduled | Responsible |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, e := range d.Entries {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			e.MilestoneID, e.ControlID, e.FindingType,
			e.ScheduledCompletion.Format("2006-01-02"), e.ResponsibleParty))
	}
	b.WriteString("\n---\n\n")

	for _, e := range d.Entries {
		b.WriteString(fmt.Sprintf("## %s — %s %s\n\n", e.MilestoneID, e.ControlID, e.ControlTitle))
		b.WriteString(fmt.Sprintf("**Type**: %s | **Scheduled**: %s | **Responsible**: %s\n\n",
			e.FindingType, e.ScheduledCompletion.Format("2006-01-02"), e.ResponsibleParty))
		b.WriteString(fmt.Sprintf("**Finding**: %s\n\n", e.FindingDescription))
		b.WriteString(fmt.Sprintf("**Remediation**: %s\n\n", e.Remediation))
		b.WriteString("---\n\n")
	}

	return b.String()
}
