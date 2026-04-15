// Package assessment generates CMMC 2.0 Level 2 self-assessment scores
// from the crosswalk. For NIST 800-171, 110 controls × 5 points = 550 max.
// Scoring follows NIST SP 800-171A assessment objectives.
package assessment

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/scttfrdmn/attest/pkg/schema"
)

// ControlScore is the assessment score for a single control.
type ControlScore struct {
	ControlID   string
	ControlTitle string
	Family      string
	Status      string // crosswalk status
	Score       int    // 0, 1, 3, or 5
	MaxScore    int    // always 5
	Rationale   string
}

// FamilyScore aggregates scores within a control family.
type FamilyScore struct {
	Family   string
	Score    int
	MaxScore int
	Controls []ControlScore
}

// Assessment is a complete CMMC/800-171A self-assessment.
type Assessment struct {
	Title         string
	SREID         string
	Framework     string
	GeneratedAt   time.Time
	TotalScore    int
	MaxScore      int
	ScorePercent  float64
	Readiness     string // "Assessment Ready", "Not Ready", "Partially Ready"
	FamilyScores  []FamilyScore
	Implemented   int
	Partial       int
	Planned       int
	Gaps          int
}

// Generator produces self-assessment documents.
type Generator struct{}

// NewGenerator creates a self-assessment generator.
func NewGenerator() *Generator { return &Generator{} }

// Generate scores the SRE against 800-171A objectives using the crosswalk.
func (g *Generator) Generate(sre *schema.SRE, fw *schema.Framework, crosswalk *schema.Crosswalk) (*Assessment, error) {
	// Index crosswalk by control ID.
	cwByID := make(map[string]schema.CrosswalkEntry)
	for _, e := range crosswalk.Entries {
		cwByID[e.ControlID] = e
	}

	// Index framework controls by family.
	type ctrlMeta struct {
		Title  string
		Family string
	}
	ctrlMetas := make(map[string]ctrlMeta)
	for _, ctrl := range fw.Controls {
		ctrlMetas[ctrl.ID] = ctrlMeta{Title: ctrl.Title, Family: ctrl.Family}
	}

	// Score each control.
	familyMap := make(map[string]*FamilyScore)

	// Sort crosswalk entries for deterministic output.
	entries := make([]schema.CrosswalkEntry, len(crosswalk.Entries))
	copy(entries, crosswalk.Entries)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ControlID < entries[j].ControlID
	})

	as := &Assessment{
		Title:       fmt.Sprintf("CMMC 2.0 Level 2 Self-Assessment — %s — %s", sre.OrgID, fw.Name),
		SREID:       sre.OrgID,
		Framework:   fw.ID,
		GeneratedAt: time.Now(),
		MaxScore:    len(crosswalk.Entries) * 5,
	}

	for _, entry := range entries {
		meta := ctrlMetas[entry.ControlID]
		cs := ControlScore{
			ControlID:    entry.ControlID,
			ControlTitle: meta.Title,
			Family:       meta.Family,
			Status:       entry.Status,
			MaxScore:     5,
		}

		switch entry.Status {
		case "enforced":
			cs.Score = 5
			cs.Rationale = "Fully enforced: both structural (SCP) and operational (Cedar) enforcement compiled."
			as.Implemented++
		case "aws_covered":
			cs.Score = 5
			cs.Rationale = "AWS-covered: control is satisfied by AWS infrastructure per shared responsibility."
			as.Implemented++
		case "partial":
			cs.Score = 3
			cs.Rationale = "Partially implemented: either structural or operational enforcement is present but not both."
			as.Partial++
		case "planned":
			cs.Score = 1
			cs.Rationale = "Planned: control is defined in the framework but no artifacts have been compiled."
			as.Planned++
		default: // gap
			cs.Score = 0
			cs.Rationale = "Not implemented: no enforcement artifacts and not AWS-covered."
			as.Gaps++
		}

		as.TotalScore += cs.Score

		family := meta.Family
		if family == "" {
			family = "Uncategorized"
		}
		if _, ok := familyMap[family]; !ok {
			familyMap[family] = &FamilyScore{Family: family}
		}
		fs := familyMap[family]
		fs.Score += cs.Score
		fs.MaxScore += 5
		fs.Controls = append(fs.Controls, cs)
	}

	// Flatten and sort families.
	for _, fs := range familyMap {
		as.FamilyScores = append(as.FamilyScores, *fs)
	}
	sort.Slice(as.FamilyScores, func(i, j int) bool {
		return as.FamilyScores[i].Family < as.FamilyScores[j].Family
	})

	// Compute score percentage and readiness.
	if as.MaxScore > 0 {
		as.ScorePercent = float64(as.TotalScore) / float64(as.MaxScore) * 100
	}
	switch {
	case as.ScorePercent >= 80.0 && as.Gaps == 0:
		as.Readiness = "Assessment Ready"
	case as.ScorePercent >= 60.0:
		as.Readiness = "Partially Ready"
	default:
		as.Readiness = "Not Ready"
	}

	return as, nil
}

// Render converts the assessment to a markdown string.
func (a *Assessment) Render() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# %s\n\n", a.Title))
	b.WriteString(fmt.Sprintf("**Generated**: %s\n", a.GeneratedAt.Format("January 2, 2006")))
	b.WriteString(fmt.Sprintf("**Score**: %d/%d (%.1f%%)\n", a.TotalScore, a.MaxScore, a.ScorePercent))
	b.WriteString(fmt.Sprintf("**Readiness**: %s\n\n", a.Readiness))

	b.WriteString("## Summary\n\n")
	b.WriteString("| Status | Count | Points |\n")
	b.WriteString("|--------|-------|--------|\n")
	b.WriteString(fmt.Sprintf("| Implemented | %d | %d |\n", a.Implemented, a.Implemented*5))
	b.WriteString(fmt.Sprintf("| Partially Implemented | %d | %d |\n", a.Partial, a.Partial*3))
	b.WriteString(fmt.Sprintf("| Planned | %d | %d |\n", a.Planned, a.Planned*1))
	b.WriteString(fmt.Sprintf("| Not Implemented (Gap) | %d | 0 |\n", a.Gaps))
	b.WriteString(fmt.Sprintf("| **Total** | **%d** | **%d/%d** |\n\n", a.Implemented+a.Partial+a.Planned+a.Gaps, a.TotalScore, a.MaxScore))

	b.WriteString("---\n\n")
	b.WriteString("## Scores by Family\n\n")

	for _, fs := range a.FamilyScores {
		pct := 0.0
		if fs.MaxScore > 0 {
			pct = float64(fs.Score) / float64(fs.MaxScore) * 100
		}
		b.WriteString(fmt.Sprintf("### %s\n\n", fs.Family))
		b.WriteString(fmt.Sprintf("**Score**: %d/%d (%.1f%%)\n\n", fs.Score, fs.MaxScore, pct))
		b.WriteString("| Control | Status | Score |\n")
		b.WriteString("|---------|--------|-------|\n")
		for _, cs := range fs.Controls {
			b.WriteString(fmt.Sprintf("| %s | %s | %d/5 |\n", cs.ControlID, cs.Status, cs.Score))
		}
		b.WriteString("\n")
	}

	return b.String()
}
