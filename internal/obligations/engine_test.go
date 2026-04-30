// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package obligations_test

import (
	"testing"

	"github.com/provabl/attest/internal/obligations"
	"github.com/provabl/attest/pkg/schema"
)

func hasObligation(obs []obligations.Obligation, id string) bool {
	for _, o := range obs {
		if o.ID == id {
			return true
		}
	}
	return false
}

func severity(obs []obligations.Obligation, id string) string {
	for _, o := range obs {
		if o.ID == id {
			return o.Severity
		}
	}
	return ""
}

var eng = obligations.New()

// --- funding rules ------------------------------------------------------------

func TestDoDFundingTriggersCMMCLevel2(t *testing.T) {
	p := schema.ResearchProject{
		Funding: []schema.GrantRef{{Source: "DoD", Award: "N00014-26-1-2345", Type: "grant"}},
	}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "cmmc-level-2") {
		t.Error("DoD funding must trigger cmmc-level-2 obligation")
	}
	if !hasObligation(obs, "sprs-reporting") {
		t.Error("DoD funding must trigger sprs-reporting obligation")
	}
}

func TestDoDPlusCUITriggersMandatoryCMMC(t *testing.T) {
	p := schema.ResearchProject{
		Funding:   []schema.GrantRef{{Source: "ONR", Award: "N00014-26-1-9999"}},
		DataTypes: []string{"CUI"},
	}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "cmmc-level-2-cui") {
		t.Error("DoD funding + CUI must trigger cmmc-level-2-cui (mandatory C3PAO) obligation")
	}
	if severity(obs, "cmmc-level-2-cui") != "critical" {
		t.Error("cmmc-level-2-cui obligation must have critical severity")
	}
}

func TestNIHFundingTriggersDMSP(t *testing.T) {
	p := schema.ResearchProject{
		Funding: []schema.GrantRef{{Source: "NIH", Award: "R01-CA-123456"}},
	}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "nih-dmsp") {
		t.Error("NIH funding must trigger nih-dmsp obligation")
	}
	if !hasObligation(obs, "nih-research-security-training") {
		t.Error("NIH funding must trigger research security training obligation")
	}
}

func TestNIHPlusGenomicTriggersGDSPolicy(t *testing.T) {
	p := schema.ResearchProject{
		Funding:   []schema.GrantRef{{Source: "NIH", Award: "R01-HG-999"}},
		DataTypes: []string{"genomic sequencing"},
	}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "nih-gds-policy") {
		t.Error("NIH + genomic data must trigger nih-gds-policy obligation")
	}
	if !hasObligation(obs, "dbgap-duc") {
		t.Error("NIH + genomic data must trigger dbgap-duc obligation")
	}
}

func TestNSFFundingTriggersDMP(t *testing.T) {
	p := schema.ResearchProject{
		Funding: []schema.GrantRef{{Source: "NSF", Award: "NSF-2026-PHY-12345"}},
	}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "nsf-dmp") {
		t.Error("NSF funding must trigger nsf-dmp obligation")
	}
}

// --- data type rules ----------------------------------------------------------

func TestPHITriggersHIPAABAA(t *testing.T) {
	p := schema.ResearchProject{DataTypes: []string{"PHI"}}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "hipaa-baa") {
		t.Error("PHI data type must trigger hipaa-baa obligation")
	}
	if severity(obs, "hipaa-baa") != "critical" {
		t.Error("hipaa-baa obligation must have critical severity")
	}
}

func TestSUDTriggers42CFRPart2(t *testing.T) {
	p := schema.ResearchProject{DataTypes: []string{"SUD"}}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "42-cfr-part-2") {
		t.Error("SUD data type must trigger 42-cfr-part-2 obligation")
	}
}

func TestStudentDataTriggersFERPA(t *testing.T) {
	p := schema.ResearchProject{DataTypes: []string{"student records"}}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "ferpa") {
		t.Error("student records data type must trigger ferpa obligation")
	}
}

// --- collaborator rules -------------------------------------------------------

func TestEUCollaboratorTriggersGDPR(t *testing.T) {
	p := schema.ResearchProject{
		Collaborators: []schema.CollaboratorRef{{Name: "Dr. Mueller", Institution: "TU Berlin", Country: "DE"}},
	}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "gdpr-sccs") {
		t.Error("EU collaborator must trigger gdpr-sccs obligation")
	}
}

func TestChineseCollaboratorPlusDoDTriggersITAR(t *testing.T) {
	p := schema.ResearchProject{
		Funding:       []schema.GrantRef{{Source: "DoD", Award: "W911NF-26-1-0001"}},
		Collaborators: []schema.CollaboratorRef{{Name: "Dr. Liu Wei", Institution: "Peking University", Country: "CN"}},
	}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "itar-tcp") {
		t.Error("DoD funding + Chinese collaborator must trigger itar-tcp obligation")
	}
	if !hasObligation(obs, "deemed-export-review") {
		t.Error("DoD funding + Chinese collaborator must trigger deemed-export-review obligation")
	}
	if severity(obs, "itar-tcp") != "critical" {
		t.Error("itar-tcp obligation must have critical severity")
	}
}

func TestNonControlledCountryNoITAR(t *testing.T) {
	p := schema.ResearchProject{
		Funding:       []schema.GrantRef{{Source: "DoD", Award: "N00014-26-1-0001"}},
		Collaborators: []schema.CollaboratorRef{{Name: "Dr. Schmidt", Institution: "ETH Zurich", Country: "CH"}},
	}
	obs := eng.Map(p, nil)
	if hasObligation(obs, "itar-tcp") {
		t.Error("Swiss collaborator must NOT trigger itar-tcp (CH is not an ITAR-controlled country)")
	}
}

func TestEUCollaboratorWithoutDoDNoITAR(t *testing.T) {
	p := schema.ResearchProject{
		Funding:       []schema.GrantRef{{Source: "NSF", Award: "NSF-2026-1234"}},
		Collaborators: []schema.CollaboratorRef{{Name: "Dr. Chen", Institution: "Peking University", Country: "CN"}},
	}
	obs := eng.Map(p, nil)
	if hasObligation(obs, "itar-tcp") {
		t.Error("Chinese collaborator without DoD funding must NOT trigger itar-tcp")
	}
}

// --- IRB rules ----------------------------------------------------------------

func TestIRBProtocolTriggersCommonRule(t *testing.T) {
	p := schema.ResearchProject{IRBProtocol: "IRB-2026-001"}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "irb-continuing-review") {
		t.Error("IRB protocol must trigger irb-continuing-review obligation")
	}
	if !hasObligation(obs, "45-cfr-46") {
		t.Error("IRB protocol must trigger 45-cfr-46 obligation")
	}
}

func TestNoIRBNoCommonRule(t *testing.T) {
	p := schema.ResearchProject{IRBProtocol: ""}
	obs := eng.Map(p, nil)
	if hasObligation(obs, "irb-continuing-review") {
		t.Error("no IRB protocol must not trigger irb-continuing-review")
	}
}

// --- dbGaP rules --------------------------------------------------------------

func TestDBGaPAccessionsTriggerAnnualRenewal(t *testing.T) {
	p := schema.ResearchProject{DBGaPAccessions: []string{"phs000001.v1.p1"}}
	obs := eng.Map(p, nil)
	if !hasObligation(obs, "dbgap-annual-renewal") {
		t.Error("dbGaP accessions must trigger dbgap-annual-renewal obligation")
	}
	for _, o := range obs {
		if o.ID == "dbgap-annual-renewal" && o.DueDate == nil {
			t.Error("dbgap-annual-renewal must have a due date set")
		}
	}
}

// --- titles helper ------------------------------------------------------------

func TestTitlesDeduplicates(t *testing.T) {
	p := schema.ResearchProject{
		Funding:   []schema.GrantRef{{Source: "DoD"}, {Source: "ONR"}},
		DataTypes: []string{"CUI"},
	}
	titles := eng.Titles(p)
	seen := map[string]int{}
	for _, t2 := range titles {
		seen[t2]++
	}
	for title, count := range seen {
		if count > 1 {
			t.Errorf("Titles() returned duplicate: %q (%d times)", title, count)
		}
	}
}
