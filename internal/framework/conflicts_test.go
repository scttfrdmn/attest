package framework

import (
	"testing"

	"github.com/provabl/attest/pkg/schema"
)

func makeFramework(id string) *schema.Framework {
	return &schema.Framework{ID: id, Name: id}
}

func TestDetectConflicts_NoConflictsWithSingleFramework(t *testing.T) {
	conflicts := DetectConflicts([]*schema.Framework{makeFramework("nist-800-171-r2")})
	if len(conflicts) != 0 {
		t.Errorf("single framework: got %d conflicts, want 0", len(conflicts))
	}
}

func TestDetectConflicts_ITARandNIST(t *testing.T) {
	conflicts := DetectConflicts([]*schema.Framework{
		makeFramework("itar"),
		makeFramework("nist-800-171-r2"),
	})
	found := false
	for _, c := range conflicts {
		if c.Severity == "blocking" && c.Type == "contradiction" {
			found = true
		}
	}
	if !found {
		t.Error("ITAR + NIST: expected blocking contradiction, got none")
	}
}

func TestDetectConflicts_ITARandNIST800_53(t *testing.T) {
	conflicts := DetectConflicts([]*schema.Framework{
		makeFramework("itar"),
		makeFramework("nist-800-53-r5"),
	})
	var blocking []Conflict
	for _, c := range conflicts {
		if c.Severity == "blocking" {
			blocking = append(blocking, c)
		}
	}
	if len(blocking) == 0 {
		t.Error("ITAR + NIST 800-53: expected at least one blocking conflict")
	}
}

func TestDetectConflicts_HIPAAandNIST(t *testing.T) {
	conflicts := DetectConflicts([]*schema.Framework{
		makeFramework("hipaa"),
		makeFramework("nist-800-171-r2"),
	})
	// HIPAA + NIST should produce an info-level conflict (emergency access)
	found := false
	for _, c := range conflicts {
		if c.Type == "info" {
			found = true
		}
	}
	if !found {
		t.Error("HIPAA + NIST: expected info-level conflict for emergency access")
	}
}

func TestDetectConflicts_NISTargetsFERPA(t *testing.T) {
	conflicts := DetectConflicts([]*schema.Framework{
		makeFramework("nist-800-171-r2"),
		makeFramework("ferpa"),
	})
	// NIST supersedes FERPA encryption — should be supersession
	found := false
	for _, c := range conflicts {
		if c.Type == "supersession" {
			found = true
		}
	}
	if !found {
		t.Error("NIST + FERPA: expected supersession conflict for encryption standard")
	}
}

func TestDetectConflicts_UKCEandNIST(t *testing.T) {
	conflicts := DetectConflicts([]*schema.Framework{
		makeFramework("uk-cyber-essentials"),
		makeFramework("nist-800-171-r2"),
	})
	found := false
	for _, c := range conflicts {
		if c.Type == "supersession" {
			found = true
		}
	}
	if !found {
		t.Error("UK CE + NIST: expected supersession conflict for region restriction")
	}
}

func TestDetectConflicts_ASDAlone(t *testing.T) {
	conflicts := DetectConflicts([]*schema.Framework{
		makeFramework("asd-essential-eight"),
	})
	// Single framework — no conflicts.
	if len(conflicts) != 0 {
		t.Errorf("ASD alone: got %d conflicts, want 0", len(conflicts))
	}
}

func TestDetectConflicts_ASDWithoutOthers(t *testing.T) {
	conflicts := DetectConflicts([]*schema.Framework{
		makeFramework("asd-essential-eight"),
		makeFramework("hipaa"),
	})
	// ASD without NIST/800-53/FedRAMP should produce a coverage warning.
	found := false
	for _, c := range conflicts {
		if c.Severity == "warning" {
			found = true
		}
	}
	if !found {
		t.Error("ASD without NIST: expected coverage warning")
	}
}

func TestHasBlockingConflicts(t *testing.T) {
	none := []Conflict{{Severity: "warning"}, {Severity: "info"}}
	if HasBlockingConflicts(none) {
		t.Error("HasBlockingConflicts(warning,info) = true, want false")
	}
	withBlocking := append(none, Conflict{Severity: "blocking"})
	if !HasBlockingConflicts(withBlocking) {
		t.Error("HasBlockingConflicts(with blocking) = false, want true")
	}
}

func TestFormatConflicts_Empty(t *testing.T) {
	if out := FormatConflicts(nil); out != "" {
		t.Errorf("FormatConflicts(nil) = %q, want empty", out)
	}
}

func TestFormatConflicts_NonEmpty(t *testing.T) {
	conflicts := []Conflict{
		{
			Type:       "contradiction",
			Severity:   "blocking",
			Frameworks: []string{"itar", "nist-800-171-r2"},
			ControlIDs: []string{"3.1.3"},
			Description: "Test conflict",
			Resolution:  "Test resolution",
		},
	}
	out := FormatConflicts(conflicts)
	if out == "" {
		t.Error("FormatConflicts with conflicts returned empty string")
	}
	if !contains(out, "contradiction") {
		t.Error("FormatConflicts output missing type")
	}
	if !contains(out, "itar") {
		t.Error("FormatConflicts output missing framework name")
	}
	if !contains(out, "3.1.3") {
		t.Error("FormatConflicts output missing control ID")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
