package reporting

import (
	"testing"
	"time"
)

func TestIncidentManagerCreate(t *testing.T) {
	dir := t.TempDir()
	mgr := NewIncidentManager(dir)

	inc, err := mgr.Create("Root login detected", "HIGH", "manual", "Saw root API call in CloudTrail", []string{"3.1.5"})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if inc.ID == "" {
		t.Error("ID should not be empty")
	}
	if inc.Title != "Root login detected" {
		t.Errorf("Title = %q, want %q", inc.Title, "Root login detected")
	}
	if inc.Status != "open" {
		t.Errorf("Status = %q, want open", inc.Status)
	}
	if len(inc.ControlIDs) != 1 || inc.ControlIDs[0] != "3.1.5" {
		t.Errorf("ControlIDs = %v, want [3.1.5]", inc.ControlIDs)
	}
	if inc.DetectedAt.IsZero() {
		t.Error("DetectedAt should be set")
	}
}

func TestIncidentManagerList(t *testing.T) {
	dir := t.TempDir()
	mgr := NewIncidentManager(dir)

	// Empty list.
	incidents, err := mgr.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(incidents) != 0 {
		t.Errorf("empty list: got %d, want 0", len(incidents))
	}

	// Create two incidents.
	_, _ = mgr.Create("Incident 1", "HIGH", "guardduty", "", nil)
	_, _ = mgr.Create("Incident 2", "MEDIUM", "manual", "", nil)

	incidents, err = mgr.List()
	if err != nil {
		t.Fatalf("List() after creates error: %v", err)
	}
	if len(incidents) != 2 {
		t.Errorf("got %d incidents, want 2", len(incidents))
	}
}

func TestIncidentManagerResolve(t *testing.T) {
	dir := t.TempDir()
	mgr := NewIncidentManager(dir)

	inc, _ := mgr.Create("Test incident", "LOW", "manual", "", nil)
	id := inc.ID

	if err := mgr.Resolve(id, "Fixed via patching"); err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	incidents, _ := mgr.List()
	var found *Incident
	for _, i := range incidents {
		if i.ID == id {
			found = i
		}
	}
	if found == nil {
		t.Fatal("resolved incident not found in list")
	}
	if found.Status != "resolved" {
		t.Errorf("Status = %q, want resolved", found.Status)
	}
	if found.ResolvedAt == nil {
		t.Error("ResolvedAt should be set after resolve")
	}
	if found.Notes != "Fixed via patching" {
		t.Errorf("Notes = %q, want 'Fixed via patching'", found.Notes)
	}
}

func TestIncidentManagerResolveNotFound(t *testing.T) {
	dir := t.TempDir()
	mgr := NewIncidentManager(dir)
	if err := mgr.Resolve("INC-9999", "notes"); err == nil {
		t.Error("Resolve(nonexistent) should return error")
	}
}

func TestIncidentIDSequential(t *testing.T) {
	dir := t.TempDir()
	mgr := NewIncidentManager(dir)

	inc1, _ := mgr.Create("First", "HIGH", "manual", "", nil)
	inc2, _ := mgr.Create("Second", "HIGH", "manual", "", nil)

	if inc1.ID == inc2.ID {
		t.Error("incidents should have unique IDs")
	}
}

func TestIncidentDetectedAtSet(t *testing.T) {
	dir := t.TempDir()
	mgr := NewIncidentManager(dir)
	before := time.Now()
	inc, _ := mgr.Create("Timed test", "LOW", "manual", "", nil)
	after := time.Now()

	if inc.DetectedAt.Before(before) || inc.DetectedAt.After(after) {
		t.Error("DetectedAt not within expected time range")
	}
}

func TestIncidentManagerPersistence(t *testing.T) {
	dir := t.TempDir()
	mgr1 := NewIncidentManager(dir)
	_, _ = mgr1.Create("Persist test", "MEDIUM", "manual", "", nil)

	// Re-open from same directory.
	mgr2 := NewIncidentManager(dir)
	incidents, err := mgr2.List()
	if err != nil {
		t.Fatalf("re-load error: %v", err)
	}
	if len(incidents) != 1 {
		t.Errorf("persistence: got %d incidents, want 1", len(incidents))
	}
	if incidents[0].Title != "Persist test" {
		t.Errorf("persisted title = %q, want 'Persist test'", incidents[0].Title)
	}
}
