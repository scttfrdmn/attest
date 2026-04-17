package multisre

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagerAddAndList(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	// Empty registry initially.
	sres, err := mgr.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(sres) != 0 {
		t.Errorf("empty registry: got %d, want 0", len(sres))
	}

	// Add one SRE.
	entry := SREEntry{
		ID:         "production",
		OrgID:      "o-abc12345xy",
		Region:     "us-east-1",
		Frameworks: []string{"nist-800-171-r2"},
	}
	if err := mgr.Add(entry); err != nil {
		t.Fatalf("Add() error: %v", err)
	}

	sres, err = mgr.List()
	if err != nil {
		t.Fatalf("List() after add error: %v", err)
	}
	if len(sres) != 1 {
		t.Fatalf("after add: got %d SREs, want 1", len(sres))
	}
	if sres[0].ID != "production" {
		t.Errorf("ID = %q, want production", sres[0].ID)
	}
	if sres[0].OrgID != "o-abc12345xy" {
		t.Errorf("OrgID = %q, want o-abc123", sres[0].OrgID)
	}
}

func TestManagerAddDuplicate(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	entry := SREEntry{ID: "prod", OrgID: "o-prodtest"}
	if err := mgr.Add(entry); err != nil {
		t.Fatalf("first Add() error: %v", err)
	}
	if err := mgr.Add(entry); err == nil {
		t.Error("duplicate Add() should return error")
	}
}

func TestManagerGet(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	_ = mgr.Add(SREEntry{ID: "dev", OrgID: "o-devtest01"})

	got, err := mgr.Get("dev")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got.OrgID != "o-devtest01" {
		t.Errorf("OrgID = %q, want o-dev", got.OrgID)
	}

	_, err = mgr.Get("nonexistent")
	if err == nil {
		t.Error("Get(nonexistent) should return error")
	}
}

func TestManagerRemove(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	_ = mgr.Add(SREEntry{ID: "prod", OrgID: "o-prodtest"})
	_ = mgr.Add(SREEntry{ID: "dev", OrgID: "o-devtest"})

	if err := mgr.Remove("dev"); err != nil {
		t.Fatalf("Remove() error: %v", err)
	}
	sres, _ := mgr.List()
	if len(sres) != 1 {
		t.Errorf("after remove: got %d SREs, want 1", len(sres))
	}
	if sres[0].ID != "prod" {
		t.Errorf("remaining SRE = %q, want prod", sres[0].ID)
	}

	if err := mgr.Remove("nonexistent"); err == nil {
		t.Error("Remove(nonexistent) should return error")
	}
}

func TestManagerStoreDir(t *testing.T) {
	mgr := NewManager(".attest")
	got := mgr.StoreDir("production")
	want := filepath.Join(".attest", ".sre-production")
	if got != want {
		t.Errorf("StoreDir = %q, want %q", got, want)
	}
}

func TestManagerAddValidation(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	// Missing ID.
	if err := mgr.Add(SREEntry{OrgID: "o-prodtest"}); err == nil {
		t.Error("Add(no ID) should return error")
	}

	// Missing OrgID.
	if err := mgr.Add(SREEntry{ID: "prod"}); err == nil {
		t.Error("Add(no OrgID) should return error")
	}
}

func TestManagerDefaultRegion(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	_ = mgr.Add(SREEntry{ID: "prod", OrgID: "o-prodtest"}) // no region specified
	sres, _ := mgr.List()
	if sres[0].Region != "us-east-1" {
		t.Errorf("default region = %q, want us-east-1", sres[0].Region)
	}
}

func TestAggregatePosture(t *testing.T) {
	postures := []SREPosture{
		{ID: "prod", Score: 400, MaxScore: 550, Enforced: 80, Partial: 20, Gaps: 10},
		{ID: "dev", Score: 300, MaxScore: 550, Enforced: 60, Partial: 20, Gaps: 30},
		{ID: "fail", Error: "scan failed"}, // should be skipped
	}
	agg := AggregatePosture(postures)
	if agg.Score != 700 {
		t.Errorf("aggregate Score = %d, want 700", agg.Score)
	}
	if agg.MaxScore != 1100 {
		t.Errorf("aggregate MaxScore = %d, want 1100", agg.MaxScore)
	}
	if agg.Enforced != 140 {
		t.Errorf("aggregate Enforced = %d, want 140", agg.Enforced)
	}
	if agg.Gaps != 40 {
		t.Errorf("aggregate Gaps = %d, want 40", agg.Gaps)
	}
}

func TestManagerRegistryPersistence(t *testing.T) {
	dir := t.TempDir()
	mgr1 := NewManager(dir)
	_ = mgr1.Add(SREEntry{ID: "prod", OrgID: "o-prodtest", Region: "us-east-1"})

	// Re-open from same directory.
	mgr2 := NewManager(dir)
	sres, err := mgr2.List()
	if err != nil {
		t.Fatalf("re-load error: %v", err)
	}
	if len(sres) != 1 || sres[0].ID != "prod" {
		t.Error("registry not persisted across manager instances")
	}

	// Verify file exists.
	if _, err := os.Stat(filepath.Join(dir, "sres.yaml")); err != nil {
		t.Errorf("sres.yaml not found: %v", err)
	}
}
