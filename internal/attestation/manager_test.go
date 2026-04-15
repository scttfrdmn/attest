package attestation

import (
	"context"
	"testing"
	"time"

	"github.com/scttfrdmn/attest/pkg/schema"
)

func TestCreateAndList(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	ctx := context.Background()

	a := &schema.Attestation{
		ID:          "ATT-2026-001",
		ControlID:   "3.2.1",
		Title:       "Annual security awareness training",
		AffirmedBy:  "CISO Dr. Park",
		ExpiresAt:   time.Now().AddDate(1, 0, 0),
		EvidenceRef: "canvas-training-export.csv",
		EvidenceType: "training_record",
	}
	if err := mgr.Create(ctx, a); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	list, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List() = %d, want 1", len(list))
	}
	if list[0].ID != "ATT-2026-001" {
		t.Errorf("ID = %q, want ATT-2026-001", list[0].ID)
	}
}

func TestIsAttested(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	ctx := context.Background()

	_ = mgr.Create(ctx, &schema.Attestation{
		ID:         "ATT-2026-001",
		ControlID:  "3.2.1",
		AffirmedBy: "CISO",
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
	})

	tests := []struct {
		controlID  string
		wantResult bool
	}{
		{"3.2.1", true},
		{"3.2.2", false},  // different control
		{"3.11.1", false}, // no attestation
	}

	for _, tt := range tests {
		att, ok, err := mgr.IsAttested(ctx, tt.controlID)
		if err != nil {
			t.Fatalf("IsAttested(%q) error = %v", tt.controlID, err)
		}
		if ok != tt.wantResult {
			t.Errorf("IsAttested(%q) = %v, want %v", tt.controlID, ok, tt.wantResult)
		}
		if tt.wantResult && att == nil {
			t.Errorf("expected attestation returned for %q", tt.controlID)
		}
	}
}

func TestExpiredAttestation(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	ctx := context.Background()

	// Create an already-expired attestation.
	_ = mgr.Create(ctx, &schema.Attestation{
		ID:         "ATT-2025-OLD",
		ControlID:  "3.11.1",
		AffirmedBy: "CISO",
		ExpiresAt:  time.Now().AddDate(-1, 0, 0), // 1 year ago
	})

	_, ok, err := mgr.IsAttested(ctx, "3.11.1")
	if err != nil {
		t.Fatalf("IsAttested() error = %v", err)
	}
	if ok {
		t.Error("IsAttested() should return false for expired attestation")
	}
}

func TestListExpiring(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	ctx := context.Background()

	_ = mgr.Create(ctx, &schema.Attestation{
		ID:        "ATT-SOON",
		ControlID: "3.2.1",
		AffirmedBy: "CISO",
		ExpiresAt: time.Now().AddDate(0, 0, 10), // 10 days
	})
	_ = mgr.Create(ctx, &schema.Attestation{
		ID:        "ATT-LATER",
		ControlID: "3.2.2",
		AffirmedBy: "CISO",
		ExpiresAt: time.Now().AddDate(1, 0, 0), // 1 year
	})

	expiring, err := mgr.ListExpiring(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("ListExpiring() error = %v", err)
	}
	if len(expiring) != 1 {
		t.Errorf("ListExpiring() = %d, want 1", len(expiring))
	}
	if len(expiring) > 0 && expiring[0].ID != "ATT-SOON" {
		t.Errorf("expected ATT-SOON, got %s", expiring[0].ID)
	}
}

func TestCreateValidation(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	ctx := context.Background()

	tests := []struct {
		name    string
		a       schema.Attestation
		wantErr bool
	}{
		{"missing affirmer", schema.Attestation{ID: "A1", ControlID: "3.2.1", ExpiresAt: time.Now().AddDate(1, 0, 0)}, true},
		{"missing expiry", schema.Attestation{ID: "A2", ControlID: "3.2.1", AffirmedBy: "CISO"}, true},
		{"missing control", schema.Attestation{ID: "A3", AffirmedBy: "CISO", ExpiresAt: time.Now().AddDate(1, 0, 0)}, true},
		{"valid", schema.Attestation{ID: "A4", ControlID: "3.2.1", AffirmedBy: "CISO", ExpiresAt: time.Now().AddDate(1, 0, 0)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.Create(ctx, &tt.a)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpireAttestation(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	ctx := context.Background()

	_ = mgr.Create(ctx, &schema.Attestation{
		ID:        "ATT-EXPIRE-ME",
		ControlID: "3.6.3",
		AffirmedBy: "CISO",
		ExpiresAt: time.Now().AddDate(1, 0, 0),
	})

	if err := mgr.Expire(ctx, "ATT-EXPIRE-ME"); err != nil {
		t.Fatalf("Expire() error = %v", err)
	}

	_, ok, _ := mgr.IsAttested(ctx, "3.6.3")
	if ok {
		t.Error("expected control to be unattestedafter expiry")
	}
}
