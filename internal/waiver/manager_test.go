// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package waiver

import (
	"context"
	"testing"
	"time"

	"github.com/provabl/attest/pkg/schema"
)

func TestCreateAndList(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	ctx := context.Background()

	w := &schema.Waiver{
		ID:          "W-2026-001",
		ControlID:   "3.1.12",
		Title:       "USB transfer exception",
		Scope:       "clean-room",
		ApprovedBy:  "CISO Dr. Park",
		ExpiresAt:   time.Now().AddDate(1, 0, 0),
		Justification: "Air-gapped instruments require USB",
	}
	if err := mgr.Create(ctx, w); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	waivers, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(waivers) != 1 {
		t.Fatalf("List() got %d waivers, want 1", len(waivers))
	}
	if waivers[0].ID != "W-2026-001" {
		t.Errorf("ID = %q, want W-2026-001", waivers[0].ID)
	}
}

func TestCreateValidation(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	ctx := context.Background()

	tests := []struct {
		name    string
		waiver  schema.Waiver
		wantErr bool
	}{
		{
			name:    "missing approver",
			waiver:  schema.Waiver{ID: "W-1", ControlID: "3.1.1", ExpiresAt: time.Now().AddDate(1, 0, 0)},
			wantErr: true,
		},
		{
			name:    "missing expiry",
			waiver:  schema.Waiver{ID: "W-2", ControlID: "3.1.1", ApprovedBy: "CISO"},
			wantErr: true,
		},
		{
			name:    "missing control ID",
			waiver:  schema.Waiver{ID: "W-3", ApprovedBy: "CISO", ExpiresAt: time.Now().AddDate(1, 0, 0)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.Create(ctx, &tt.waiver)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsWaived(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	ctx := context.Background()

	_ = mgr.Create(ctx, &schema.Waiver{
		ID:         "W-active",
		ControlID:  "3.1.12",
		Scope:      "clean-room",
		ApprovedBy: "CISO",
		ExpiresAt:  time.Now().AddDate(1, 0, 0),
	})

	tests := []struct {
		controlID string
		scope     string
		wantWaived bool
	}{
		{"3.1.12", "clean-room", true},
		{"3.1.12", "", true},       // empty scope matches any
		{"3.1.12", "other-scope", false},
		{"3.1.1", "clean-room", false}, // different control
	}

	for _, tt := range tests {
		w, waived, err := mgr.IsWaived(ctx, tt.controlID, tt.scope)
		if err != nil {
			t.Fatalf("IsWaived() error = %v", err)
		}
		if waived != tt.wantWaived {
			t.Errorf("IsWaived(%q, %q) = %v, want %v", tt.controlID, tt.scope, waived, tt.wantWaived)
		}
		if tt.wantWaived && w == nil {
			t.Error("expected waiver returned, got nil")
		}
	}
}

func TestListExpiring(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)
	ctx := context.Background()

	// One expiring soon, one not.
	_ = mgr.Create(ctx, &schema.Waiver{
		ID: "W-soon", ControlID: "3.1.1", ApprovedBy: "CISO",
		ExpiresAt: time.Now().AddDate(0, 0, 15), // 15 days
	})
	_ = mgr.Create(ctx, &schema.Waiver{
		ID: "W-later", ControlID: "3.1.2", ApprovedBy: "CISO",
		ExpiresAt: time.Now().AddDate(1, 0, 0), // 1 year
	})

	expiring, err := mgr.ListExpiring(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("ListExpiring() error = %v", err)
	}
	if len(expiring) != 1 {
		t.Errorf("ListExpiring() = %d, want 1", len(expiring))
	}
	if len(expiring) > 0 && expiring[0].ID != "W-soon" {
		t.Errorf("expected W-soon expiring, got %s", expiring[0].ID)
	}
}

func TestComputeStatus(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		expiresAt  time.Time
		wantStatus string
	}{
		{"expired", now.AddDate(0, 0, -1), "expired"},
		{"expiring", now.AddDate(0, 0, 15), "expiring"},
		{"active", now.AddDate(1, 0, 0), "active"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := schema.Waiver{ExpiresAt: tt.expiresAt}
			got := computeStatus(w, now)
			if got != tt.wantStatus {
				t.Errorf("computeStatus() = %q, want %q", got, tt.wantStatus)
			}
		})
	}
}
