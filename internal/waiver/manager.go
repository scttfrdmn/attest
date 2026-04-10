// Package waiver manages compliance exceptions. Real compliance has
// exceptions — the waiver is a first-class object: time-bounded, scoped,
// approved, documented. It affects posture scoring, SSP narratives,
// Cedar evaluation (waived operations record the waiver ID), and the
// dashboard (expiring waivers alert).
package waiver

import (
	"context"
	"fmt"
	"time"

	"github.com/scttfrdmn/attest/pkg/schema"
)

// Manager handles waiver lifecycle: create, list, expire, and evaluate.
type Manager struct {
	storePath string // .attest/waivers/
}

// NewManager creates a waiver manager.
func NewManager(storePath string) *Manager {
	return &Manager{storePath: storePath}
}

// Create records a new waiver. The waiver must have an approver and expiry date.
func (m *Manager) Create(ctx context.Context, waiver *schema.Waiver) error {
	if waiver.ApprovedBy == "" {
		return fmt.Errorf("waiver must have an approver")
	}
	if waiver.ExpiresAt.IsZero() {
		return fmt.Errorf("waiver must have an expiry date")
	}
	// TODO: Write to .attest/waivers/<id>.yaml, commit to git store.
	return fmt.Errorf("not implemented")
}

// List returns all active waivers, optionally filtered.
func (m *Manager) List(ctx context.Context) ([]schema.Waiver, error) {
	return nil, fmt.Errorf("not implemented")
}

// ListExpiring returns waivers expiring within the given window.
func (m *Manager) ListExpiring(ctx context.Context, within time.Duration) ([]schema.Waiver, error) {
	return nil, fmt.Errorf("not implemented")
}

// IsWaived checks whether a control has an active waiver for the given scope.
func (m *Manager) IsWaived(ctx context.Context, controlID, scope string) (*schema.Waiver, bool, error) {
	return nil, false, fmt.Errorf("not implemented")
}
