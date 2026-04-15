// Package waiver manages compliance exceptions. Real compliance has
// exceptions — the waiver is a first-class object: time-bounded, scoped,
// approved, auditable. It affects posture scoring, SSP narratives, and
// Cedar evaluation (waived operations record the waiver ID).
package waiver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/scttfrdmn/attest/pkg/schema"
)

// Manager handles waiver lifecycle: create, list, expire.
type Manager struct {
	storePath string // .attest/waivers/
}

// NewManager creates a waiver manager.
func NewManager(storePath string) *Manager {
	return &Manager{storePath: storePath}
}

// Create records a new waiver.
// Validates required fields (ApprovedBy, ExpiresAt) before writing.
func (m *Manager) Create(ctx context.Context, w *schema.Waiver) error {
	if w.ApprovedBy == "" {
		return fmt.Errorf("waiver must have an approver (--approved-by)")
	}
	if w.ExpiresAt.IsZero() {
		return fmt.Errorf("waiver must have an expiry date (--expires)")
	}
	if w.ID == "" {
		return fmt.Errorf("waiver must have an ID")
	}
	if w.ControlID == "" {
		return fmt.Errorf("waiver must specify a control ID (--control)")
	}

	w.ApprovedAt = time.Now()
	w.Status = "active"

	if err := os.MkdirAll(m.storePath, 0750); err != nil {
		return fmt.Errorf("creating waivers directory: %w", err)
	}

	data, err := yaml.Marshal(w)
	if err != nil {
		return fmt.Errorf("marshaling waiver: %w", err)
	}

	path := filepath.Join(m.storePath, w.ID+".yaml")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing waiver %s: %w", w.ID, err)
	}
	return nil
}

// List returns all waivers sorted by expiry date.
func (m *Manager) List(ctx context.Context) ([]schema.Waiver, error) {
	entries, err := os.ReadDir(m.storePath)
	if os.IsNotExist(err) {
		return nil, nil // No waivers yet.
	}
	if err != nil {
		return nil, fmt.Errorf("reading waivers directory: %w", err)
	}

	var waivers []schema.Waiver
	now := time.Now()

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.storePath, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading waiver %s: %w", e.Name(), err)
		}
		var w schema.Waiver
		if err := yaml.Unmarshal(data, &w); err != nil {
			return nil, fmt.Errorf("parsing waiver %s: %w", e.Name(), err)
		}
		// Refresh status based on current time.
		w.Status = computeStatus(w, now)
		waivers = append(waivers, w)
	}

	sort.Slice(waivers, func(i, j int) bool {
		return waivers[i].ExpiresAt.Before(waivers[j].ExpiresAt)
	})
	return waivers, nil
}

// ListExpiring returns waivers expiring within the given duration.
func (m *Manager) ListExpiring(ctx context.Context, within time.Duration) ([]schema.Waiver, error) {
	all, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(within)
	var expiring []schema.Waiver
	for _, w := range all {
		// Include both "active" and "expiring" waivers that haven't yet expired
		// and will expire within the window.
		if w.Status != "expired" && w.ExpiresAt.Before(cutoff) {
			expiring = append(expiring, w)
		}
	}
	return expiring, nil
}

// IsWaived returns the active waiver for a control/scope pair, if one exists.
// If scope is empty, matches any waiver for the control.
func (m *Manager) IsWaived(ctx context.Context, controlID, scope string) (*schema.Waiver, bool, error) {
	waivers, err := m.List(ctx)
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	for _, w := range waivers {
		if w.ControlID != controlID {
			continue
		}
		if w.ExpiresAt.Before(now) {
			continue
		}
		if scope != "" && w.Scope != "" && w.Scope != scope {
			continue
		}
		copy := w
		return &copy, true, nil
	}
	return nil, false, nil
}

// Expire marks a waiver as expired by updating its status and ExpiresAt.
func (m *Manager) Expire(ctx context.Context, waiverID string) error {
	path := filepath.Join(m.storePath, waiverID+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("waiver %s not found: %w", waiverID, err)
	}
	var w schema.Waiver
	if err := yaml.Unmarshal(data, &w); err != nil {
		return err
	}
	w.Status = "expired"
	w.ExpiresAt = time.Now()

	updated, err := yaml.Marshal(w)
	if err != nil {
		return err
	}
	return os.WriteFile(path, updated, 0644)
}

// computeStatus returns the current status of a waiver based on time.
func computeStatus(w schema.Waiver, now time.Time) string {
	if w.ExpiresAt.Before(now) {
		return "expired"
	}
	if w.ExpiresAt.Before(now.Add(30 * 24 * time.Hour)) {
		return "expiring"
	}
	return "active"
}
