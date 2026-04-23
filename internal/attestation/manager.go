// Package attestation manages human-affirmed compliance attestation records.
// An attestation is a bounded statement that an administrative control is satisfied:
// who affirmed it, when, what evidence, and when it expires.
// Storage: one YAML file per attestation in .attest/attestations/.
package attestation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/provabl/attest/pkg/schema"
)

var safeIDRE = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

// Manager handles attestation lifecycle: create, list, expire.
type Manager struct {
	storePath string // .attest/attestations/
}

// NewManager creates an attestation manager.
func NewManager(storePath string) *Manager {
	return &Manager{storePath: storePath}
}

// Create records a new attestation after validating required fields.
func (m *Manager) Create(ctx context.Context, a *schema.Attestation) error {
	if a.AffirmedBy == "" {
		return fmt.Errorf("attestation must have an affirmer (--affirmed-by)")
	}
	if a.ExpiresAt.IsZero() {
		return fmt.Errorf("attestation must have an expiry date (--expires)")
	}
	if a.ID == "" {
		return fmt.Errorf("attestation must have an ID")
	}
	if !safeIDRE.MatchString(a.ID) {
		return fmt.Errorf("attestation ID %q contains unsafe characters (allowed: a-z A-Z 0-9 - _)", a.ID)
	}
	if a.ControlID == "" {
		return fmt.Errorf("attestation must specify a control ID (--control)")
	}

	a.AffirmedAt = time.Now()
	a.Status = "current"

	if err := os.MkdirAll(m.storePath, 0750); err != nil {
		return fmt.Errorf("creating attestations directory: %w", err)
	}

	data, err := yaml.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshaling attestation: %w", err)
	}

	path := filepath.Join(m.storePath, a.ID+".yaml")
	return os.WriteFile(path, data, 0640)
}

// List returns all attestations sorted by expiry date.
func (m *Manager) List(ctx context.Context) ([]schema.Attestation, error) {
	entries, err := os.ReadDir(m.storePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading attestations directory: %w", err)
	}

	now := time.Now()
	var attestations []schema.Attestation

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.storePath, e.Name()))
		if err != nil {
			return nil, err
		}
		var a schema.Attestation
		if err := yaml.Unmarshal(data, &a); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", e.Name(), err)
		}
		a.Status = computeStatus(a, now)
		attestations = append(attestations, a)
	}

	sort.Slice(attestations, func(i, j int) bool {
		return attestations[i].ExpiresAt.Before(attestations[j].ExpiresAt)
	})
	return attestations, nil
}

// ListExpiring returns attestations expiring within the given duration.
func (m *Manager) ListExpiring(ctx context.Context, within time.Duration) ([]schema.Attestation, error) {
	all, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(within)
	var expiring []schema.Attestation
	for _, a := range all {
		if a.Status != "expired" && a.ExpiresAt.Before(cutoff) {
			expiring = append(expiring, a)
		}
	}
	return expiring, nil
}

// IsAttested checks whether a control has a current (non-expired) attestation.
// Returns the most recently affirmed attestation, or false if none.
func (m *Manager) IsAttested(ctx context.Context, controlID string) (*schema.Attestation, bool, error) {
	all, err := m.List(ctx)
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	for _, a := range all {
		if a.ControlID != controlID {
			continue
		}
		if a.ExpiresAt.Before(now) {
			continue
		}
		copy := a
		return &copy, true, nil
	}
	return nil, false, nil
}

// Expire marks an attestation as expired.
func (m *Manager) Expire(ctx context.Context, attestationID string) error {
	if !safeIDRE.MatchString(attestationID) {
		return fmt.Errorf("attestation ID %q contains unsafe characters", attestationID)
	}
	path := filepath.Join(m.storePath, attestationID+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("attestation %s not found: %w", attestationID, err)
	}
	var a schema.Attestation
	if err := yaml.Unmarshal(data, &a); err != nil {
		return err
	}
	a.Status = "expired"
	a.ExpiresAt = time.Now()
	updated, err := yaml.Marshal(a)
	if err != nil {
		return err
	}
	return os.WriteFile(path, updated, 0640)
}

func computeStatus(a schema.Attestation, now time.Time) string {
	if a.ExpiresAt.Before(now) {
		return "expired"
	}
	if a.ExpiresAt.Before(now.Add(30 * 24 * time.Hour)) {
		return "expiring"
	}
	return "current"
}
