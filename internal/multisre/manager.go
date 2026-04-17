// Package multisre manages compliance across multiple AWS Organizations (SREs).
// An institution may operate several SREs: production, dev, partner networks.
// Multi-SRE provides a single compliance registry and aggregate posture view.
//
// Registry file: .attest/sres.yaml
// Per-SRE store: .attest/<id>/  (separate git store per SRE)
package multisre

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// isValidOrgID validates an AWS Organizations ID.
// AWS format: o- followed by lowercase alphanumeric chars, min 2 chars after prefix.
// Also prevents markdown injection when OrgIDs are embedded in generated reports
// (rejects `]`, `[`, `<`, `>`, quotes, and other HTML/markdown metacharacters).
func isValidOrgID(id string) bool {
	if len(id) < 4 || len(id) > 36 {
		return false
	}
	if len(id) < 2 || id[0] != 'o' || id[1] != '-' {
		return false
	}
	for _, r := range id[2:] {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// IsValidSREID reports whether an SRE ID is safe for use in file paths.
// Allows only alphanumeric, hyphen, and underscore (max 64 chars).
// Exported so CLI commands can validate --from/--to flags before reaching StoreDir.
func IsValidSREID(id string) bool {
	return isValidSREID(id)
}

// isValidSREID is the internal implementation.
func isValidSREID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// SREEntry is a registered AWS Organization in the multi-SRE registry.
type SREEntry struct {
	ID         string   `yaml:"id"`         // e.g., "production"
	OrgID      string   `yaml:"org_id"`     // e.g., "o-pygqyjjoym"
	Region     string   `yaml:"region"`     // e.g., "us-east-1"
	Profile    string   `yaml:"profile"`    // AWS CLI profile
	Frameworks []string `yaml:"frameworks"` // active framework IDs
	Notes      string   `yaml:"notes,omitempty"`
}

// Registry is the multi-SRE configuration file (.attest/sres.yaml).
type Registry struct {
	SREs []SREEntry `yaml:"sres"`
}

// SREPosture is the scanned posture for a single SRE.
type SREPosture struct {
	ID       string
	OrgID    string
	Score    int
	MaxScore int
	Enforced int
	Partial  int
	Gaps     int
	Error    string // non-empty if scan failed
}

// Manager manages the multi-SRE registry.
type Manager struct {
	registryPath string // .attest/sres.yaml
	storeRoot    string // .attest/
}

// NewManager creates a manager rooted at the given .attest/ directory.
func NewManager(storeRoot string) *Manager {
	return &Manager{
		registryPath: filepath.Join(storeRoot, "sres.yaml"),
		storeRoot:    storeRoot,
	}
}

// Load reads the registry file. Returns an empty registry if the file doesn't exist yet.
func (m *Manager) Load() (*Registry, error) {
	data, err := os.ReadFile(m.registryPath)
	if os.IsNotExist(err) {
		return &Registry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", m.registryPath, err)
	}
	var reg Registry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parsing registry: %w", err)
	}
	return &reg, nil
}

// Save writes the registry to disk.
func (m *Manager) Save(reg *Registry) error {
	if err := os.MkdirAll(filepath.Dir(m.registryPath), 0750); err != nil {
		return err
	}
	data, err := yaml.Marshal(reg)
	if err != nil {
		return fmt.Errorf("marshaling registry: %w", err)
	}
	return os.WriteFile(m.registryPath, data, 0640)
}

// Add registers a new SRE. Returns an error if the ID already exists.
func (m *Manager) Add(entry SREEntry) error {
	if entry.ID == "" {
		return fmt.Errorf("SRE ID is required")
	}
	// Validate ID to prevent path traversal via StoreDir().
	// Only alphanumeric, hyphen, underscore allowed — no ., /, \, or ..'
	if !isValidSREID(entry.ID) {
		return fmt.Errorf("invalid SRE ID %q: must be alphanumeric, hyphen, or underscore (max 64 chars)", entry.ID)
	}
	if entry.OrgID == "" {
		return fmt.Errorf("org_id is required")
	}
	// Validate OrgID matches AWS Organizations format: o-[a-z0-9]{10,32}
	// This also prevents markdown injection when OrgID is embedded in reports.
	if !isValidOrgID(entry.OrgID) {
		return fmt.Errorf("invalid org_id %q: must match AWS format o-[a-z0-9]{10,32}", entry.OrgID)
	}
	if entry.Region == "" {
		entry.Region = "us-east-1"
	}

	reg, err := m.Load()
	if err != nil {
		return err
	}
	for _, e := range reg.SREs {
		if e.ID == entry.ID {
			return fmt.Errorf("SRE %q already registered — use 'attest sre remove %s' first", entry.ID, entry.ID)
		}
	}
	reg.SREs = append(reg.SREs, entry)
	return m.Save(reg)
}

// Remove deregisters an SRE by ID (does not delete its .attest/<id>/ directory).
func (m *Manager) Remove(id string) error {
	reg, err := m.Load()
	if err != nil {
		return err
	}
	n := 0
	for _, e := range reg.SREs {
		if e.ID != id {
			reg.SREs[n] = e
			n++
		}
	}
	if n == len(reg.SREs) {
		return fmt.Errorf("SRE %q not found in registry", id)
	}
	reg.SREs = reg.SREs[:n]
	return m.Save(reg)
}

// Get returns a single SRE entry by ID.
func (m *Manager) Get(id string) (*SREEntry, error) {
	reg, err := m.Load()
	if err != nil {
		return nil, err
	}
	for _, e := range reg.SREs {
		if e.ID == id {
			eCopy := e
			return &eCopy, nil
		}
	}
	return nil, fmt.Errorf("SRE %q not registered — use 'attest sre add'", id)
}

// List returns all registered SREs.
func (m *Manager) List() ([]SREEntry, error) {
	reg, err := m.Load()
	if err != nil {
		return nil, err
	}
	return reg.SREs, nil
}

// StoreDir returns the per-SRE .attest/ directory path.
// SAFETY: id must have been validated with isValidSREID() before calling this
// (enforced by Add()). The ".sre-" prefix prevents collision with reserved names.
func (m *Manager) StoreDir(id string) string {
	return filepath.Join(m.storeRoot, ".sre-"+id)
}

// ScanAll scans all registered SREs concurrently, reading their compiled
// crosswalks for posture data. Returns one SREPosture per SRE.
func (m *Manager) ScanAll(scanFn func(entry SREEntry, storeDir string) (*SREPosture, error)) ([]SREPosture, error) {
	reg, err := m.Load()
	if err != nil {
		return nil, err
	}
	if len(reg.SREs) == 0 {
		return nil, fmt.Errorf("no SREs registered — use 'attest sre add'")
	}

	results := make([]SREPosture, len(reg.SREs))
	var wg sync.WaitGroup
	// SAFETY: Each goroutine writes to a distinct index (i) of results[].
	// The index is passed as an explicit argument — not captured from the loop —
	// so there is no closure race. Do NOT refactor to capture i from the outer loop.
	for i, entry := range reg.SREs {
		wg.Add(1)
		go func(i int, entry SREEntry) {
			defer wg.Done()
			storeDir := m.StoreDir(entry.ID)
			posture, err := scanFn(entry, storeDir)
			if err != nil {
				results[i] = SREPosture{ID: entry.ID, OrgID: entry.OrgID, Error: err.Error()}
			} else {
				results[i] = *posture
			}
		}(i, entry)
	}
	wg.Wait()
	return results, nil
}

// AggregatePosture sums posture across all scanned SREs.
func AggregatePosture(postures []SREPosture) SREPosture {
	agg := SREPosture{ID: "aggregate"}
	for _, p := range postures {
		if p.Error != "" {
			continue
		}
		agg.Score += p.Score
		agg.MaxScore += p.MaxScore
		agg.Enforced += p.Enforced
		agg.Partial += p.Partial
		agg.Gaps += p.Gaps
	}
	return agg
}
