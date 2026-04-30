// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package reporting contains trend analysis and incident lifecycle management.
// Incident records are stored in .attest/history/incidents.yaml and tracked
// through detection → remediation → resolution.
package reporting

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Incident tracks a security or compliance event and its lifecycle.
type Incident struct {
	ID         string     `yaml:"id"`
	Title      string     `yaml:"title"`
	DetectedAt time.Time  `yaml:"detected_at"`
	ResolvedAt *time.Time `yaml:"resolved_at,omitempty"`
	ControlIDs []string   `yaml:"control_ids,omitempty"`
	Severity   string     `yaml:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Source     string     `yaml:"source"`   // "guardduty", "cedar-denial", "manual"
	Status     string     `yaml:"status"`   // "open", "resolved", "accepted"
	Notes      string     `yaml:"notes,omitempty"`
}

// IncidentManager manages incident records stored in the .attest/history/ directory.
type IncidentManager struct {
	dir string
}

// NewIncidentManager creates a manager rooted at the given directory
// (typically ".attest/history").
func NewIncidentManager(dir string) *IncidentManager {
	return &IncidentManager{dir: dir}
}

func (m *IncidentManager) path() string {
	return filepath.Join(m.dir, "incidents.yaml")
}

// List returns all incidents, most-recent first.
func (m *IncidentManager) List() ([]*Incident, error) {
	data, err := os.ReadFile(m.path())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading incidents: %w", err)
	}
	var incidents []*Incident
	if err := yaml.Unmarshal(data, &incidents); err != nil {
		return nil, fmt.Errorf("parsing incidents: %w", err)
	}
	return incidents, nil
}

// Create records a new incident and saves it.
const (
	maxIncidentTitleLen    = 512
	maxIncidentNotesLen    = 10_000
	maxIncidentControlIDs  = 100
)

func (m *IncidentManager) Create(title, severity, source, notes string, controlIDs []string) (*Incident, error) {
	if len(title) > maxIncidentTitleLen {
		return nil, fmt.Errorf("incident title too long (max %d chars)", maxIncidentTitleLen)
	}
	if len(notes) > maxIncidentNotesLen {
		return nil, fmt.Errorf("incident notes too long (max %d chars)", maxIncidentNotesLen)
	}
	if len(controlIDs) > maxIncidentControlIDs {
		return nil, fmt.Errorf("too many control IDs (max %d)", maxIncidentControlIDs)
	}
	incidents, err := m.List()
	if err != nil {
		return nil, err
	}
	inc := &Incident{
		ID:         fmt.Sprintf("INC-%04d", len(incidents)+1),
		Title:      title,
		DetectedAt: time.Now().UTC(),
		Severity:   severity,
		Source:     source,
		Status:     "open",
		Notes:      notes,
		ControlIDs: controlIDs,
	}
	incidents = append([]*Incident{inc}, incidents...)
	return inc, m.save(incidents)
}

// Resolve marks an incident as resolved.
func (m *IncidentManager) Resolve(id, notes string) error {
	if len(notes) > maxIncidentNotesLen {
		return fmt.Errorf("incident notes too long (max %d chars)", maxIncidentNotesLen)
	}
	incidents, err := m.List()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, inc := range incidents {
		if inc.ID == id {
			inc.Status = "resolved"
			inc.ResolvedAt = &now
			if notes != "" {
				inc.Notes = notes
			}
			return m.save(incidents)
		}
	}
	return fmt.Errorf("incident %s not found", id)
}

func (m *IncidentManager) save(incidents []*Incident) error {
	if err := os.MkdirAll(m.dir, 0750); err != nil {
		return err
	}
	data, err := yaml.Marshal(incidents)
	if err != nil {
		return fmt.Errorf("marshaling incidents: %w", err)
	}
	return os.WriteFile(m.path(), data, 0640)
}
