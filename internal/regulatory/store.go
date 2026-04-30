// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package regulatory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Store persists regulatory notices and tracks which have been processed.
// All data is written to .attest/regulatory/.
type Store struct {
	dir string
}

// NewStore creates a Store rooted at dir (typically ".attest/regulatory").
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

// DefaultStore returns a Store at the default .attest/regulatory path.
func DefaultStore() *Store {
	return NewStore(filepath.Join(".attest", "regulatory")) // nosemgrep: semgrep.attest-filepath-join-no-confinement — hardcoded path
}

type processedFile struct {
	Processed []processedEntry `yaml:"processed"`
}

type processedEntry struct {
	ID          string    `yaml:"id"`
	ProcessedAt time.Time `yaml:"processed_at"`
	Relevant    bool      `yaml:"relevant"`
}

// IsProcessed returns true if the notice with this ID has already been analyzed.
func (s *Store) IsProcessed(id string) bool {
	pf, err := s.loadProcessed()
	if err != nil {
		return false
	}
	for _, e := range pf.Processed {
		if e.ID == id {
			return true
		}
	}
	return false
}

// MarkProcessed records that this notice ID has been analyzed.
func (s *Store) MarkProcessed(id string, relevant bool) error {
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return err
	}
	pf, _ := s.loadProcessed()
	pf.Processed = append(pf.Processed, processedEntry{
		ID:          id,
		ProcessedAt: time.Now(),
		Relevant:    relevant,
	})
	data, err := yaml.Marshal(pf)
	if err != nil {
		return fmt.Errorf("marshal processed: %w", err)
	}
	return os.WriteFile(filepath.Join(s.dir, "processed.yaml"), data, 0o640)
}

// SaveNotice writes a notice and its analysis result to the notices/ directory.
func (s *Store) SaveNotice(n Notice, r *RelevanceResult) error {
	noticesDir := filepath.Join(s.dir, "notices")
	if err := os.MkdirAll(noticesDir, 0o750); err != nil {
		return err
	}

	record := struct {
		Notice          Notice          `yaml:"notice"`
		RelevanceResult *RelevanceResult `yaml:"analysis,omitempty"`
	}{Notice: n, RelevanceResult: r}

	data, err := yaml.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal notice: %w", err)
	}

	date := n.PublishedAt.Format("2006-01-02")
	safeID := sanitizeFilename(n.ID)
	filename := filepath.Join(noticesDir, date+"-"+safeID+".yaml")
	return os.WriteFile(filename, data, 0o640)
}

func (s *Store) loadProcessed() (processedFile, error) {
	var pf processedFile
	data, err := os.ReadFile(filepath.Join(s.dir, "processed.yaml"))
	if os.IsNotExist(err) {
		return pf, nil
	}
	if err != nil {
		return pf, err
	}
	return pf, yaml.Unmarshal(data, &pf)
}

// sanitizeFilename removes characters unsafe for filenames.
func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	result := b.String()
	if len(result) > 64 {
		result = result[:64]
	}
	return result
}
