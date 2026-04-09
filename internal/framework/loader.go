// Package framework loads, validates, and manages compliance framework definitions.
package framework

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/scttfrdmn/attest/pkg/schema"
	"gopkg.in/yaml.v3"
)

// Loader reads framework definitions from the frameworks/ directory
// and enriches them with Artifact-sourced shared responsibility data.
type Loader struct {
	frameworkDir string
}

// NewLoader creates a framework loader.
func NewLoader(frameworkDir string) *Loader {
	return &Loader{frameworkDir: frameworkDir}
}

// Load reads a single framework definition by ID.
func (l *Loader) Load(id string) (*schema.Framework, error) {
	path := filepath.Join(l.frameworkDir, id, "framework.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading framework %s: %w", id, err)
	}

	var fw schema.Framework
	if err := yaml.Unmarshal(data, &fw); err != nil {
		return nil, fmt.Errorf("parsing framework %s: %w", id, err)
	}

	if err := validate(&fw); err != nil {
		return nil, fmt.Errorf("validating framework %s: %w", id, err)
	}
	return &fw, nil
}

// LoadAll reads all framework definitions in the directory.
func (l *Loader) LoadAll() ([]*schema.Framework, error) {
	entries, err := os.ReadDir(l.frameworkDir)
	if err != nil {
		return nil, err
	}

	var frameworks []*schema.Framework
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		fw, err := l.Load(e.Name())
		if err != nil {
			return nil, err
		}
		frameworks = append(frameworks, fw)
	}
	return frameworks, nil
}

// Resolve computes the effective control set for a given set of active
// frameworks. Handles cross-framework overlap (e.g., HIPAA and 800-171
// both require encryption at rest — emit one SCP, map to both controls).
func Resolve(frameworks []*schema.Framework) (*ResolvedControlSet, error) {
	rcs := &ResolvedControlSet{
		Controls: make(map[string][]ResolvedControl),
	}

	for _, fw := range frameworks {
		for _, ctrl := range fw.Controls {
			key := deduplicationKey(ctrl)
			rcs.Controls[key] = append(rcs.Controls[key], ResolvedControl{
				FrameworkID: fw.ID,
				Control:     ctrl,
			})
		}
	}
	return rcs, nil
}

// ResolvedControlSet is the deduplicated set of controls across all active frameworks.
type ResolvedControlSet struct {
	// Controls maps a deduplication key → list of controls that share enforcement.
	// Multiple framework controls can map to the same enforcement artifact.
	Controls map[string][]ResolvedControl
}

// ResolvedControl pairs a control with its originating framework.
type ResolvedControl struct {
	FrameworkID string
	Control     schema.Control
}

// deduplicationKey generates a key for grouping controls that share enforcement.
// Controls requiring the same SCP/Cedar policy across frameworks get one artifact.
func deduplicationKey(ctrl schema.Control) string {
	// Simplified: use first structural enforcement ID if present,
	// otherwise family + control ID.
	if len(ctrl.Structural) > 0 {
		return ctrl.Structural[0].ID
	}
	return ctrl.Family + "/" + ctrl.ID
}

func validate(fw *schema.Framework) error {
	if fw.ID == "" {
		return fmt.Errorf("framework ID is required")
	}
	if len(fw.Controls) == 0 {
		return fmt.Errorf("framework must define at least one control")
	}
	for _, ctrl := range fw.Controls {
		if ctrl.ID == "" {
			return fmt.Errorf("control ID is required")
		}
	}
	return nil
}
