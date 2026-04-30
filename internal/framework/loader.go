// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package framework loads, validates, and manages compliance framework definitions.
package framework

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/provabl/attest/pkg/schema"
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
	// Validate id before path construction — validate() runs after YAML parsing
	// and checks fw.ID from the file, not the caller-supplied id parameter.
	// Without this check, id = "../other" would traverse outside frameworkDir.
	resolved := filepath.Join(l.frameworkDir, id)
	base, err := filepath.Abs(l.frameworkDir)
	if err != nil {
		return nil, fmt.Errorf("resolving framework dir: %w", err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return nil, fmt.Errorf("resolving framework path: %w", err)
	}
	if !strings.HasPrefix(abs+string(filepath.Separator), base+string(filepath.Separator)) {
		return nil, fmt.Errorf("framework ID %q escapes framework directory", id)
	}

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
// frameworks, separated into three maps by enforcement type.
//
// Structural (SCP): deduplicates by condition fingerprint — two frameworks
// requiring the same deny condition produce one SCP statement.
//
// Operational (Cedar): never deduplicates across frameworks — each
// framework's Cedar policies evaluate independently via default-deny AND
// semantics. Key is frameworkID+controlID to guarantee separation.
//
// Monitoring (Config): deduplicates by resource_type+rule — two frameworks
// checking the same Config rule produce one rule deployment.
func Resolve(frameworks []*schema.Framework) (*ResolvedControlSet, error) {
	rcs := &ResolvedControlSet{
		Structural:  make(map[string][]ResolvedControl),
		Operational: make(map[string][]ResolvedControl),
		Monitoring:  make(map[string][]ResolvedControl),
	}

	for _, fw := range frameworks {
		for _, ctrl := range fw.Controls {
			rc := ResolvedControl{FrameworkID: fw.ID, Control: ctrl}
			if len(ctrl.Structural) > 0 {
				key := structuralKey(ctrl)
				rcs.Structural[key] = append(rcs.Structural[key], rc)
			}
			if len(ctrl.Operational) > 0 {
				// Operational specs never deduplicate across frameworks.
				// Cedar's default-deny model requires both frameworks' policies
				// to independently permit — AND semantics, not OR.
				key := fw.ID + "/" + ctrl.ID
				rcs.Operational[key] = append(rcs.Operational[key], rc)
			}
			if len(ctrl.Monitoring) > 0 {
				key := monitoringKey(ctrl)
				rcs.Monitoring[key] = append(rcs.Monitoring[key], rc)
			}
		}
	}
	return rcs, nil
}

// ResolvedControlSet holds the deduplicated controls across all active frameworks,
// separated by enforcement type so each compiler accesses only its domain.
type ResolvedControlSet struct {
	// Structural maps condition-fingerprint → controls with Structural (SCP) specs.
	// Two frameworks requiring the same deny condition share one SCP statement.
	Structural map[string][]ResolvedControl

	// Operational maps frameworkID+controlID → controls with Operational (Cedar) specs.
	// Each framework's Cedar policies are kept separate: AND semantics via default-deny.
	Operational map[string][]ResolvedControl

	// Monitoring maps resourceType+ruleID → controls with Monitoring (Config) specs.
	// Two frameworks checking the same resource type/rule share one Config rule.
	Monitoring map[string][]ResolvedControl
}

// ResolvedControl pairs a control with its originating framework.
type ResolvedControl struct {
	FrameworkID string
	Control     schema.Control
}

// structuralKey generates the SCP deduplication key.
// Controls sharing the same structural enforcement spec ID → one SCP statement.
func structuralKey(ctrl schema.Control) string {
	if len(ctrl.Structural) > 0 {
		return ctrl.Structural[0].ID
	}
	return ctrl.Family + "/" + ctrl.ID
}

// monitoringKey generates the Config rule deduplication key.
// Controls checking the same resource type and rule → one Config rule.
func monitoringKey(ctrl schema.Control) string {
	if len(ctrl.Monitoring) > 0 {
		return ctrl.Monitoring[0].ResourceType + "/" + ctrl.Monitoring[0].ID
	}
	return ctrl.Family + "/" + ctrl.ID
}

const (
	maxFrameworkIDLen = 128
	maxControlIDLen   = 64
	maxControlTitleLen = 512
	maxControls        = 10_000
)

func validate(fw *schema.Framework) error {
	if fw.ID == "" {
		return fmt.Errorf("framework ID is required")
	}
	if len(fw.ID) > maxFrameworkIDLen {
		return fmt.Errorf("framework ID too long (max %d chars)", maxFrameworkIDLen)
	}
	// Enforce strict ASCII lowercase + hyphen character set on framework IDs.
	// This prevents Unicode homoglyph attacks that could bypass conflict detection
	// (e.g., Cyrillic "ітар" bypassing detection of "itar").
	for _, r := range fw.ID {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return fmt.Errorf("framework ID %q contains invalid character %q (allowed: a-z 0-9 - _)", fw.ID, r)
		}
	}
	if len(fw.Controls) == 0 {
		return fmt.Errorf("framework must define at least one control")
	}
	if len(fw.Controls) > maxControls {
		return fmt.Errorf("framework has too many controls (%d, max %d)", len(fw.Controls), maxControls)
	}
	for _, ctrl := range fw.Controls {
		if ctrl.ID == "" {
			return fmt.Errorf("control ID is required")
		}
		if len(ctrl.ID) > maxControlIDLen {
			return fmt.Errorf("control ID %q too long (max %d)", ctrl.ID, maxControlIDLen)
		}
		if len(ctrl.Title) > maxControlTitleLen {
			return fmt.Errorf("control %s title too long (max %d chars)", ctrl.ID, maxControlTitleLen)
		}
	}
	return nil
}
