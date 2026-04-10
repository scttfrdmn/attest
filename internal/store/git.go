// Package store manages the git-backed policy store in .attest/.
// Every `attest compile` commits. Every `attest apply` can tag.
// The git log is the change management record an auditor verifies.
//
// Layout:
//
//	.attest/
//	├── sre.yaml              # SRE definition
//	├── compiled/
//	│   ├── scps/             # Generated SCP JSON files
//	│   ├── cedar/            # Generated Cedar policies
//	│   ├── config/           # Generated Config rules
//	│   ├── crosswalk.yaml    # Control → artifact mapping
//	│   └── terraform/        # IaC output (if --output terraform)
//	├── proposed/             # AI-generated artifacts awaiting review
//	├── waivers/              # Active waivers
//	├── history/              # Posture snapshots for trend analysis
//	└── documents/            # Generated SSP, POA&M, OSCAL
package store

import (
	"fmt"
)

// Store manages the .attest/ directory and its git lifecycle.
type Store struct {
	root string // path to .attest/
}

// NewStore opens or initializes the policy store at the given path.
func NewStore(root string) (*Store, error) {
	return &Store{root: root}, nil
}

// Commit creates a git commit in the store with the given message.
func (s *Store) Commit(message string) error {
	return fmt.Errorf("not implemented")
}

// Tag creates a git tag (e.g., "assessment-2025-q1").
func (s *Store) Tag(name, message string) error {
	return fmt.Errorf("not implemented")
}

// Diff returns the changes between two refs (tags or commits).
func (s *Store) Diff(from, to string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

// AcceptProposed moves a proposed artifact into the compiled set.
func (s *Store) AcceptProposed(name string) error {
	return fmt.Errorf("not implemented")
}
