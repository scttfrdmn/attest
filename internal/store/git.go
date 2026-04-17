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
//	│   ├── crosswalk.yaml    # Control → artifact mapping
//	│   └── terraform/        # IaC output (if --output terraform)
//	├── proposed/             # AI-generated artifacts awaiting review
//	├── waivers/              # Active waivers
//	├── history/              # Posture snapshots for trend analysis
//	└── documents/            # Generated SSP, POA&M, OSCAL
package store

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Store manages the .attest/ directory and its git lifecycle.
type Store struct {
	root     string // absolute path to .attest/
	noCommit bool   // skip git operations (e.g., in CI environments without git)
}

// NewStore opens or initializes the policy store at the given path.
// If the directory is not already a git repository, it is initialized.
func NewStore(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0750); err != nil {
		return nil, fmt.Errorf("creating store directory %s: %w", root, err)
	}
	s := &Store{root: root}

	// Initialize git repo if not already present.
	if _, err := os.Stat(filepath.Join(root, ".git")); os.IsNotExist(err) {
		if err := s.git("init"); err != nil {
			// Git not available — run in no-commit mode.
			s.noCommit = true
		} else {
			// Set a default identity so commits don't fail in CI.
			_ = s.git("config", "user.email", "attest@localhost")
			_ = s.git("config", "user.name", "attest")
		}
	}
	return s, nil
}

// NewStoreNoCommit creates a store that skips all git operations.
func NewStoreNoCommit(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0750); err != nil {
		return nil, fmt.Errorf("creating store directory %s: %w", root, err)
	}
	return &Store{root: root, noCommit: true}, nil
}

// Commit stages all changes and creates a commit. A no-op if there are
// no changes to commit or if the store is in no-commit mode.
func (s *Store) Commit(message string) error {
	if s.noCommit {
		return nil
	}
	// Stage all changes.
	if err := s.git("add", "-A"); err != nil {
		return fmt.Errorf("git add: %w", err)
	}
	// Check if there's anything to commit.
	out, err := s.gitOutput("status", "--porcelain")
	if err != nil {
		return fmt.Errorf("git status: %w", err)
	}
	if strings.TrimSpace(out) == "" {
		return nil // Nothing to commit.
	}
	if err := s.git("commit", "-m", message); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	return nil
}

// Tag creates an annotated git tag (e.g., "assessment-2025-q1").
func (s *Store) Tag(name, message string) error {
	if s.noCommit {
		return nil
	}
	if err := s.git("tag", "-a", name, "-m", message); err != nil {
		return fmt.Errorf("git tag %s: %w", name, err)
	}
	return nil
}

// Diff returns the unified diff between two refs (tags, commits, or branches).
// Typical use: s.Diff("assessment-2025-q1", "assessment-2026-q1")
func (s *Store) Diff(from, to string) (string, error) {
	if s.noCommit {
		return "", fmt.Errorf("store is in no-commit mode")
	}
	out, err := s.gitOutput("diff", from+".."+to)
	if err != nil {
		return "", fmt.Errorf("git diff %s..%s: %w", from, to, err)
	}
	return out, nil
}

// ListTags returns all annotated tags in the store, sorted most-recent first.
func (s *Store) ListTags() ([]string, error) {
	if s.noCommit {
		return nil, nil
	}
	out, err := s.gitOutput("tag", "-l", "--sort=-creatordate")
	if err != nil {
		return nil, fmt.Errorf("git tag list: %w", err)
	}
	var tags []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			tags = append(tags, line)
		}
	}
	return tags, nil
}

// Checkout checks out the store to the given tag or ref. Use "main" to return
// to HEAD. This is used by rollback to restore a prior compiled artifact state.
func (s *Store) Checkout(ref string) error {
	if s.noCommit {
		return nil
	}
	if err := s.git("checkout", ref, "--", "."); err != nil {
		return fmt.Errorf("git checkout %s: %w", ref, err)
	}
	return nil
}

// AcceptProposed moves a proposed artifact from .attest/proposed/
// into the appropriate compiled subdirectory and commits.
func (s *Store) AcceptProposed(name string) error {
	src := filepath.Join(s.root, "proposed", name)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("proposed artifact %s not found: %w", name, err)
	}

	// Determine destination by file extension.
	dest := s.compiledDestination(name)
	if err := os.MkdirAll(filepath.Dir(dest), 0750); err != nil {
		return err
	}
	if err := os.Rename(src, dest); err != nil {
		return fmt.Errorf("moving %s to %s: %w", src, dest, err)
	}

	return s.Commit(fmt.Sprintf("store: accept proposed artifact %s", name))
}

// --- helpers ---

// git runs a git command in the store's root directory.
func (s *Store) git(args ...string) error {
	_, err := s.gitOutput(args...)
	return err
}

// gitOutput runs a git command and returns its stdout.
func (s *Store) gitOutput(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", s.root}, args...)...) //nolint:gosec
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// compiledDestination maps a proposed artifact filename to its compiled path.
func (s *Store) compiledDestination(name string) string {
	switch {
	case strings.HasSuffix(name, ".cedar"):
		return filepath.Join(s.root, "compiled", "cedar", name)
	case strings.HasSuffix(name, ".json"):
		return filepath.Join(s.root, "compiled", "scps", name)
	case strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"):
		return filepath.Join(s.root, "compiled", name)
	default:
		return filepath.Join(s.root, "compiled", name)
	}
}
