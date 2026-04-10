// Package testing provides policy testing capabilities:
//   - Unit tests: define scenarios in YAML, run locally against cedar-go
//   - Simulation: replay real CloudTrail events against proposed policy changes
//   - CI/CD checks: evaluate Terraform plans for compliance violations
package testing

import (
	"context"
	"fmt"

	"github.com/scttfrdmn/attest/pkg/schema"
)

// Runner executes policy test suites against cedar-go locally.
type Runner struct{}

// NewRunner creates a policy test runner.
func NewRunner() *Runner { return &Runner{} }

// RunSuite executes a test suite and returns results.
func (r *Runner) RunSuite(ctx context.Context, suite *schema.PolicyTestSuite, policies []string) (*SuiteResult, error) {
	return nil, fmt.Errorf("not implemented")
}

// SuiteResult is the outcome of a test suite run.
type SuiteResult struct {
	Name   string
	Total  int
	Passed int
	Failed int
	Cases  []CaseResult
}

// CaseResult is the outcome of a single test case.
type CaseResult struct {
	Description string
	Expected    string
	Actual      string
	Passed      bool
	PolicyID    string // which policy made the decision
}

// Simulator replays CloudTrail events against a proposed policy set
// and diffs the results against current policies.
type Simulator struct{}

// NewSimulator creates a policy simulator.
func NewSimulator() *Simulator { return &Simulator{} }

// Simulate replays events and returns the diff.
func (s *Simulator) Simulate(ctx context.Context, proposedPolicies []string, windowDays int) (*SimulationResult, error) {
	return nil, fmt.Errorf("not implemented")
}

// SimulationResult shows what would change under proposed policies.
type SimulationResult struct {
	EventsReplayed    int
	ChangedDecisions  int
	NewDenials        []SimulatedChange
	NewPermits        []SimulatedChange
}

// SimulatedChange is an operation whose Cedar decision would change.
type SimulatedChange struct {
	Action      string
	Principal   string
	Resource    string
	CurrentEffect  string
	ProposedEffect string
	PolicyID    string
	Impact      string // human-readable impact description
}

// TerraformChecker evaluates a Terraform plan for compliance violations.
type TerraformChecker struct{}

// NewTerraformChecker creates a Terraform compliance checker.
func NewTerraformChecker() *TerraformChecker { return &TerraformChecker{} }

// Check evaluates a Terraform plan JSON against Cedar policies.
// Returns SARIF for GitHub annotation integration.
func (tc *TerraformChecker) Check(ctx context.Context, planPath string) (*CheckResult, error) {
	return nil, fmt.Errorf("not implemented")
}

// CheckResult is the output of a Terraform compliance check.
type CheckResult struct {
	Passed     bool
	Violations []Violation
}

// Violation is a single compliance violation in a Terraform plan.
type Violation struct {
	Resource   string
	Change     string
	ControlID  string
	PolicyID   string
	Message    string
}
