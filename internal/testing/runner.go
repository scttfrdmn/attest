// Package testing provides policy testing capabilities:
//   - Unit tests: define scenarios in YAML, run locally against cedar-go
//   - Terraform CI checks: evaluate Terraform plan JSON for compliance violations
//
// Simulation (replay real CloudTrail events) is deferred to v0.5.0 as it
// requires CloudTrail Lake access.
package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/provabl/attest/pkg/schema"
)

// Runner executes policy test suites against cedar-go locally.
// No AWS access required — tests run against compiled Cedar policies.
type Runner struct {
	cedarDir string // path to compiled Cedar policies (default: .attest/compiled/cedar)
}

// NewRunner creates a policy test runner.
func NewRunner(cedarDir string) *Runner {
	if cedarDir == "" {
		cedarDir = filepath.Join(".attest", "compiled", "cedar")
	}
	return &Runner{cedarDir: cedarDir}
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
	PolicyID    string
}

// RunSuite executes a test suite against the compiled Cedar policies.
func (r *Runner) RunSuite(ctx context.Context, suite *schema.PolicyTestSuite) (*SuiteResult, error) {
	ps, err := r.loadPolicies()
	if err != nil {
		return nil, fmt.Errorf("loading Cedar policies from %s: %w", r.cedarDir, err)
	}

	result := &SuiteResult{Name: suite.Name, Total: len(suite.Cases)}

	for _, tc := range suite.Cases {
		cr := r.runCase(ps, tc)
		if cr.Passed {
			result.Passed++
		} else {
			result.Failed++
		}
		result.Cases = append(result.Cases, cr)
	}

	return result, nil
}

// runCase evaluates a single test case against the policy set.
func (r *Runner) runCase(ps *cedar.PolicySet, tc schema.PolicyTestCase) CaseResult {
	cr := CaseResult{Description: tc.Description, Expected: tc.Expected}

	// Build entities from the test case.
	entities := types.EntityMap{}

	// Principal entity.
	principalUID := types.NewEntityUID(types.EntityType("Principal"), types.String("test-principal"))
	principalAttrs := mapToRecord(tc.Principal)
	entities[principalUID] = types.Entity{
		UID:        principalUID,
		Attributes: principalAttrs,
	}

	// Resource entity.
	resourceUID := types.NewEntityUID(types.EntityType("Resource"), types.String("test-resource"))
	resourceAttrs := mapToRecord(tc.Resource)
	entities[resourceUID] = types.Entity{
		UID:        resourceUID,
		Attributes: resourceAttrs,
	}

	// Action entity.
	actionUID := types.NewEntityUID(types.EntityType("Action"), types.String(tc.Action))
	entities[actionUID] = types.Entity{
		UID: actionUID,
	}

	req := types.Request{
		Principal: principalUID,
		Action:    actionUID,
		Resource:  resourceUID,
	}

	decision, diag := cedar.Authorize(ps, entities, req)

	var actual string
	if decision == types.Decision(true) {
		actual = "ALLOW"
	} else {
		actual = "DENY"
	}

	cr.Actual = actual
	cr.Passed = actual == tc.Expected

	// Extract policy ID from diagnostics if available.
	if len(diag.Reasons) > 0 {
		var policyIDs []string
		for _, r := range diag.Reasons {
			policyIDs = append(policyIDs, string(r.PolicyID))
		}
		cr.PolicyID = strings.Join(policyIDs, ", ")
	}

	return cr
}

// loadPolicies reads all .cedar files from the Cedar directory.
func (r *Runner) loadPolicies() (*cedar.PolicySet, error) {
	entries, err := os.ReadDir(r.cedarDir)
	if os.IsNotExist(err) {
		return cedar.NewPolicySet(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading Cedar directory: %w", err)
	}

	ps := cedar.NewPolicySet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cedar") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(r.cedarDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		parsed, err := cedar.NewPolicySetFromBytes(e.Name(), data)
		if err != nil {
			// Skip policies that don't parse cleanly (e.g., placeholder text).
			continue
		}
		// Merge the parsed policies into the main policy set.
		for policyID, policy := range parsed.Map() {
			ps.Add(policyID, policy)
		}
	}
	return ps, nil
}

// mapToRecord converts a map[string]any test case attribute map to a cedar Record.
func mapToRecord(m map[string]any) types.Record {
	rm := types.RecordMap{}
	for k, v := range m {
		rm[types.String(k)] = anyToCedarValue(v)
	}
	return types.NewRecord(rm)
}

// anyToCedarValue converts a Go value to a Cedar Value.
func anyToCedarValue(v any) types.Value {
	switch val := v.(type) {
	case bool:
		return types.Boolean(val)
	case string:
		return types.String(val)
	case int:
		return types.Long(val)
	case int64:
		return types.Long(val)
	case float64:
		return types.Long(int64(val))
	default:
		return types.String(fmt.Sprintf("%v", v))
	}
}

// --- Terraform CI checker ---

// TerraformChecker evaluates a Terraform plan JSON for compliance violations.
// Output is in text format with SARIF available for GitHub annotation.
type TerraformChecker struct {
	crosswalkPath string
}

// NewTerraformChecker creates a Terraform compliance checker.
func NewTerraformChecker(crosswalkPath string) *TerraformChecker {
	if crosswalkPath == "" {
		crosswalkPath = filepath.Join(".attest", "compiled", "crosswalk.yaml")
	}
	return &TerraformChecker{crosswalkPath: crosswalkPath}
}

// CheckResult is the output of a Terraform compliance check.
type CheckResult struct {
	Passed     bool
	Violations []Violation
}

// Violation is a potential compliance issue in a Terraform plan.
type Violation struct {
	Resource  string
	Change    string
	ControlID string
	PolicyID  string
	Message   string
}

// tfPlan is the minimal Terraform plan JSON structure we need.
type tfPlan struct {
	PlannedValues struct {
		RootModule struct {
			Resources []struct {
				Type   string         `json:"type"`
				Name   string         `json:"name"`
				Values map[string]any `json:"values"`
			} `json:"resources"`
		} `json:"root_module"`
	} `json:"planned_values"`
}

// Check evaluates a Terraform plan JSON for compliance violations.
// Heuristically checks resource changes against SCP actions in the crosswalk.
func (tc *TerraformChecker) Check(ctx context.Context, planPath string) (*CheckResult, error) {
	data, err := os.ReadFile(planPath)
	if err != nil {
		return nil, fmt.Errorf("reading Terraform plan %s: %w", planPath, err)
	}

	var plan tfPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("parsing Terraform plan: %w", err)
	}

	result := &CheckResult{Passed: true}

	for _, resource := range plan.PlannedValues.RootModule.Resources {
		// Check for public access patterns.
		if vals, ok := resource.Values["associate_public_ip_address"]; ok {
			if b, ok := vals.(bool); ok && b {
				result.Violations = append(result.Violations, Violation{
					Resource:  resource.Type + "." + resource.Name,
					Change:    "associate_public_ip_address = true",
					ControlID: "3.13.1",
					PolicyID:  "scp-deny-public-access",
					Message:   "Public IP association violates SRE boundary policy (3.13.1)",
				})
			}
		}
		// Check for unencrypted storage.
		if enc, ok := resource.Values["encrypted"]; ok {
			if b, ok := enc.(bool); ok && !b {
				result.Violations = append(result.Violations, Violation{
					Resource:  resource.Type + "." + resource.Name,
					Change:    "encrypted = false",
					ControlID: "3.13.16",
					PolicyID:  "scp-require-kms-encryption",
					Message:   "Unencrypted storage violates CUI encryption policy (3.13.16)",
				})
			}
		}
	}

	if len(result.Violations) > 0 {
		result.Passed = false
	}
	return result, nil
}

// SARIF produces a SARIF JSON string from the check result.
func (r *CheckResult) SARIF() string {
	type sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID  string          `json:"ruleId"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	type sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []sarifResult `json:"results"`
		} `json:"runs"`
	}

	s := sarif{Version: "2.1.0"}
	run := struct {
		Results []sarifResult `json:"results"`
	}{}
	for _, v := range r.Violations {
		sr := sarifResult{RuleID: v.PolicyID}
		sr.Message.Text = v.Message
		run.Results = append(run.Results, sr)
	}
	s.Runs = append(s.Runs, run)
	b, _ := json.MarshalIndent(s, "", "  ")
	return string(b)
}
