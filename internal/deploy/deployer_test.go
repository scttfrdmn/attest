package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// mockDeployOrgAPI implements deployOrgAPI for testing.
type mockDeployOrgAPI struct {
	roots          []types.Root
	existingScps   []types.PolicySummary
	attachedToRoot []types.PolicySummary
	policyContent  map[string]string // policyID → content
	createCount    int
	updateCount    int
	attachCount    int
	createErr      error
	updateErr      error
	attachErr      error
}

func (m *mockDeployOrgAPI) ListRoots(_ context.Context, _ *organizations.ListRootsInput, _ ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	return &organizations.ListRootsOutput{Roots: m.roots}, nil
}

func (m *mockDeployOrgAPI) ListPolicies(_ context.Context, _ *organizations.ListPoliciesInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	return &organizations.ListPoliciesOutput{Policies: m.existingScps}, nil
}

func (m *mockDeployOrgAPI) ListPoliciesForTarget(_ context.Context, params *organizations.ListPoliciesForTargetInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	return &organizations.ListPoliciesForTargetOutput{Policies: m.attachedToRoot}, nil
}

func (m *mockDeployOrgAPI) DescribePolicy(_ context.Context, params *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	content := m.policyContent[aws.ToString(params.PolicyId)]
	return &organizations.DescribePolicyOutput{
		Policy: &types.Policy{
			Content:       aws.String(content),
			PolicySummary: &types.PolicySummary{Id: params.PolicyId},
		},
	}, nil
}

func (m *mockDeployOrgAPI) CreatePolicy(_ context.Context, _ *organizations.CreatePolicyInput, _ ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	m.createCount++
	return &organizations.CreatePolicyOutput{
		Policy: &types.Policy{
			PolicySummary: &types.PolicySummary{Id: aws.String("p-new001")},
		},
	}, nil
}

func (m *mockDeployOrgAPI) UpdatePolicy(_ context.Context, _ *organizations.UpdatePolicyInput, _ ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	m.updateCount++
	return &organizations.UpdatePolicyOutput{}, nil
}

func (m *mockDeployOrgAPI) AttachPolicy(_ context.Context, _ *organizations.AttachPolicyInput, _ ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
	if m.attachErr != nil {
		return nil, m.attachErr
	}
	m.attachCount++
	return &organizations.AttachPolicyOutput{}, nil
}

func (m *mockDeployOrgAPI) DetachPolicy(_ context.Context, _ *organizations.DetachPolicyInput, _ ...func(*organizations.Options)) (*organizations.DetachPolicyOutput, error) {
	return &organizations.DetachPolicyOutput{}, nil
}

// writeSCPFixtures writes sample SCP JSON files to a temp directory.
func writeSCPFixtures(t *testing.T, dir string, scps map[string]any) {
	t.Helper()
	for name, policy := range scps {
		data, _ := json.MarshalIndent(policy, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, name+".json"), data, 0644); err != nil {
			t.Fatalf("writing SCP fixture %s: %v", name, err)
		}
	}
}

func sampleSCP(sid string) any {
	return map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{"Sid": sid, "Effect": "Deny", "Action": []string{"*"}, "Resource": "*"},
		},
	}
}

func TestPlanAllNew(t *testing.T) {
	dir := t.TempDir()
	writeSCPFixtures(t, dir, map[string]any{
		"attest-scp-require-mfa": sampleSCP("scp-require-mfa"),
		"attest-scp-deny-root":   sampleSCP("scp-deny-root"),
	})

	mock := &mockDeployOrgAPI{
		roots:        []types.Root{{Id: aws.String("r-test")}},
		existingScps: []types.PolicySummary{},
	}
	d := newDeployerWithSvc(mock, "us-east-1")
	plan, err := d.Plan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if len(plan.ToCreate) != 2 {
		t.Errorf("ToCreate = %d, want 2", len(plan.ToCreate))
	}
	if len(plan.ToUpdate) != 0 {
		t.Errorf("ToUpdate = %d, want 0", len(plan.ToUpdate))
	}
	if plan.RootID != "r-test" {
		t.Errorf("RootID = %q, want r-test", plan.RootID)
	}
}

func TestPlanNoChange(t *testing.T) {
	dir := t.TempDir()
	policy := sampleSCP("scp-require-mfa")
	writeSCPFixtures(t, dir, map[string]any{
		"attest-scp-require-mfa": policy,
	})

	// Existing SCP with same content.
	policyJSON, _ := json.Marshal(policy)
	mock := &mockDeployOrgAPI{
		roots: []types.Root{{Id: aws.String("r-test")}},
		existingScps: []types.PolicySummary{
			{Id: aws.String("p-001"), Name: aws.String("attest-scp-require-mfa")},
		},
		attachedToRoot: []types.PolicySummary{
			{Name: aws.String("attest-scp-require-mfa")},
		},
		policyContent: map[string]string{"p-001": string(policyJSON)},
	}
	d := newDeployerWithSvc(mock, "us-east-1")
	plan, err := d.Plan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if len(plan.NoChange) != 1 {
		t.Errorf("NoChange = %d, want 1", len(plan.NoChange))
	}
	if len(plan.ToCreate)+len(plan.ToUpdate) != 0 {
		t.Errorf("expected no changes, got creates=%d updates=%d", len(plan.ToCreate), len(plan.ToUpdate))
	}
}

func TestPlanContentChanged(t *testing.T) {
	dir := t.TempDir()
	newPolicy := sampleSCP("scp-require-mfa")
	writeSCPFixtures(t, dir, map[string]any{
		"attest-scp-require-mfa": newPolicy,
	})

	// Existing SCP with different content.
	oldPolicy := sampleSCP("scp-require-mfa-old")
	oldJSON, _ := json.Marshal(oldPolicy)
	mock := &mockDeployOrgAPI{
		roots: []types.Root{{Id: aws.String("r-test")}},
		existingScps: []types.PolicySummary{
			{Id: aws.String("p-001"), Name: aws.String("attest-scp-require-mfa")},
		},
		attachedToRoot: []types.PolicySummary{
			{Name: aws.String("attest-scp-require-mfa")},
		},
		policyContent: map[string]string{"p-001": string(oldJSON)},
	}
	d := newDeployerWithSvc(mock, "us-east-1")
	plan, err := d.Plan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if len(plan.ToUpdate) != 1 {
		t.Errorf("ToUpdate = %d, want 1", len(plan.ToUpdate))
	}
}

func TestApplyCreatesAndAttaches(t *testing.T) {
	dir := t.TempDir()
	writeSCPFixtures(t, dir, map[string]any{
		"attest-scp-require-mfa": sampleSCP("scp-require-mfa"),
	})

	mock := &mockDeployOrgAPI{
		roots: []types.Root{{Id: aws.String("r-test")}},
	}
	d := newDeployerWithSvc(mock, "us-east-1")

	plan := &DeployPlan{
		RootID:   "r-test",
		ToCreate: []PlannedSCP{{AttestID: "attest-scp-require-mfa", Action: "create"}},
	}
	if _, err := d.Apply(context.Background(), plan, dir, func(s string) {}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if mock.createCount != 1 {
		t.Errorf("createCount = %d, want 1", mock.createCount)
	}
	if mock.attachCount != 1 {
		t.Errorf("attachCount = %d, want 1", mock.attachCount)
	}
}

func TestContentMatches(t *testing.T) {
	a := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny"}]}`
	b := `{"Version":  "2012-10-17",  "Statement":[{"Effect":"Deny"}]}`
	if !contentMatches(a, b) {
		t.Error("contentMatches() should ignore whitespace differences")
	}

	c := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]}`
	if contentMatches(a, c) {
		t.Error("contentMatches() should detect content differences")
	}
}

func TestDeploySummary(t *testing.T) {
	plan := &DeployPlan{
		RootID:   "r-test",
		ToCreate: []PlannedSCP{{AttestID: "attest-a"}},
		ToUpdate: []PlannedSCP{{AttestID: "attest-b"}},
	}
	summary := plan.Summary()
	if summary == "" {
		t.Error("Summary() returned empty string")
	}
	if !containsStr(summary, "Create and attach: 1") {
		t.Errorf("Summary missing create count: %s", summary)
	}
	if !containsStr(summary, "Update:") {
		t.Errorf("Summary missing update: %s", summary)
	}
}

func containsStr(s, sub string) bool {
	return len(s) > 0 && len(sub) > 0 && (s == sub || len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}

func TestLoadCompiledSCPs(t *testing.T) {
	dir := t.TempDir()
	writeSCPFixtures(t, dir, map[string]any{
		"attest-scp-a": sampleSCP("scp-a"),
		"attest-scp-b": sampleSCP("scp-b"),
	})
	// Write a non-JSON file that should be ignored.
	os.WriteFile(filepath.Join(dir, "schema.cedarschema"), []byte("entity Test {}"), 0644)

	scps, err := loadCompiledSCPs(dir)
	if err != nil {
		t.Fatalf("loadCompiledSCPs() error = %v", err)
	}
	if len(scps) != 2 {
		t.Errorf("got %d SCPs, want 2", len(scps))
	}
	if _, ok := scps["attest-scp-a"]; !ok {
		t.Error("expected attest-scp-a in result")
	}
}

func TestMissingScpDir(t *testing.T) {
	_, err := loadCompiledSCPs("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing directory")
	}
}

func TestPlanMissingRoot(t *testing.T) {
	dir := t.TempDir()
	writeSCPFixtures(t, dir, map[string]any{"attest-scp-x": sampleSCP("x")})

	mock := &mockDeployOrgAPI{roots: []types.Root{}} // no roots
	d := newDeployerWithSvc(mock, "us-east-1")
	_, err := d.Plan(context.Background(), dir)
	if err == nil {
		t.Error("expected error when no org root found")
	}
}

func TestApplyError(t *testing.T) {
	dir := t.TempDir()
	writeSCPFixtures(t, dir, map[string]any{"attest-scp-x": sampleSCP("x")})

	mock := &mockDeployOrgAPI{
		roots:     []types.Root{{Id: aws.String("r-test")}},
		createErr: fmt.Errorf("access denied"),
	}
	d := newDeployerWithSvc(mock, "us-east-1")
	plan := &DeployPlan{
		RootID:   "r-test",
		ToCreate: []PlannedSCP{{AttestID: "attest-scp-x"}},
	}
	result, _ := d.Apply(context.Background(), plan, dir, func(s string) {})
	if result == nil || len(result.Failed) == 0 {
		t.Error("expected failed result when create fails")
	}
}
