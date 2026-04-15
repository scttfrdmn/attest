package org

import (
	"context"
	"fmt"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/provabl/attest/pkg/schema"
)

// mockOrgAPI implements orgAPI for testing.
type mockOrgAPI struct {
	describeOrgOut   *organizations.DescribeOrganizationOutput
	describeOrgErr   error
	listRootsOut     *organizations.ListRootsOutput
	listRootsErr     error
	listOUsPages     map[string][]types.OrganizationalUnit // parentID → OUs
	listOUsErr       error
	listAccountPages map[string][]types.Account // parentID → accounts
	listAccountsErr  error
	listPoliciesForTargetOut map[string][]types.PolicySummary // targetID → policies
	listPoliciesForTargetErr error
	listPoliciesOut  *organizations.ListPoliciesOutput
	listPoliciesErr  error
	describePolicyOut map[string]*organizations.DescribePolicyOutput // policyID → output
	describePolicyErr error
	listTagsOut      map[string][]types.Tag // resourceID → tags
	listTagsErr      error
}

func (m *mockOrgAPI) DescribeOrganization(ctx context.Context, _ *organizations.DescribeOrganizationInput, _ ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	return m.describeOrgOut, m.describeOrgErr
}
func (m *mockOrgAPI) ListRoots(ctx context.Context, _ *organizations.ListRootsInput, _ ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	return m.listRootsOut, m.listRootsErr
}
func (m *mockOrgAPI) ListOrganizationalUnitsForParent(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	if m.listOUsErr != nil {
		return nil, m.listOUsErr
	}
	ous := m.listOUsPages[*params.ParentId]
	return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: ous}, nil
}
func (m *mockOrgAPI) ListAccountsForParent(ctx context.Context, params *organizations.ListAccountsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
	if m.listAccountsErr != nil {
		return nil, m.listAccountsErr
	}
	accts := m.listAccountPages[*params.ParentId]
	return &organizations.ListAccountsForParentOutput{Accounts: accts}, nil
}
func (m *mockOrgAPI) ListPoliciesForTarget(ctx context.Context, params *organizations.ListPoliciesForTargetInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	if m.listPoliciesForTargetErr != nil {
		return nil, m.listPoliciesForTargetErr
	}
	policies := m.listPoliciesForTargetOut[*params.TargetId]
	return &organizations.ListPoliciesForTargetOutput{Policies: policies}, nil
}
func (m *mockOrgAPI) ListPolicies(ctx context.Context, _ *organizations.ListPoliciesInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	return m.listPoliciesOut, m.listPoliciesErr
}
func (m *mockOrgAPI) DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if m.describePolicyErr != nil {
		return nil, m.describePolicyErr
	}
	if out, ok := m.describePolicyOut[*params.PolicyId]; ok {
		return out, nil
	}
	return nil, fmt.Errorf("policy %s not found", *params.PolicyId)
}
func (m *mockOrgAPI) ListTagsForResource(ctx context.Context, params *organizations.ListTagsForResourceInput, _ ...func(*organizations.Options)) (*organizations.ListTagsForResourceOutput, error) {
	if m.listTagsErr != nil {
		return nil, m.listTagsErr
	}
	tags := m.listTagsOut[*params.ResourceId]
	return &organizations.ListTagsForResourceOutput{Tags: tags}, nil
}

// mockConfigAPI implements configAPI for testing.
type mockConfigAPI struct {
	describeConfigRulesOut *awsconfig.DescribeConfigRulesOutput
	describeConfigRulesErr error
}

func (m *mockConfigAPI) DescribeConfigRules(ctx context.Context, _ *awsconfig.DescribeConfigRulesInput, _ ...func(*awsconfig.Options)) (*awsconfig.DescribeConfigRulesOutput, error) {
	return m.describeConfigRulesOut, m.describeConfigRulesErr
}

func sp(s string) *string { return &s }

func TestBuildOrgTree(t *testing.T) {
	tests := []struct {
		name         string
		org          *mockOrgAPI
		wantRootID   string
		wantChildOUs int
		wantAccounts int
		wantErr      bool
	}{
		{
			name: "root with one OU and two accounts",
			org: &mockOrgAPI{
				listRootsOut: &organizations.ListRootsOutput{
					Roots: []types.Root{{Id: sp("r-root"), Name: sp("Root")}},
				},
				listOUsPages: map[string][]types.OrganizationalUnit{
					"r-root": {{Id: sp("ou-1"), Name: sp("Enclave")}},
					"ou-1":   {},
				},
				listAccountPages: map[string][]types.Account{
					"r-root": {},
					"ou-1": {
						{Id: sp("111111111111"), Name: sp("hipaa-lab"), Email: sp("a@b.com"), State: types.AccountStateActive},
						{Id: sp("222222222222"), Name: sp("cui-lab"), Email: sp("b@b.com"), State: types.AccountStateActive},
					},
				},
				listPoliciesForTargetOut: map[string][]types.PolicySummary{},
				describePolicyOut:        map[string]*organizations.DescribePolicyOutput{},
				listTagsOut:              map[string][]types.Tag{},
			},
			wantRootID:   "r-root",
			wantChildOUs: 1,
			wantAccounts: 2, // in the child OU
		},
		{
			name: "no roots error",
			org: &mockOrgAPI{
				listRootsOut: &organizations.ListRootsOutput{Roots: []types.Root{}},
			},
			wantErr: true,
		},
		{
			name: "listRoots error",
			org: &mockOrgAPI{
				listRootsErr: fmt.Errorf("access denied"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnalyzerWithSvc(tt.org, &mockConfigAPI{}, "us-west-2")
			root, err := a.BuildOrgTree(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("BuildOrgTree() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if root.ID != tt.wantRootID {
				t.Errorf("root.ID = %q, want %q", root.ID, tt.wantRootID)
			}
			if len(root.Children) != tt.wantChildOUs {
				t.Errorf("root.Children = %d, want %d", len(root.Children), tt.wantChildOUs)
			}
			if tt.wantChildOUs > 0 {
				childAccounts := len(root.Children[0].Accounts)
				if childAccounts != tt.wantAccounts {
					t.Errorf("child OU accounts = %d, want %d", childAccounts, tt.wantAccounts)
				}
			}
		})
	}
}

func TestBuildSRE(t *testing.T) {
	tests := []struct {
		name          string
		org           *mockOrgAPI
		wantOrgID     string
		wantEnvCount  int
		wantErr       bool
	}{
		{
			name: "builds SRE with environments",
			org: &mockOrgAPI{
				describeOrgOut: &organizations.DescribeOrganizationOutput{
					Organization: &types.Organization{
						Id:                  sp("o-test123"),
						MasterAccountEmail:  sp("admin@example.com"),
					},
				},
				listRootsOut: &organizations.ListRootsOutput{
					Roots: []types.Root{{Id: sp("r-root"), Name: sp("Root")}},
				},
				listOUsPages: map[string][]types.OrganizationalUnit{
					"r-root": {},
				},
				listAccountPages: map[string][]types.Account{
					"r-root": {
						{Id: sp("111111111111"), Name: sp("hipaa-lab"), Email: sp("a@b.com"), State: types.AccountStateActive},
					},
				},
				listPoliciesForTargetOut: map[string][]types.PolicySummary{},
				describePolicyOut:        map[string]*organizations.DescribePolicyOutput{},
				listTagsOut: map[string][]types.Tag{
					"111111111111": {
						{Key: sp("attest:data-class"), Value: sp("PHI,CUI")},
						{Key: sp("attest:owner"), Value: sp("Dr. Smith")},
					},
				},
			},
			wantOrgID:    "o-test123",
			wantEnvCount: 1,
		},
		{
			name: "skips suspended accounts",
			org: &mockOrgAPI{
				describeOrgOut: &organizations.DescribeOrganizationOutput{
					Organization: &types.Organization{Id: sp("o-test"), MasterAccountEmail: sp("a@b.com")},
				},
				listRootsOut: &organizations.ListRootsOutput{
					Roots: []types.Root{{Id: sp("r-root"), Name: sp("Root")}},
				},
				listOUsPages: map[string][]types.OrganizationalUnit{"r-root": {}},
				listAccountPages: map[string][]types.Account{
					"r-root": {
						{Id: sp("111111111111"), Name: sp("active"), State: types.AccountStateActive},
						{Id: sp("222222222222"), Name: sp("suspended"), State: types.AccountStateSuspended},
					},
				},
				listPoliciesForTargetOut: map[string][]types.PolicySummary{},
				describePolicyOut:        map[string]*organizations.DescribePolicyOutput{},
				listTagsOut:              map[string][]types.Tag{},
			},
			wantOrgID:    "o-test",
			wantEnvCount: 1, // only the active account
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnalyzerWithSvc(tt.org, &mockConfigAPI{}, "us-west-2")
			sre, err := a.BuildSRE(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("BuildSRE() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if sre.OrgID != tt.wantOrgID {
				t.Errorf("OrgID = %q, want %q", sre.OrgID, tt.wantOrgID)
			}
			if len(sre.Environments) != tt.wantEnvCount {
				t.Errorf("Environments = %d, want %d", len(sre.Environments), tt.wantEnvCount)
			}
		})
	}
}

func TestTagToDataClass(t *testing.T) {
	tests := []struct {
		name       string
		tagValue   string
		wantClasses []string
	}{
		{"single class", "CUI", []string{"CUI"}},
		{"multiple classes", "CUI,PHI", []string{"CUI", "PHI"}},
		{"with spaces", "CUI, PHI, FERPA", []string{"CUI", "PHI", "FERPA"}},
		{"empty", "", []string(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockOrgAPI{
				describeOrgOut: &organizations.DescribeOrganizationOutput{
					Organization: &types.Organization{Id: sp("o-test"), MasterAccountEmail: sp("a@b.com")},
				},
				listRootsOut: &organizations.ListRootsOutput{
					Roots: []types.Root{{Id: sp("r-root"), Name: sp("Root")}},
				},
				listOUsPages:             map[string][]types.OrganizationalUnit{"r-root": {}},
				listPoliciesForTargetOut: map[string][]types.PolicySummary{},
				describePolicyOut:        map[string]*organizations.DescribePolicyOutput{},
				listAccountPages: map[string][]types.Account{
					"r-root": {{Id: sp("111111111111"), Name: sp("lab"), State: types.AccountStateActive}},
				},
				listTagsOut: map[string][]types.Tag{
					"111111111111": {{Key: sp(dataClassTagKey), Value: sp(tt.tagValue)}},
				},
			}
			a := newAnalyzerWithSvc(mock, &mockConfigAPI{}, "us-west-2")
			sre, err := a.BuildSRE(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			env := sre.Environments["111111111111"]
			if len(env.DataClasses) != len(tt.wantClasses) {
				t.Errorf("DataClasses = %v, want %v", env.DataClasses, tt.wantClasses)
				return
			}
			for i, want := range tt.wantClasses {
				if env.DataClasses[i] != want {
					t.Errorf("DataClass[%d] = %q, want %q", i, env.DataClasses[i], want)
				}
			}
		})
	}
}

func TestResolveDataClasses(t *testing.T) {
	tests := []struct {
		name     string
		sre      *schema.SRE
		wantLen  int
		wantHas  []string
	}{
		{
			name: "deduplicates across accounts",
			sre: &schema.SRE{
				Environments: map[string]schema.Environment{
					"111": {DataClasses: []string{"CUI", "PHI"}},
					"222": {DataClasses: []string{"CUI", "FERPA"}},
				},
			},
			wantLen: 3,
			wantHas: []string{"CUI", "PHI", "FERPA"},
		},
		{
			name: "empty environments",
			sre: &schema.SRE{
				Environments: map[string]schema.Environment{},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnalyzerWithSvc(&mockOrgAPI{}, &mockConfigAPI{}, "us-west-2")
			classes, err := a.ResolveDataClasses(context.Background(), tt.sre)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(classes) != tt.wantLen {
				t.Errorf("got %d classes, want %d: %v", len(classes), tt.wantLen, classes)
			}
			classSet := make(map[string]bool)
			for _, c := range classes {
				classSet[c] = true
			}
			for _, want := range tt.wantHas {
				if !classSet[want] {
					t.Errorf("expected data class %q", want)
				}
			}
		})
	}
}

func TestInventoryConfigRules(t *testing.T) {
	tests := []struct {
		name     string
		cfgOut   *awsconfig.DescribeConfigRulesOutput
		cfgErr   error
		wantLen  int
		wantErr  bool
	}{
		{
			name: "returns rule names",
			cfgOut: &awsconfig.DescribeConfigRulesOutput{
				ConfigRules: []configtypes.ConfigRule{
					{ConfigRuleName: sp("s3-encryption")},
					{ConfigRuleName: sp("mfa-enabled")},
				},
			},
			wantLen: 2,
		},
		{
			name:    "API error",
			cfgErr:  fmt.Errorf("access denied"),
			wantErr: true,
		},
		{
			name:    "empty rules",
			cfgOut:  &awsconfig.DescribeConfigRulesOutput{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnalyzerWithSvc(&mockOrgAPI{}, &mockConfigAPI{
				describeConfigRulesOut: tt.cfgOut,
				describeConfigRulesErr: tt.cfgErr,
			}, "us-west-2")
			rules, err := a.InventoryConfigRules(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("InventoryConfigRules() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				got := rules[a.accountID]
				if len(got) != tt.wantLen {
					t.Errorf("got %d rules, want %d", len(got), tt.wantLen)
				}
			}
		})
	}
}
