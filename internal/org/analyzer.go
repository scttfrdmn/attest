// Package org reads an AWS Organization and maps it to the SRE model.
// The Organization IS the Secure Research Environment. Accounts within it
// are research environments that inherit org-level compliance posture.
package org

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsconfig "github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/scttfrdmn/attest/pkg/schema"
)

// dataClassTagKey is the account tag attest reads to determine data classification.
// Tag value is a comma-separated list, e.g., "CUI,PHI".
const dataClassTagKey = "attest:data-class"

// OUNode represents a node in the org tree.
type OUNode struct {
	ID       string
	Name     string
	ParentID string
	Path     string // e.g., "Root/Enclave/HIPAA"
	SCPs     []AttachedSCP
	Children []OUNode
	Accounts []AccountInfo
}

// AttachedSCP is an SCP currently attached to an OU or account.
type AttachedSCP struct {
	ID       string
	Name     string
	Document string // raw JSON policy
}

// AccountInfo is basic account metadata from the Organizations API.
type AccountInfo struct {
	ID     string
	Name   string
	Email  string
	Status string // ACTIVE, SUSPENDED
	Tags   map[string]string
}

// orgAPI is the interface we use for the Organizations SDK client,
// defined to enable mocking in tests.
type orgAPI interface {
	DescribeOrganization(ctx context.Context, params *organizations.DescribeOrganizationInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListRoots(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListAccountsForParent(ctx context.Context, params *organizations.ListAccountsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error)
	ListPoliciesForTarget(ctx context.Context, params *organizations.ListPoliciesForTargetInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTagsForResource(ctx context.Context, params *organizations.ListTagsForResourceInput, optFns ...func(*organizations.Options)) (*organizations.ListTagsForResourceOutput, error)
}

// configAPI is the interface we use for the Config SDK client.
type configAPI interface {
	DescribeConfigRules(ctx context.Context, params *awsconfig.DescribeConfigRulesInput, optFns ...func(*awsconfig.Options)) (*awsconfig.DescribeConfigRulesOutput, error)
}

// Analyzer reads org topology, existing SCPs, and account metadata
// to build the SRE model.
type Analyzer struct {
	orgSvc    orgAPI
	cfgSvc    configAPI
	accountID string
	region    string
}

// NewAnalyzer creates an org analyzer using the default credential chain.
func NewAnalyzer(ctx context.Context, region string) (*Analyzer, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &Analyzer{
		orgSvc: organizations.NewFromConfig(cfg),
		cfgSvc: awsconfig.NewFromConfig(cfg),
		region: region,
	}, nil
}

// newAnalyzerWithSvc creates an analyzer with injected API clients (for testing).
func newAnalyzerWithSvc(orgSvc orgAPI, cfgSvc configAPI, region string) *Analyzer {
	return &Analyzer{orgSvc: orgSvc, cfgSvc: cfgSvc, region: region}
}

// BuildSRE reads the full org tree and constructs the SRE model.
// This is the starting point for `attest init` and `attest scan`.
func (a *Analyzer) BuildSRE(ctx context.Context) (*schema.SRE, error) {
	out, err := a.orgSvc.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return nil, fmt.Errorf("describing organization: %w", err)
	}
	org := out.Organization

	root, err := a.BuildOrgTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("building org tree: %w", err)
	}

	sre := &schema.SRE{
		OrgID:        aws.ToString(org.Id),
		Name:         aws.ToString(org.MasterAccountEmail), // best we have without a name tag
		Environments: make(map[string]schema.Environment),
	}

	// Flatten the tree into environments.
	flattenAccounts(root, sre)

	return sre, nil
}

// BuildOrgTree walks the full OU hierarchy.
func (a *Analyzer) BuildOrgTree(ctx context.Context) (*OUNode, error) {
	rootsOut, err := a.orgSvc.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing org roots: %w", err)
	}
	if len(rootsOut.Roots) == 0 {
		return nil, fmt.Errorf("no org root found")
	}
	root := rootsOut.Roots[0]

	node := &OUNode{
		ID:   aws.ToString(root.Id),
		Name: aws.ToString(root.Name),
		Path: aws.ToString(root.Name),
	}

	if err := a.walkOU(ctx, node); err != nil {
		return nil, err
	}

	return node, nil
}

// walkOU recursively populates a node with its children, accounts, and SCPs.
func (a *Analyzer) walkOU(ctx context.Context, node *OUNode) error {
	// Collect SCPs attached to this OU/root.
	scps, err := a.listSCPsForTarget(ctx, node.ID)
	if err != nil {
		return fmt.Errorf("listing SCPs for %s: %w", node.ID, err)
	}
	node.SCPs = scps

	// Collect accounts directly under this OU.
	accounts, err := a.listAccountsForParent(ctx, node.ID)
	if err != nil {
		return fmt.Errorf("listing accounts for %s: %w", node.ID, err)
	}
	node.Accounts = accounts

	// Recurse into child OUs.
	var nextToken *string
	for {
		out, err := a.orgSvc.ListOrganizationalUnitsForParent(ctx, &organizations.ListOrganizationalUnitsForParentInput{
			ParentId:  aws.String(node.ID),
			NextToken: nextToken,
		})
		if err != nil {
			return fmt.Errorf("listing OUs for parent %s: %w", node.ID, err)
		}

		for _, ou := range out.OrganizationalUnits {
			child := &OUNode{
				ID:       aws.ToString(ou.Id),
				Name:     aws.ToString(ou.Name),
				ParentID: node.ID,
				Path:     node.Path + "/" + aws.ToString(ou.Name),
			}
			if err := a.walkOU(ctx, child); err != nil {
				return err
			}
			node.Children = append(node.Children, *child)
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return nil
}

// listSCPsForTarget returns all SCPs attached to a given target (root, OU, or account).
func (a *Analyzer) listSCPsForTarget(ctx context.Context, targetID string) ([]AttachedSCP, error) {
	var scps []AttachedSCP
	var nextToken *string

	for {
		out, err := a.orgSvc.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
			TargetId:  aws.String(targetID),
			Filter:    types.PolicyTypeServiceControlPolicy,
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing policies for target %s: %w", targetID, err)
		}

		for _, p := range out.Policies {
			policyID := aws.ToString(p.Id)
			descOut, err := a.orgSvc.DescribePolicy(ctx, &organizations.DescribePolicyInput{
				PolicyId: aws.String(policyID),
			})
			if err != nil {
				return nil, fmt.Errorf("describing policy %s: %w", policyID, err)
			}
			scps = append(scps, AttachedSCP{
				ID:       policyID,
				Name:     aws.ToString(p.Name),
				Document: aws.ToString(descOut.Policy.Content),
			})
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return scps, nil
}

// listAccountsForParent returns all accounts directly under a parent OU/root,
// including their tags.
func (a *Analyzer) listAccountsForParent(ctx context.Context, parentID string) ([]AccountInfo, error) {
	var accounts []AccountInfo
	var nextToken *string

	for {
		out, err := a.orgSvc.ListAccountsForParent(ctx, &organizations.ListAccountsForParentInput{
			ParentId:  aws.String(parentID),
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing accounts for parent %s: %w", parentID, err)
		}

		for _, acct := range out.Accounts {
			info := AccountInfo{
				ID:     aws.ToString(acct.Id),
				Name:   aws.ToString(acct.Name),
				Email:  aws.ToString(acct.Email),
				Status: string(acct.State),
				Tags:   make(map[string]string),
			}

			// Fetch tags for data classification.
			tags, err := a.listTagsForResource(ctx, aws.ToString(acct.Id))
			if err != nil {
				return nil, fmt.Errorf("listing tags for account %s: %w", info.ID, err)
			}
			info.Tags = tags
			accounts = append(accounts, info)
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return accounts, nil
}

// listTagsForResource returns all tags for an org resource as a map.
func (a *Analyzer) listTagsForResource(ctx context.Context, resourceID string) (map[string]string, error) {
	tags := make(map[string]string)
	var nextToken *string

	for {
		out, err := a.orgSvc.ListTagsForResource(ctx, &organizations.ListTagsForResourceInput{
			ResourceId: aws.String(resourceID),
			NextToken:  nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing tags for %s: %w", resourceID, err)
		}

		for _, t := range out.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return tags, nil
}

// InventoryExistingSCPs collects all SCPs defined in the org.
// Used by the gap analyzer to determine which controls already have structural enforcement.
func (a *Analyzer) InventoryExistingSCPs(ctx context.Context) ([]AttachedSCP, error) {
	var scps []AttachedSCP
	var nextToken *string

	for {
		out, err := a.orgSvc.ListPolicies(ctx, &organizations.ListPoliciesInput{
			Filter:    types.PolicyTypeServiceControlPolicy,
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing all SCPs: %w", err)
		}

		for _, p := range out.Policies {
			policyID := aws.ToString(p.Id)
			descOut, err := a.orgSvc.DescribePolicy(ctx, &organizations.DescribePolicyInput{
				PolicyId: aws.String(policyID),
			})
			if err != nil {
				return nil, fmt.Errorf("describing policy %s: %w", policyID, err)
			}
			scps = append(scps, AttachedSCP{
				ID:       policyID,
				Name:     aws.ToString(p.Name),
				Document: aws.ToString(descOut.Policy.Content),
			})
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return scps, nil
}

// InventoryConfigRules collects existing Config rules in the current account.
// Returns map of account_id → list of Config rule names.
//
// Note: For v0.2.0, this queries the management account only. Cross-account
// Config rule inventory requires org-delegated Config and assumed roles;
// that is deferred to v0.3.0.
func (a *Analyzer) InventoryConfigRules(ctx context.Context) (map[string][]string, error) {
	result := make(map[string][]string)
	var nextToken *string

	for {
		out, err := a.cfgSvc.DescribeConfigRules(ctx, &awsconfig.DescribeConfigRulesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("describing Config rules: %w", err)
		}

		for _, rule := range out.ConfigRules {
			result[a.accountID] = append(result[a.accountID], aws.ToString(rule.ConfigRuleName))
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return result, nil
}

// ResolveDataClasses determines which data classification tags are present in the org.
// This drives framework activation — if any account holds CUI, NIST 800-171 must be active.
func (a *Analyzer) ResolveDataClasses(ctx context.Context, sre *schema.SRE) ([]string, error) {
	classes := make(map[string]bool)
	for _, env := range sre.Environments {
		for _, dc := range env.DataClasses {
			classes[dc] = true
		}
	}
	result := make([]string, 0, len(classes))
	for dc := range classes {
		result = append(result, dc)
	}
	return result, nil
}

// --- helpers ---

// flattenAccounts recursively walks the OUNode tree and populates sre.Environments.
func flattenAccounts(node *OUNode, sre *schema.SRE) {
	for _, acct := range node.Accounts {
		if acct.Status != "ACTIVE" {
			continue
		}
		env := schema.Environment{
			AccountID: acct.ID,
			Name:      acct.Name,
			OU:        node.Path,
			Tags:      acct.Tags,
		}

		// Parse attest:data-class tag ("CUI,PHI" → ["CUI","PHI"]).
		if dc, ok := acct.Tags[dataClassTagKey]; ok && dc != "" {
			for _, class := range strings.Split(dc, ",") {
				env.DataClasses = append(env.DataClasses, strings.TrimSpace(class))
			}
		}

		// Owner tag → PI or lab.
		if owner, ok := acct.Tags["attest:owner"]; ok {
			env.Owner = owner
		}

		// Purpose tag.
		if purpose, ok := acct.Tags["attest:purpose"]; ok {
			env.Purpose = purpose
		}

		sre.Environments[acct.ID] = env
	}

	for i := range node.Children {
		flattenAccounts(&node.Children[i], sre)
	}
}
