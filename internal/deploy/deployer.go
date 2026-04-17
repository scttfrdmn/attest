// Package deploy handles deploying compiled policy artifacts to an AWS Organization.
// It separates read (internal/org) from write concerns: creating, updating, and
// attaching SCPs to the org root via the Organizations API.
package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// deployOrgAPI is the Organizations write interface used by the deployer.
// Defined as an interface to enable mocking in tests.
type deployOrgAPI interface {
	ListRoots(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	ListPoliciesForTarget(ctx context.Context, params *organizations.ListPoliciesForTargetInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	CreatePolicy(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error)
	UpdatePolicy(ctx context.Context, params *organizations.UpdatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error)
	AttachPolicy(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error)
	DetachPolicy(ctx context.Context, params *organizations.DetachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.DetachPolicyOutput, error)
}

// PlannedSCP describes one SCP operation in a deployment plan.
type PlannedSCP struct {
	AttestID  string // attest internal ID: "attest-scp-require-mfa"
	OrgID     string // AWS policy ID if exists: "p-xxxxxxxxxx" (empty if new)
	Action    string // "create", "update", "attach", "no-change"
	HasChange bool   // true if content differs from deployed version
}

// scpPerTargetLimit is the AWS hard limit for SCPs attached to a root/OU/account.
const SCPPerTargetLimit = 5

// DeployPlan describes what `attest apply` would do.
type DeployPlan struct {
	ToCreate     []PlannedSCP // new SCPs to create and attach
	ToUpdate     []PlannedSCP // existing SCPs whose content has changed
	ToAttach     []PlannedSCP // existing SCPs not yet attached to root
	NoChange     []PlannedSCP // SCPs already deployed and current
	RootID       string       // org root ID (r-xxxx)
	QuotaWarning string       // non-empty if deployment would exceed SCP limit
	CurrentCount int          // SCPs currently attached to root
}

// Summary returns a human-readable deployment summary.
func (p *DeployPlan) Summary() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Deployment plan (root: %s):\n", p.RootID))
	b.WriteString(fmt.Sprintf("  Create and attach: %d SCP(s)\n", len(p.ToCreate)))
	b.WriteString(fmt.Sprintf("  Update:            %d SCP(s)\n", len(p.ToUpdate)))
	b.WriteString(fmt.Sprintf("  Attach:            %d SCP(s)\n", len(p.ToAttach)))
	b.WriteString(fmt.Sprintf("  No change:         %d SCP(s)\n", len(p.NoChange)))
	if len(p.ToCreate)+len(p.ToUpdate)+len(p.ToAttach) == 0 {
		b.WriteString("  Nothing to do — org is up to date.\n")
	}
	return b.String()
}

// Deployer deploys compiled SCP artifacts to an AWS Organization.
type Deployer struct {
	orgSvc deployOrgAPI
	region string
}

// NewDeployer creates a deployer backed by real AWS SDK clients.
func NewDeployer(ctx context.Context, region string) (*Deployer, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &Deployer{
		orgSvc: organizations.NewFromConfig(cfg),
		region: region,
	}, nil
}

// newDeployerWithSvc creates a deployer with an injected API client (for testing).
func newDeployerWithSvc(svc deployOrgAPI, region string) *Deployer {
	return &Deployer{orgSvc: svc, region: region}
}

// Plan computes what attest apply would do without making any changes.
// It loads compiled SCP JSON files from scpDir and compares them against
// the currently deployed SCPs in the organization.
func (d *Deployer) Plan(ctx context.Context, scpDir string) (*DeployPlan, error) {
	// Load compiled SCPs from .attest/compiled/scps/*.json
	compiled, err := loadCompiledSCPs(scpDir)
	if err != nil {
		return nil, fmt.Errorf("loading compiled SCPs from %s: %w", scpDir, err)
	}

	// Get org root ID.
	rootID, err := d.getRootID(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting org root: %w", err)
	}

	// Get all existing SCPs in the org, indexed by Name.
	existing, err := d.listExistingSCPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing existing SCPs: %w", err)
	}

	// Get SCPs already attached to the root.
	attachedToRoot, err := d.listAttachedToRoot(ctx, rootID)
	if err != nil {
		return nil, fmt.Errorf("listing root-attached SCPs: %w", err)
	}

	// Count currently attached SCPs (including non-attest ones like FullAWSAccess).
	currentCount, err := d.countAttachedSCPs(ctx, rootID)
	if err != nil {
		return nil, fmt.Errorf("counting attached SCPs: %w", err)
	}

	plan := &DeployPlan{RootID: rootID, CurrentCount: currentCount}

	for attID, content := range compiled {
		name := attID // "attest-scp-require-mfa"

		existingPolicy, exists := existing[name]
		isAttached := attachedToRoot[name]

		switch {
		case !exists:
			plan.ToCreate = append(plan.ToCreate, PlannedSCP{
				AttestID: attID, Action: "create", HasChange: true,
			})
		case exists && !contentMatches(existingPolicy.Content, content):
			plan.ToUpdate = append(plan.ToUpdate, PlannedSCP{
				AttestID: attID, OrgID: existingPolicy.ID, Action: "update", HasChange: true,
			})
			if !isAttached {
				plan.ToAttach = append(plan.ToAttach, PlannedSCP{
					AttestID: attID, OrgID: existingPolicy.ID, Action: "attach",
				})
			}
		case exists && !isAttached:
			plan.ToAttach = append(plan.ToAttach, PlannedSCP{
				AttestID: attID, OrgID: existingPolicy.ID, Action: "attach",
			})
		default:
			plan.NoChange = append(plan.NoChange, PlannedSCP{
				AttestID: attID, OrgID: existingPolicy.ID, Action: "no-change",
			})
		}
	}

	// Quota check: would deploying exceed the 5-per-target hard limit?
	newToAttach := len(plan.ToCreate) + len(plan.ToAttach)
	projectedTotal := currentCount + newToAttach
	if projectedTotal > SCPPerTargetLimit {
		plan.QuotaWarning = fmt.Sprintf(
			"deployment would attach %d SCP(s) to root (%d existing + %d new = %d total, limit is %d)\n"+
				"  Solution: run 'attest compile --scp-strategy merged' to produce ≤4 composite SCPs",
			newToAttach, currentCount, newToAttach, projectedTotal, SCPPerTargetLimit)
	}

	return plan, nil
}

// ApplyResult summarizes what was deployed and what failed.
type ApplyResult struct {
	Deployed []string
	Failed   []string // "id: reason"
}

// Apply executes a deployment plan, creating, updating, and attaching SCPs.
// Continues on individual SCP failures — reports all failures at the end.
func (d *Deployer) Apply(ctx context.Context, plan *DeployPlan, scpDir string, progressFn func(string)) (*ApplyResult, error) {
	compiled, err := loadCompiledSCPs(scpDir)
	if err != nil {
		return nil, err
	}

	result := &ApplyResult{}

	// Create new SCPs.
	for _, scp := range plan.ToCreate {
		content := compiled[scp.AttestID]
		progressFn(fmt.Sprintf("  Creating SCP: %s", scp.AttestID))
		out, err := d.orgSvc.CreatePolicy(ctx, &organizations.CreatePolicyInput{
			Name:        aws.String(scp.AttestID),
			Description: aws.String("Managed by attest — do not edit manually"),
			Content:     aws.String(content),
			Type:        types.PolicyTypeServiceControlPolicy,
		})
		if err != nil {
			progressFn(fmt.Sprintf("  ✗ Failed: %s (%v)", scp.AttestID, err))
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", scp.AttestID, err))
			continue
		}
		policyID := aws.ToString(out.Policy.PolicySummary.Id)
		progressFn(fmt.Sprintf("  Attaching SCP: %s → %s", scp.AttestID, plan.RootID))
		if _, err := d.orgSvc.AttachPolicy(ctx, &organizations.AttachPolicyInput{
			PolicyId: aws.String(policyID),
			TargetId: aws.String(plan.RootID),
		}); err != nil {
			progressFn(fmt.Sprintf("  ✗ Attach failed: %s (%v)", scp.AttestID, err))
			result.Failed = append(result.Failed, fmt.Sprintf("%s (attach): %v", scp.AttestID, err))
			continue
		}
		result.Deployed = append(result.Deployed, scp.AttestID)
	}

	// Update existing SCPs.
	for _, scp := range plan.ToUpdate {
		content := compiled[scp.AttestID]
		progressFn(fmt.Sprintf("  Updating SCP: %s (%s)", scp.AttestID, scp.OrgID))
		if _, err := d.orgSvc.UpdatePolicy(ctx, &organizations.UpdatePolicyInput{
			PolicyId: aws.String(scp.OrgID),
			Content:  aws.String(content),
		}); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s (update): %v", scp.AttestID, err))
			continue
		}
		result.Deployed = append(result.Deployed, scp.AttestID)
	}

	// Attach unattached SCPs.
	for _, scp := range plan.ToAttach {
		progressFn(fmt.Sprintf("  Attaching SCP: %s → %s", scp.AttestID, plan.RootID))
		if _, err := d.orgSvc.AttachPolicy(ctx, &organizations.AttachPolicyInput{
			PolicyId: aws.String(scp.OrgID),
			TargetId: aws.String(plan.RootID),
		}); err != nil {
				result.Failed = append(result.Failed, fmt.Sprintf("%s (attach): %v", scp.AttestID, err))
			continue
		}
		result.Deployed = append(result.Deployed, scp.AttestID)
	}

	return result, nil
}

// --- helpers ---

type existingPolicy struct {
	ID      string
	Content string
}

// getRootID returns the organization root ID.
func (d *Deployer) getRootID(ctx context.Context) (string, error) {
	out, err := d.orgSvc.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return "", err
	}
	if len(out.Roots) == 0 {
		return "", fmt.Errorf("no organization root found")
	}
	return aws.ToString(out.Roots[0].Id), nil
}

// listExistingSCPs returns all SCPs in the org indexed by name.
func (d *Deployer) listExistingSCPs(ctx context.Context) (map[string]existingPolicy, error) {
	result := make(map[string]existingPolicy)
	var nextToken *string

	for {
		out, err := d.orgSvc.ListPolicies(ctx, &organizations.ListPoliciesInput{
			Filter:    types.PolicyTypeServiceControlPolicy,
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}
		for _, p := range out.Policies {
			name := aws.ToString(p.Name)
			desc, err := d.orgSvc.DescribePolicy(ctx, &organizations.DescribePolicyInput{
				PolicyId: p.Id,
			})
			if err != nil {
				continue
			}
			result[name] = existingPolicy{
				ID:      aws.ToString(p.Id),
				Content: aws.ToString(desc.Policy.Content),
			}
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return result, nil
}

// listAttachedToRoot returns the set of SCP names attached to the root.
func (d *Deployer) listAttachedToRoot(ctx context.Context, rootID string) (map[string]bool, error) {
	attached := make(map[string]bool)
	var nextToken *string

	for {
		out, err := d.orgSvc.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
			TargetId:  aws.String(rootID),
			Filter:    types.PolicyTypeServiceControlPolicy,
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}
		for _, p := range out.Policies {
			attached[aws.ToString(p.Name)] = true
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return attached, nil
}

// countAttachedSCPs returns the total number of SCPs attached to the target.
func (d *Deployer) countAttachedSCPs(ctx context.Context, targetID string) (int, error) {
	count := 0
	var nextToken *string
	for {
		out, err := d.orgSvc.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
			TargetId:  aws.String(targetID),
			Filter:    types.PolicyTypeServiceControlPolicy,
			NextToken: nextToken,
		})
		if err != nil {
			return 0, err
		}
		count += len(out.Policies)
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return count, nil
}

// DetachAll detaches every attest-managed SCP (name prefix "attest-") from the
// org root. Used by rollback before re-applying a prior checkpoint state.
func (d *Deployer) DetachAll(ctx context.Context, rootID string) error {
	var nextToken *string
	for {
		out, err := d.orgSvc.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
			TargetId:  aws.String(rootID),
			Filter:    types.PolicyTypeServiceControlPolicy,
			NextToken: nextToken,
		})
		if err != nil {
			return fmt.Errorf("listing SCPs at root: %w", err)
		}
		for _, p := range out.Policies {
			if !strings.HasPrefix(aws.ToString(p.Name), "attest-") {
				continue // leave non-attest SCPs (e.g., FullAWSAccess) alone
			}
			if _, err := d.orgSvc.DetachPolicy(ctx, &organizations.DetachPolicyInput{
				PolicyId: p.Id,
				TargetId: aws.String(rootID),
			}); err != nil {
				return fmt.Errorf("detaching %s: %w", aws.ToString(p.Name), err)
			}
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return nil
}

// loadCompiledSCPs reads all .json files from scpDir, returning a map of
// attID → raw JSON content.
func loadCompiledSCPs(scpDir string) (map[string]string, error) {
	entries, err := os.ReadDir(scpDir)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("compiled SCPs directory %s not found (run 'attest compile' first)", scpDir)
	}
	if err != nil {
		return nil, err
	}

	scps := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(scpDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		scps[id] = string(data)
	}
	return scps, nil
}

// contentMatches compares two SCP JSON documents for semantic equality.
// Normalizes whitespace by round-tripping through json.Marshal.
func contentMatches(a, b string) bool {
	var objA, objB any
	if err := json.Unmarshal([]byte(a), &objA); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &objB); err != nil {
		return false
	}
	normA, _ := json.Marshal(objA)
	normB, _ := json.Marshal(objB)
	return string(normA) == string(normB)
}
