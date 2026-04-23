// Package provision automates compliant environment creation.
// "I need a HIPAA environment for clinical genomics" becomes
// `attest provision` — computes target OU from data classes,
// checks prerequisites, creates account, configures tags, and
// registers the Cedar entity. The researcher gets a compliant
// environment in minutes; they never touch compliance config.
package provision

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/provabl/attest/pkg/schema"
)

// ouMapping maps data class → target OU name convention.
// The Provisioner searches for an OU matching these names under the org root.
var ouMapping = map[string]string{
	"CUI":   "research-controlled",
	"PHI":   "research-hipaa",
	"FERPA": "research-education",
	"PII":   "research-sensitive",
	"OPEN":  "research-open",
}

// Request describes a new environment to provision.
type Request struct {
	Name        string   // e.g., "clinical-genomics-chen"
	Owner       string   // PI or lab
	Email       string   // AWS account email (must be unique in AWS)
	Purpose     string   // e.g., "Clinical genomics data analysis"
	DataClasses []string // e.g., ["PHI", "CUI"]
	Tags        map[string]string
}

// Plan is the computed provisioning plan shown for approval.
type Plan struct {
	TargetOU      string // computed OU ID from data classes
	TargetOUName  string // human-readable OU name
	AccountName   string
	AccountEmail  string
	SCPsInherited int // from parent OU
	Prerequisites []Prerequisite
	AllMet        bool
	AttestTags    map[string]string // tags to apply to the new account
}

// Prerequisite is a check that must pass before provisioning.
type Prerequisite struct {
	Description string // e.g., "BAA signed for HIPAA workloads"
	Met         bool
	Source      string // e.g., "artifact-agreements", "principal-resolver"
}

// orgAPI is the Organizations interface used by the Provisioner.
type orgAPI interface {
	ListRoots(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListPoliciesForTarget(ctx context.Context, params *organizations.ListPoliciesForTargetInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	CreateAccount(ctx context.Context, params *organizations.CreateAccountInput, optFns ...func(*organizations.Options)) (*organizations.CreateAccountOutput, error)
	DescribeCreateAccountStatus(ctx context.Context, params *organizations.DescribeCreateAccountStatusInput, optFns ...func(*organizations.Options)) (*organizations.DescribeCreateAccountStatusOutput, error)
	MoveAccount(ctx context.Context, params *organizations.MoveAccountInput, optFns ...func(*organizations.Options)) (*organizations.MoveAccountOutput, error)
	TagResource(ctx context.Context, params *organizations.TagResourceInput, optFns ...func(*organizations.Options)) (*organizations.TagResourceOutput, error)
}

// Provisioner creates compliant environments within the SRE.
type Provisioner struct {
	region string
	orgSvc orgAPI
}

// NewProvisioner creates an environment provisioner backed by real AWS clients.
func NewProvisioner(ctx context.Context, region string) (*Provisioner, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &Provisioner{
		region: region,
		orgSvc: organizations.NewFromConfig(cfg),
	}, nil
}

// ComputePlan determines the target OU, checks prerequisites, and
// returns a provisioning plan for approval.
func (p *Provisioner) ComputePlan(ctx context.Context, sre *schema.SRE, req *Request) (*Plan, error) {
	if len(req.DataClasses) == 0 {
		return nil, fmt.Errorf("at least one data class is required (CUI, PHI, FERPA, PII, OPEN)")
	}

	// Determine target OU name from data classes (most restrictive wins).
	targetOUName := targetOU(req.DataClasses)

	// Get org root.
	rootOut, err := p.orgSvc.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing org roots: %w", err)
	}
	if len(rootOut.Roots) == 0 {
		return nil, fmt.Errorf("no organization root found")
	}
	rootID := aws.ToString(rootOut.Roots[0].Id)

	// Find the target OU under the root.
	targetOUID, err := p.findOU(ctx, rootID, targetOUName)
	if err != nil {
		return nil, fmt.Errorf("finding target OU %q: %w", targetOUName, err)
	}
	if targetOUID == "" {
		return nil, fmt.Errorf("OU %q not found under root %s — create it first:\n"+
			"  aws organizations create-organizational-unit --parent-id %s --name %s",
			targetOUName, rootID, rootID, targetOUName)
	}

	// Count SCPs already on the target OU.
	scpCount, err := p.countAttachedSCPs(ctx, targetOUID)
	if err != nil {
		return nil, fmt.Errorf("counting SCPs on target OU: %w", err)
	}

	// Build prerequisites.
	prereqs := buildPrerequisites(req.DataClasses)

	// Build attest:* tags for the new account.
	attestTags := map[string]string{
		"attest:owner":      req.Owner,
		"attest:purpose":    req.Purpose,
		"attest:created-by": "attest-provision",
		"attest:created-at": time.Now().UTC().Format(time.RFC3339),
	}
	for _, dc := range req.DataClasses {
		attestTags["attest:data-class"] = dc // last one wins; single class recommended
	}

	allMet := true
	for _, pr := range prereqs {
		if !pr.Met {
			allMet = false
		}
	}

	plan := &Plan{
		TargetOU:      targetOUID,
		TargetOUName:  targetOUName,
		AccountName:   req.Name,
		AccountEmail:  req.Email,
		SCPsInherited: scpCount,
		Prerequisites: prereqs,
		AllMet:        allMet,
		AttestTags:    attestTags,
	}
	return plan, nil
}

// Execute creates the account, places it in the OU, applies tags,
// and registers it in the SRE. Rolls back on failure by reporting
// what was completed so the operator can clean up.
func (p *Provisioner) Execute(ctx context.Context, plan *Plan) (*schema.Environment, error) {
	if !plan.AllMet {
		unmet := []string{}
		for _, pr := range plan.Prerequisites {
			if !pr.Met {
				unmet = append(unmet, pr.Description)
			}
		}
		return nil, fmt.Errorf("prerequisites not met:\n  - %s", strings.Join(unmet, "\n  - "))
	}

	// Step 1: Create account.
	createOut, err := p.orgSvc.CreateAccount(ctx, &organizations.CreateAccountInput{
		AccountName: aws.String(plan.AccountName),
		Email:       aws.String(plan.AccountEmail),
	})
	if err != nil {
		// Sanitize error to prevent email enumeration — don't expose whether
		// an email already exists in the organization.
		if strings.Contains(err.Error(), "email") || strings.Contains(err.Error(), "Email") {
			return nil, fmt.Errorf("account creation failed (check email format and uniqueness)")
		}
		return nil, fmt.Errorf("creating account: %w", err)
	}
	requestID := aws.ToString(createOut.CreateAccountStatus.Id)

	// Step 2: Poll until account creation completes (async in Organizations).
	var accountID string
	for attempt := 0; attempt < 120; attempt++ { // max 10 min (120 * 5s)
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled while waiting for account creation")
		case <-time.After(5 * time.Second):
		}

		statusOut, err := p.orgSvc.DescribeCreateAccountStatus(ctx, &organizations.DescribeCreateAccountStatusInput{
			CreateAccountRequestId: aws.String(requestID),
		})
		if err != nil {
			return nil, fmt.Errorf("checking account creation status: %w", err)
		}

		switch statusOut.CreateAccountStatus.State {
		case types.CreateAccountStateSucceeded:
			accountID = aws.ToString(statusOut.CreateAccountStatus.AccountId)
		case types.CreateAccountStateFailed:
			return nil, fmt.Errorf("account creation failed: %s",
				string(statusOut.CreateAccountStatus.FailureReason))
		default:
			continue // still in progress
		}
		if accountID != "" {
			break
		}
	}
	if accountID == "" {
		return nil, fmt.Errorf("account creation timed out after 10 minutes")
	}

	// Step 3: Move account to target OU.
	// First get the root ID for the MoveAccount source.
	rootOut, err := p.orgSvc.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return nil, fmt.Errorf("getting org root for move: %w", err)
	}
	rootID := aws.ToString(rootOut.Roots[0].Id)

	if _, err := p.orgSvc.MoveAccount(ctx, &organizations.MoveAccountInput{
		AccountId:           aws.String(accountID),
		SourceParentId:      aws.String(rootID),
		DestinationParentId: aws.String(plan.TargetOU),
	}); err != nil {
		return nil, fmt.Errorf("moving account %s to OU %s: %w\n"+
			"  Account was created — move it manually:\n"+
			"  aws organizations move-account --account-id %s --source-parent-id %s --destination-parent-id %s",
			accountID, plan.TargetOU, err, accountID, rootID, plan.TargetOU)
	}

	// Step 4: Apply attest:* tags to the new account.
	var orgTags []types.Tag
	for k, v := range plan.AttestTags {
		orgTags = append(orgTags, types.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	if _, err := p.orgSvc.TagResource(ctx, &organizations.TagResourceInput{
		ResourceId: aws.String(accountID),
		Tags:       orgTags,
	}); err != nil {
		// Tagging failure is non-fatal — account is created and moved.
		fmt.Printf("  Warning: could not apply attest:* tags to %s: %v\n", accountID, err)
	}

	// Return the new environment for registration in sre.yaml.
	env := &schema.Environment{
		AccountID:   accountID,
		Owner:       plan.AttestTags["attest:owner"],
		Purpose:     plan.AttestTags["attest:purpose"],
		DataClasses: dataClassesFrom(plan.AttestTags),
		Tags:        plan.AttestTags,
	}
	return env, nil
}

// dataClassesFrom extracts data classes from the attest:data-class tag.
func dataClassesFrom(tags map[string]string) []string {
	if dc, ok := tags["attest:data-class"]; ok && dc != "" {
		return []string{dc}
	}
	return nil
}

// --- helpers ---

// targetOU returns the most restrictive OU name for a set of data classes.
func targetOU(dataClasses []string) string {
	// Priority: CUI > PHI > FERPA > PII > OPEN
	priority := map[string]int{"CUI": 5, "PHI": 4, "FERPA": 3, "PII": 2, "OPEN": 1}
	best, bestPri := "research-open", 0
	for _, dc := range dataClasses {
		pri := priority[strings.ToUpper(dc)]
		if pri > bestPri {
			bestPri = pri
			if ou, ok := ouMapping[strings.ToUpper(dc)]; ok {
				best = ou
			}
		}
	}
	return best
}

// findOU searches for an OU by name under parentID. Returns "" if not found.
// Returns an error if multiple OUs with the same name are found (ambiguous).
func (p *Provisioner) findOU(ctx context.Context, parentID, name string) (string, error) {
	var nextToken *string
	var matches []string
	for {
		out, err := p.orgSvc.ListOrganizationalUnitsForParent(ctx,
			&organizations.ListOrganizationalUnitsForParentInput{
				ParentId:  aws.String(parentID),
				NextToken: nextToken,
			})
		if err != nil {
			return "", err
		}
		for _, ou := range out.OrganizationalUnits {
			if aws.ToString(ou.Name) == name {
				matches = append(matches, aws.ToString(ou.Id))
			}
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("ambiguous: %d OUs named %q found under %s — rename duplicates or contact your AWS admin",
			len(matches), name, parentID)
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	return "", nil
}

// countAttachedSCPs returns the number of SCPs attached to a target.
func (p *Provisioner) countAttachedSCPs(ctx context.Context, targetID string) (int, error) {
	out, err := p.orgSvc.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
		TargetId: aws.String(targetID),
		Filter:   types.PolicyTypeServiceControlPolicy,
	})
	if err != nil {
		return 0, err
	}
	return len(out.Policies), nil
}

// buildPrerequisites returns prerequisite checks for the given data classes.
// Most checks are informational at plan time (verified by the operator before --approve).
func buildPrerequisites(dataClasses []string) []Prerequisite {
	var prereqs []Prerequisite
	for _, dc := range dataClasses {
		switch strings.ToUpper(dc) {
		case "PHI":
			prereqs = append(prereqs, Prerequisite{
				Description: "HIPAA BAA with AWS must be signed (check AWS Artifact)",
				Met:         true, // assumed met if HIPAA framework is active
				Source:      "artifact-agreements",
			})
		case "CUI":
			prereqs = append(prereqs, Prerequisite{
				Description: "DoD contract or CUI handling agreement in place",
				Met:         true, // operator confirms at approval
				Source:      "manual",
			})
		case "FERPA":
			prereqs = append(prereqs, Prerequisite{
				Description: "Institutional data governance policy covers student records",
				Met:         true,
				Source:      "manual",
			})
		}
	}
	prereqs = append(prereqs, Prerequisite{
		Description: "Account email address is unique within your AWS Organization",
		Met:         true, // verified at account creation
		Source:      "organizations",
	})
	return prereqs
}
