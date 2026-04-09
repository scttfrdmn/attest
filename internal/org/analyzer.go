// Package org reads an AWS Organization and maps it to the SRE model.
// The Organization IS the Secure Research Environment. Accounts within it
// are research environments that inherit org-level compliance posture.
package org

import (
	"context"
	"fmt"

	"github.com/scttfrdmn/attest/pkg/schema"
)

// OUNode represents a node in the org tree.
type OUNode struct {
	ID       string
	Name     string
	ParentID string
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

// AccountInfo is basic account metadata from Organizations API.
type AccountInfo struct {
	ID     string
	Name   string
	Email  string
	Status string // ACTIVE, SUSPENDED
	Tags   map[string]string
}

// Analyzer reads org topology, existing SCPs, and account metadata
// to build the SRE model.
type Analyzer struct {
	region string
}

// NewAnalyzer creates an org analyzer.
func NewAnalyzer(region string) *Analyzer {
	return &Analyzer{region: region}
}

// BuildSRE reads the full org tree and constructs the SRE model.
// This is the starting point for `attest init` and `attest scan`.
func (a *Analyzer) BuildSRE(ctx context.Context) (*schema.SRE, error) {
	// Step 1: DescribeOrganization → OrgID
	// Step 2: ListRoots → root OU
	// Step 3: Recursively ListOrganizationalUnitsForParent → full tree
	// Step 4: For each OU: ListPoliciesForTarget → attached SCPs
	// Step 5: For each OU: ListAccountsForParent → accounts
	// Step 6: For each account: ListTagsForResource → tags (data classes, owner, etc.)
	// Step 7: Map to SRE model.
	return nil, fmt.Errorf("not implemented")
}

// BuildOrgTree walks the full OU hierarchy.
func (a *Analyzer) BuildOrgTree(ctx context.Context) (*OUNode, error) {
	return nil, fmt.Errorf("not implemented")
}

// InventoryExistingSCPs collects all SCPs across the org.
// Used by the gap analyzer to determine which controls already have structural enforcement.
func (a *Analyzer) InventoryExistingSCPs(ctx context.Context) ([]AttachedSCP, error) {
	return nil, fmt.Errorf("not implemented")
}

// InventoryConfigRules collects existing Config rules across all accounts.
// Used to detect which controls already have drift monitoring.
func (a *Analyzer) InventoryConfigRules(ctx context.Context) (map[string][]string, error) {
	// Returns map of account_id → list of Config rule names.
	return nil, fmt.Errorf("not implemented")
}

// ResolveDataClasses determines which data classification tags are present
// in the org. This drives framework activation — if any account holds CUI,
// NIST 800-171 must be active.
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
