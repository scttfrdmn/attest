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

	"github.com/scttfrdmn/attest/pkg/schema"
)

// Request describes a new environment to provision.
type Request struct {
	Name        string   // e.g., "clinical-genomics-chen"
	Owner       string   // PI or lab
	Purpose     string   // e.g., "Clinical genomics data analysis"
	DataClasses []string // e.g., ["PHI", "CUI"]
	Tags        map[string]string
}

// Plan is the computed provisioning plan shown for approval.
type Plan struct {
	TargetOU       string // computed from data classes
	AccountName    string
	SCPsInherited  int    // from parent OU
	CedarEntities  int    // entities to register
	Prerequisites  []Prerequisite
	AllMet         bool
}

// Prerequisite is a check that must pass before provisioning.
type Prerequisite struct {
	Description string // e.g., "BAA signed for HIPAA workloads"
	Met         bool
	Source      string // e.g., "artifact-agreements", "principal-resolver"
}

// Provisioner creates compliant environments within the SRE.
type Provisioner struct {
	region string
}

// NewProvisioner creates an environment provisioner.
func NewProvisioner(region string) *Provisioner {
	return &Provisioner{region: region}
}

// ComputePlan determines the target OU, checks prerequisites, and
// returns a provisioning plan for approval.
func (p *Provisioner) ComputePlan(ctx context.Context, sre *schema.SRE, req *Request) (*Plan, error) {
	return nil, fmt.Errorf("not implemented")
}

// Execute creates the account, places it in the OU, applies tags,
// and registers Cedar entities. Rolls back on failure.
func (p *Provisioner) Execute(ctx context.Context, plan *Plan) (*schema.Environment, error) {
	return nil, fmt.Errorf("not implemented")
}
