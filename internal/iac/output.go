// Package iac generates Infrastructure-as-Code output from compiled
// policy artifacts. Supports Terraform modules and CDK constructs
// so organizations deploy through existing IaC pipelines rather than
// a separate `attest apply` channel.
//
// `attest compile --output terraform` writes a Terraform module tree:
//   - SCPs (aws_organizations_policy + aws_organizations_policy_attachment)
//   - Config conformance packs
//   - EventBridge rules wiring CloudTrail → Cedar PDP
//   - Security service enablement (GuardDuty, Inspector, Macie, Security Hub)
//
// Every resource is tagged with managed_by=attest and the specific
// framework controls it satisfies.
package iac

import (
	"fmt"
)

// Format is the IaC output format.
type Format string

const (
	FormatTerraform Format = "terraform"
	FormatCDK       Format = "cdk"
)

// Generator produces IaC output from compiled policy artifacts.
type Generator struct {
	format    Format
	outputDir string
}

// NewGenerator creates an IaC output generator.
func NewGenerator(format Format, outputDir string) *Generator {
	return &Generator{format: format, outputDir: outputDir}
}

// Generate writes the IaC modules/constructs to the output directory.
func (g *Generator) Generate(compiledDir string) error {
	switch g.format {
	case FormatTerraform:
		return g.generateTerraform(compiledDir)
	case FormatCDK:
		return g.generateCDK(compiledDir)
	default:
		return fmt.Errorf("unsupported IaC format: %s", g.format)
	}
}

func (g *Generator) generateTerraform(compiledDir string) error {
	// TODO: Generate Terraform modules:
	//   - scps/main.tf (aws_organizations_policy resources)
	//   - config/main.tf (aws_config_conformance_pack)
	//   - eventbridge/main.tf (aws_cloudwatch_event_rule)
	//   - security/main.tf (GuardDuty, Inspector, Macie, Security Hub enablement)
	return fmt.Errorf("not implemented")
}

func (g *Generator) generateCDK(compiledDir string) error {
	// TODO: Generate Python CDK stack with constructs for each resource type.
	return fmt.Errorf("not implemented")
}
