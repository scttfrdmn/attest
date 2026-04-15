// Package iac generates Infrastructure-as-Code output from compiled policy artifacts.
// Supports Terraform modules so organizations deploy through existing IaC pipelines.
package iac

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// Generate writes the IaC modules to the output directory.
func (g *Generator) Generate(compiledDir string) error {
	switch g.format {
	case FormatTerraform:
		return g.generateTerraform(compiledDir)
	case FormatCDK:
		return fmt.Errorf("CDK output not yet implemented; use --output terraform")
	default:
		return fmt.Errorf("unsupported IaC format: %s", g.format)
	}
}

// generateTerraform produces a Terraform module for all compiled SCPs.
// Each SCP becomes an aws_organizations_policy resource attached to the org root.
func (g *Generator) generateTerraform(compiledDir string) error {
	scpDir := filepath.Join(compiledDir, "scps")
	entries, err := os.ReadDir(scpDir)
	if os.IsNotExist(err) {
		return fmt.Errorf("no compiled SCPs found in %s (run 'attest compile' first)", scpDir)
	}
	if err != nil {
		return err
	}

	if err := os.MkdirAll(g.outputDir, 0750); err != nil {
		return err
	}

	var b strings.Builder

	// Header.
	b.WriteString(`# Attest-generated Terraform module
# Auto-generated — do not edit manually
# Re-generate with: attest compile --output terraform

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_organizations_organization" "current" {}

`)

	// One resource block per compiled SCP.
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		resourceName := strings.ReplaceAll(id, "-", "_")

		b.WriteString(fmt.Sprintf(`resource "aws_organizations_policy" "%s" {
  name        = %q
  description = "Managed by attest — do not edit manually"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/scps/%s")
  tags = {
    managed_by = "attest"
  }
}

resource "aws_organizations_policy_attachment" "%s" {
  policy_id = aws_organizations_policy.%s.id
  target_id = data.aws_organizations_organization.current.roots[0].id
}

`, resourceName, id, e.Name(), resourceName, resourceName))
	}

	mainTF := filepath.Join(g.outputDir, "main.tf")
	if err := os.WriteFile(mainTF, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("writing main.tf: %w", err)
	}

	// Copy SCP JSON files into the terraform directory.
	tfSCPDir := filepath.Join(g.outputDir, "scps")
	if err := os.MkdirAll(tfSCPDir, 0750); err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(scpDir, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tfSCPDir, e.Name()), data, 0644); err != nil {
			return err
		}
	}

	return nil
}
