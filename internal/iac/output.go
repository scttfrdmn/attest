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
// The outputDir is validated here to prevent path traversal even when called
// programmatically (not via the CLI, which has its own validation).
func (g *Generator) Generate(compiledDir string) error {
	// Defend against relative path traversal in outputDir.
	// Absolute paths are allowed (programmatic use); only relative paths that
	// escape via ".." are rejected. CLI callers independently restrict to
	// "terraform" or "cdk" which are always safe.
	if !filepath.IsAbs(g.outputDir) {
		if clean := filepath.Clean(g.outputDir); strings.HasPrefix(clean, "..") {
			return fmt.Errorf("iac: output directory escapes project: %s", g.outputDir)
		}
	}
	switch g.format {
	case FormatTerraform:
		return g.generateTerraform(compiledDir)
	case FormatCDK:
		return g.generateCDK(compiledDir)
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
	if err := os.WriteFile(mainTF, []byte(b.String()), 0640); err != nil {
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
		if err := os.WriteFile(filepath.Join(tfSCPDir, e.Name()), data, 0640); err != nil {
			return err
		}
	}

	return nil
}

// generateCDK produces an AWS CDK v2 TypeScript stack for all compiled SCPs.
// Output: .attest/compiled/cdk/stack.ts, cdk.json, package.json
func (g *Generator) generateCDK(compiledDir string) error {
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

	// Collect SCP file names for stack generation.
	// Validate each SCP ID before embedding into TypeScript to prevent code injection.
	var scpFiles []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if !isValidSCPID(id) {
			return fmt.Errorf("SCP ID %q contains characters unsafe for CDK TypeScript generation (allowed: a-z 0-9 - _)", id)
		}
		scpFiles = append(scpFiles, e.Name())
	}
	if len(scpFiles) == 0 {
		return fmt.Errorf("no SCP JSON files found in %s", scpDir)
	}

	// --- stack.ts ---
	var stack strings.Builder
	stack.WriteString(`// Attest-generated AWS CDK v2 stack
// Auto-generated — do not edit manually
// Re-generate with: attest compile --output cdk

import * as cdk from 'aws-cdk-lib';
import * as organizations from 'aws-cdk-lib/aws-organizations';
import * as fs from 'fs';
import * as path from 'path';

export class AttestSCPStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Discover the org root ID at deploy time.
    // Note: Organizations CDK constructs require the management account.
    const orgResource = new cdk.custom_resources.AwsCustomResource(this, 'OrgRoot', {
      onUpdate: {
        service: 'Organizations',
        action: 'listRoots',
        physicalResourceId: cdk.custom_resources.PhysicalResourceId.fromResponse('Roots.0.Id'),
      },
      policy: cdk.custom_resources.AwsCustomResourcePolicy.fromSdkCalls({
        resources: cdk.custom_resources.AwsCustomResourcePolicy.ANY_RESOURCE,
      }),
    });
    const rootId = orgResource.getResponseField('Roots.0.Id');

`)

	for _, f := range scpFiles {
		id := strings.TrimSuffix(f, ".json")
		resourceID := toCDKResourceID(id)
		stack.WriteString(fmt.Sprintf(`    // SCP: %s
    const policy%s = new organizations.CfnPolicy(this, %q, {
      name: %q,
      type: 'SERVICE_CONTROL_POLICY',
      description: 'Managed by attest — do not edit manually',
      content: fs.readFileSync(path.join(__dirname, 'scps', %q), 'utf8'),
      tags: [{ key: 'managed_by', value: 'attest' }],
    });

    new organizations.CfnPolicyAttachment(this, %q, {
      policyId: policy%s.attrId,
      targetId: rootId,
    });

`, id, resourceID, resourceID, id, f, resourceID+"Attach", resourceID))
	}

	stack.WriteString(`  }
}

const app = new cdk.App();
new AttestSCPStack(app, 'AttestSCPStack', {
  description: 'Attest-managed Service Control Policies',
});
app.synth();
`)

	if err := os.WriteFile(filepath.Join(g.outputDir, "stack.ts"), []byte(stack.String()), 0640); err != nil {
		return fmt.Errorf("writing stack.ts: %w", err)
	}

	// --- cdk.json ---
	cdkJSON := `{
  "app": "npx ts-node stack.ts",
  "context": {
    "@aws-cdk/core:enableStackNameDuplicates": true
  }
}
`
	if err := os.WriteFile(filepath.Join(g.outputDir, "cdk.json"), []byte(cdkJSON), 0640); err != nil {
		return fmt.Errorf("writing cdk.json: %w", err)
	}

	// --- package.json ---
	pkgJSON := `{
  "name": "attest-scp-stack",
  "version": "1.0.0",
  "description": "Attest-generated CDK stack for Service Control Policies",
  "scripts": {
    "build": "npx tsc",
    "deploy": "npx cdk deploy",
    "diff": "npx cdk diff",
    "destroy": "npx cdk destroy"
  },
  "dependencies": {
    "aws-cdk-lib": "^2.0.0",
    "constructs": "^10.0.0"
  },
  "devDependencies": {
    "ts-node": "^10.0.0",
    "typescript": "^5.0.0"
  }
}
`
	if err := os.WriteFile(filepath.Join(g.outputDir, "package.json"), []byte(pkgJSON), 0640); err != nil {
		return fmt.Errorf("writing package.json: %w", err)
	}

	// --- tsconfig.json ---
	tsconfig := `{
  "compilerOptions": {
    "target": "ES2018",
    "module": "commonjs",
    "lib": ["ES2018"],
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "outDir": "./dist"
  }
}
`
	if err := os.WriteFile(filepath.Join(g.outputDir, "tsconfig.json"), []byte(tsconfig), 0640); err != nil {
		return fmt.Errorf("writing tsconfig.json: %w", err)
	}

	// Copy SCP JSON files into the CDK directory.
	cdkSCPDir := filepath.Join(g.outputDir, "scps")
	if err := os.MkdirAll(cdkSCPDir, 0750); err != nil {
		return err
	}
	for _, f := range scpFiles {
		data, err := os.ReadFile(filepath.Join(scpDir, f))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(cdkSCPDir, f), data, 0640); err != nil {
			return err
		}
	}

	return nil
}

// isValidSCPID validates that an SCP ID contains only safe characters for use
// in generated TypeScript identifiers and template strings.
// Only lowercase alphanumeric and hyphens are allowed — no quotes, backticks,
// template literals, or TypeScript metacharacters.
func isValidSCPID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// toCDKResourceID converts a kebab-case SCP ID like "attest-scp-01" to a
// CamelCase CDK resource ID like "AttestScp01".
func toCDKResourceID(id string) string {
	parts := strings.Split(id, "-")
	var b strings.Builder
	for _, p := range parts {
		if len(p) > 0 {
			b.WriteString(strings.ToUpper(p[:1]) + p[1:])
		}
	}
	return b.String()
}

// GenerateKyverno writes a Kyverno ClusterPolicy requiring cosign-verified container
// images in the SRE. The policy is placed in outputDir/kyverno/require-signed-images.yaml.
//
// This satisfies CMMC/NIST 800-171 controls:
//   - 3.14.2 — malicious code protection (only signed/verified images run)
//   - SI.L3-3.14.3e — software, firmware integrity (cryptographic protection)
//   - SI.L3-3.14.4e — behavioral malware analysis (supply chain provenance)
//
// The policy requires keyless (OIDC) cosign signatures issued by GitHub Actions,
// matching the Sigstore/Rekor ecosystem used in the attest release pipeline.
// Customize the subject glob to match your organization's CI/CD identity.
func GenerateKyverno(orgID, ecrRegistry, ciSubjectGlob, outputDir string) error {
	if err := os.MkdirAll(filepath.Join(outputDir, "kyverno"), 0750); err != nil {
		return fmt.Errorf("creating kyverno dir: %w", err)
	}

	if ecrRegistry == "" {
		ecrRegistry = "*.dkr.ecr.*.amazonaws.com/*"
	}
	if ciSubjectGlob == "" {
		ciSubjectGlob = "https://github.com/*"
	}

	policy := fmt.Sprintf(`# Kyverno ClusterPolicy: require cosign-verified container images
# Generated by attest for org %s
# Controls: NIST 800-171 3.14.2, SI.L3-3.14.3e, SI.L3-3.14.4e
#
# This policy blocks any Pod from running an image that does not have a valid
# keyless cosign signature issued by GitHub Actions via Sigstore/Rekor.
#
# Customize:
#   image:   Change the ECR registry glob pattern to match your registry
#   subject: Change to your CI/CD OIDC identity (e.g., your GitHub org)
#   issuer:  Update if using a different OIDC provider
#
# Deploy: kubectl apply -f require-signed-images.yaml
# Test:   kubectl run test --image=<unsigned-image>  # should be blocked
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: attest-require-signed-images
  annotations:
    policies.kyverno.io/title: Require Signed Container Images
    policies.kyverno.io/category: Software Supply Chain Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Requires all container images from the organizational ECR registry to have
      a valid cosign keyless signature. Satisfies NIST SP 800-171 §3.14.2 (malicious
      code protection) and CMMC Level 3 SI.L3-3.14.3e (software integrity).
      Generated by attest for org: %s
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - %q
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: %q
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
          mutateDigest: true
          required: true
`, orgID, orgID, ecrRegistry, ciSubjectGlob)

	outPath := filepath.Join(outputDir, "kyverno", "require-signed-images.yaml")
	if err := os.WriteFile(outPath, []byte(policy), 0640); err != nil {
		return fmt.Errorf("writing kyverno policy: %w", err)
	}
	return nil
}
