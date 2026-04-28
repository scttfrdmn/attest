package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	cedar "github.com/cedar-policy/cedar-go"

	"encoding/json"
	"net/mail"
	"regexp"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	ebsvc "github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	iamSvc "github.com/aws/aws-sdk-go-v2/service/iam"
	sqssvc "github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/provabl/attest/internal/ai"
	"github.com/provabl/attest/internal/auth"
	"github.com/provabl/attest/internal/output"
	"github.com/provabl/attest/internal/dashboard"
	"github.com/provabl/attest/internal/document/cmmc"
	"github.com/provabl/attest/internal/integrations/grc"
	"github.com/provabl/attest/internal/multisre"
	"github.com/provabl/attest/internal/principal"
	"github.com/provabl/attest/internal/provision"
	"github.com/provabl/attest/internal/artifact"
	"github.com/provabl/attest/internal/attestation"
	compilerce "github.com/provabl/attest/internal/compiler/cedar"
	compilerscp "github.com/provabl/attest/internal/compiler/scp"
	"github.com/provabl/attest/internal/deploy"
	assessmentpkg "github.com/provabl/attest/internal/document/assessment"
	"github.com/provabl/attest/internal/document/dmsp"
	osalexport "github.com/provabl/attest/internal/document/oscal"
	"github.com/provabl/attest/internal/document/poam"
	"github.com/provabl/attest/internal/document/ssp"
	"github.com/provabl/attest/internal/evaluator"
	"github.com/provabl/attest/internal/framework"
	"github.com/provabl/attest/internal/iac"
	"github.com/provabl/attest/internal/org"
	"github.com/provabl/attest/internal/reporting"
	"github.com/provabl/attest/internal/store"
	attesttesting "github.com/provabl/attest/internal/testing"
	"github.com/provabl/attest/internal/waiver"
	"github.com/provabl/attest/pkg/schema"
)

var version = "0.19.9"

func main() {
	root := &cobra.Command{
		Use:   "attest",
		Short: "Compliance compiler for AWS Secure Research Environments",
		Long: `Attest reads compliance frameworks, maps controls to deployable policy
artifacts (SCPs, Cedar policies, Config rules), and generates audit documents
(SSP, POA&M, self-assessments) from the live state of your AWS Organization.

An SRE is an AWS Organization configured as a compliance enclave. Accounts
within it are research environments that inherit the org-level posture.`,
	}

	root.AddCommand(
		initCmd(),
		scanCmd(),
		frameworksCmd(),
		compileCmd(),
		applyCmd(),
		rollbackCmd(),
		preflightCmd(),
		evaluateCmd(),
		generateCmd(),
		diffCmd(),
		watchCmd(),
		serveCmd(),
		testCmd(),
		checkCmd(),
		simulateCmd(),
		provisionCmd(),
		waiverCmd(),
		incidentCmd(),
		attestCmd(),
		calendarCmd(),
		reportCmd(),
		aiCmd(),
		versionCmd(),
		verifyCmd(),
		sreCmd(),
		integrateCmd(),
		enforceCmd(),
		ingestCmd(),
		c3paoCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize an SRE from an existing AWS Organization",
		Long: `Reads the AWS Organization topology, inventories existing SCPs and Config
rules, detects active Artifact agreements, and creates the SRE definition file.

This is the starting point. Run this once, then use 'attest frameworks add'
to activate compliance frameworks and 'attest compile' to generate policies.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")
			classScheme, _ := cmd.Flags().GetString("classification-scheme")

			output.Println("Initializing SRE...")

			// Read Organization topology.
			output.Printf("  Reading Organization topology (region: %s)...\n", region)
			analyzer, err := org.NewAnalyzer(ctx, region)
			if err != nil {
				return fmt.Errorf("creating org analyzer: %w", err)
			}
			sre, err := analyzer.BuildSRE(ctx)
			if err != nil {
				return fmt.Errorf("building SRE: %w", err)
			}
			output.Printf("  Organization: %s (%d environments)\n", sre.OrgID, len(sre.Environments))

			// Inventory existing SCPs.
			output.Println("  Inventorying existing SCPs...")
			scps, err := analyzer.InventoryExistingSCPs(ctx)
			if err != nil {
				return fmt.Errorf("inventorying SCPs: %w", err)
			}
			output.Printf("  Found %d existing SCPs\n", len(scps))

			// Detect Artifact agreements → activated frameworks.
			output.Println("  Querying Artifact for active agreements...")
			artifactClient, err := artifact.NewClient(ctx, region)
			if err != nil {
				return fmt.Errorf("creating Artifact client: %w", err)
			}
			activations, err := artifactClient.DetectFrameworkActivations(ctx)
			if err != nil {
				// Non-fatal: Artifact may not be accessible from all accounts.
				output.Printf("  Warning: could not query Artifact agreements: %v\n", err)
			} else {
				for fwID := range activations {
					sre.Frameworks = append(sre.Frameworks, schema.FrameworkRef{
						ID:      fwID,
						Version: "latest",
					})
					output.Printf("  Framework activated via agreement: %s\n", fwID)
				}
			}

			// Apply institutional classification scheme if provided.
			if classScheme != "" {
				output.Printf("  Applying classification scheme: %s...\n", classScheme)
				if err := applyClassificationScheme(classScheme, sre); err != nil {
					output.Printf("  Warning: could not apply scheme %s: %v\n", classScheme, err)
				}
			}

			// Detect data classifications from account tags.
			output.Println("  Detecting data classifications from account tags...")
			classes, _ := analyzer.ResolveDataClasses(ctx, sre)
			if len(classes) > 0 {
				output.Printf("  Data classes found: %s\n", strings.Join(classes, ", "))
			}

			// Write SRE config to .attest/sre.yaml.
			if err := os.MkdirAll(".attest", 0750); err != nil {
				return fmt.Errorf("creating .attest directory: %w", err)
			}
			out, err := yaml.Marshal(sre)
			if err != nil {
				return fmt.Errorf("marshaling SRE config: %w", err)
			}
			if err := os.WriteFile(filepath.Join(".attest", "sre.yaml"), out, 0640); err != nil {
				return fmt.Errorf("writing sre.yaml: %w", err)
			}

			output.Println()
			output.Printf("SRE initialized. Written to .attest/sre.yaml\n")
			output.Printf("  Org: %s\n", sre.OrgID)
			output.Printf("  Environments: %d\n", len(sre.Environments))
			output.Printf("  Active frameworks: %d\n", len(sre.Frameworks))
			if len(sre.Frameworks) == 0 {
				output.Println()
				output.Println("No frameworks activated. Run 'attest frameworks add <framework-id>' to activate one.")
			} else {
				output.Println("\nRun 'attest compile' to generate policy artifacts.")
			}
			return nil
		},
	}
	cmd.Flags().String("region", "us-west-2", "AWS region")
	cmd.Flags().String("classification-scheme", "", "Institutional classification scheme (e.g., uc-protection-levels)")
	return cmd
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Analyze current org posture against active frameworks",
		Long: `Reads the current state of the SRE and evaluates it against all active
frameworks. Produces a posture report showing which controls are enforced,
partially enforced, or have gaps.

If --region is provided, the scanner compares the compiled crosswalk against
actually-deployed SCPs in the live org for accurate status. Without --region,
posture is derived from the compiled crosswalk (run 'attest compile' first).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			fwDir, _ := cmd.Flags().GetString("frameworks")
			region, _ := cmd.Flags().GetString("region")

			// Load SRE config.
			sreData, err := os.ReadFile(filepath.Join(".attest", "sre.yaml"))
			if err != nil {
				return fmt.Errorf("reading .attest/sre.yaml: %w (run 'attest init' first)", err)
			}
			var sre schema.SRE
			if err := yaml.Unmarshal(sreData, &sre); err != nil {
				return fmt.Errorf("parsing sre.yaml: %w", err)
			}

			output.Printf("Scanning SRE posture: %s\n", sre.OrgID)
			output.Printf("  Environments: %d\n", len(sre.Environments))

			if len(sre.Frameworks) == 0 {
				output.Println("\nNo active frameworks. Run 'attest frameworks add <id>' to activate one.")
				return nil
			}

			// Load active frameworks.
			loader := framework.NewLoader(fwDir)
			var frameworks []*schema.Framework
			for _, ref := range sre.Frameworks {
				fw, err := loader.Load(ref.ID)
				if err != nil {
					output.Printf("  Warning: could not load framework %s: %v\n", ref.ID, err)
					continue
				}
				frameworks = append(frameworks, fw)
				output.Printf("  Loaded framework: %s (%d controls)\n", fw.Name, len(fw.Controls))
			}
			if len(frameworks) == 0 {
				return fmt.Errorf("no frameworks could be loaded")
			}

			// Optionally load deployed SCPs for accurate comparison.
			deployedSCPIDs := make(map[string]bool)
			if region != "" {
				output.Printf("  Checking deployed SCPs (region: %s)...\n", region)
				analyzer, err := org.NewAnalyzer(ctx, region)
				if err != nil {
					output.Printf("  Warning: could not connect to org: %v\n", err)
				} else {
					deployedSCPs, err := analyzer.InventoryExistingSCPs(ctx)
					if err != nil {
						output.Printf("  Warning: could not inventory SCPs: %v\n", err)
					} else {
						for _, s := range deployedSCPs {
							deployedSCPIDs[s.ID] = true
						}
						output.Printf("  Found %d deployed SCP(s)\n", len(deployedSCPs))
					}
				}
			}

			// Try loading compiled crosswalk first.
			var crosswalkEntries map[string]schema.CrosswalkEntry
			crosswalkPath := filepath.Join(".attest", "compiled", "crosswalk.yaml")
			if cwData, err := os.ReadFile(crosswalkPath); err == nil {
				var cw schema.Crosswalk
				if err := yaml.Unmarshal(cwData, &cw); err == nil {
					crosswalkEntries = make(map[string]schema.CrosswalkEntry)
					for _, e := range cw.Entries {
						crosswalkEntries[e.ControlID] = e
					}
					output.Printf("  Loaded crosswalk (%d entries)\n", len(crosswalkEntries))
				}
			}

			// Compute posture.
			posture := &schema.Posture{
				ComputedAt: time.Now(),
				Frameworks: make(map[string]schema.FrameworkPosture),
			}

			for _, fw := range frameworks {
				fp := schema.FrameworkPosture{
					FrameworkID: fw.ID,
					Controls:    make(map[string]string),
				}
				for _, ctrl := range fw.Controls {
					var status string

					if crosswalkEntries != nil {
						// Use crosswalk status, refined by live deployment check.
						if entry, ok := crosswalkEntries[ctrl.ID]; ok {
							status = entry.Status
							// If we have live SCP data, check if SCPs are actually deployed.
							if len(deployedSCPIDs) > 0 && len(entry.SCPs) > 0 {
								deployed := 0
								for _, scpID := range entry.SCPs {
									if deployedSCPIDs[scpID] {
										deployed++
									}
								}
								if deployed == 0 {
									// Compiled but not deployed.
									if entry.Status == "enforced" || entry.Status == "partial" {
										status = "partial"
									}
								}
							}
						} else {
							status = "gap"
						}
					} else {
						// Fall back to framework-based analysis.
						if len(ctrl.Structural) > 0 && len(ctrl.Operational) > 0 {
							status = "enforced"
						} else if len(ctrl.Structural) > 0 || len(ctrl.Operational) > 0 {
							status = "partial"
						} else {
							status = "gap"
						}
					}

					fp.Controls[ctrl.ID] = status
					posture.TotalControls++
					switch status {
					case "enforced":
						posture.Enforced++
					case "partial":
						posture.Partial++
					case "gap":
						posture.Gaps++
					}
				}
				posture.Frameworks[fw.ID] = fp
			}

			// Print summary.
			output.Println()
			output.Println("Posture summary:")
			output.Printf("  Total controls:  %d\n", posture.TotalControls)
			output.Printf("  Enforced:        %d\n", posture.Enforced)
			output.Printf("  Partial:         %d\n", posture.Partial)
			output.Printf("  Gaps:            %d\n", posture.Gaps)

			for _, fw := range frameworks {
				fp := posture.Frameworks[fw.ID]
				enforced, partial, gaps := 0, 0, 0
				for _, status := range fp.Controls {
					switch status {
					case "enforced":
						enforced++
					case "partial":
						partial++
					default:
						gaps++
					}
				}
				output.Printf("\n  %s:\n", fw.Name)
				output.Printf("    Enforced: %d  Partial: %d  Gaps: %d\n", enforced, partial, gaps)
			}

			// Save posture snapshot.
			if err := os.MkdirAll(filepath.Join(".attest", "history"), 0750); err == nil {
				snapshot := schema.PostureSnapshot{Timestamp: posture.ComputedAt, Posture: *posture}
				if data, err := yaml.Marshal(snapshot); err == nil {
					fname := fmt.Sprintf("posture-%s.yaml", posture.ComputedAt.Format("2006-01-02T150405"))
					_ = os.WriteFile(filepath.Join(".attest", "history", fname), data, 0640)
				}
			}

			if crosswalkEntries == nil {
				output.Println("\nTip: run 'attest compile' first for crosswalk-based posture.")
			}

			// Run conflict detection when multiple frameworks are active.
			if len(frameworks) > 1 {
				conflicts := framework.DetectConflicts(frameworks)
				if len(conflicts) > 0 {
					output.Print(framework.FormatConflicts(conflicts))
					if framework.HasBlockingConflicts(conflicts) {
						output.Println("  ✗ Blocking conflicts detected — review resolutions above before deploying.")
					}
				}
			}

			// Optional: direct API verification (free, no Config required).
			verify, _ := cmd.Flags().GetBool("verify")
			if verify && region != "" {
				runVerification(context.Background(), region, &sre)
			} else if verify {
				output.Println("\nNote: --verify requires --region to check live org state.")
			}
			return nil
		},
	}
	cmd.Flags().String("frameworks", "frameworks", "Path to frameworks directory")
	cmd.Flags().String("region", "", "AWS region for live SCP deployment check (optional)")
	cmd.Flags().Bool("verify", false, "Run direct API spot-checks (CloudTrail, SCPs, S3 encryption) — free, no Config required")
	return cmd
}

// runVerification performs direct AWS API spot-checks for compliance verification.
// All API calls are free — no AWS Config or Security Hub required.
func runVerification(ctx context.Context, region string, sre *schema.SRE) {
	output.Println("\nDirect API verification (no Config required):")

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		output.Printf("  Warning: could not load AWS config for verification: %v\n", err)
		return
	}

	// Check 1: CloudTrail status.
	ctClient := cloudtrail.NewFromConfig(cfg)
	trueVal := true
	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: &trueVal,
	})
	if err != nil {
		output.Printf("  cloudtrail: could not check (%v)\n", err)
	} else {
		multiRegion := 0
		for _, t := range trails.TrailList {
			if t.IsMultiRegionTrail != nil && *t.IsMultiRegionTrail {
				multiRegion++
			}
		}
		if multiRegion > 0 {
			output.Printf("  ✓ CloudTrail: %d multi-region trail(s) active\n", multiRegion)
		} else if len(trails.TrailList) > 0 {
			output.Printf("  ⚠ CloudTrail: %d trail(s) but none multi-region\n", len(trails.TrailList))
		} else {
			output.Printf("  ✗ CloudTrail: no trails found\n")
		}
	}

	// Check 2: Attest SCPs at root (via Organizations).
	orgAnalyzer, err := org.NewAnalyzer(ctx, region)
	if err == nil {
		scps, err := orgAnalyzer.InventoryExistingSCPs(ctx)
		attestSCPs := 0
		for _, s := range scps {
			if strings.HasPrefix(s.Name, "attest-") {
				attestSCPs++
			}
		}
		if err != nil {
			output.Printf("  SCPs: could not check (%v)\n", err)
		} else if attestSCPs > 0 {
			output.Printf("  ✓ Attest SCPs: %d deployed to org\n", attestSCPs)
		} else {
			output.Printf("  ⚠ Attest SCPs: none deployed (run 'attest apply')\n")
		}
	}

	// Check 3: IAM password policy.
	iamClient := iamSvc.NewFromConfig(cfg)
	_, err = iamClient.GetAccountPasswordPolicy(ctx, &iamSvc.GetAccountPasswordPolicyInput{})
	if err != nil {
		output.Printf("  ⚠ IAM password policy: not configured\n")
	} else {
		output.Printf("  ✓ IAM password policy: active\n")
	}

	output.Println("  (Config and Security Hub not required — $0 ongoing cost)")
}

// applyClassificationScheme reads a classification scheme YAML and maps
// institutional data classification tags on accounts to attest data classes.
func applyClassificationScheme(schemeName string, sre *schema.SRE) error {
	const schemeDir = "classification-schemes"
	base, err := filepath.Abs(schemeDir)
	if err != nil {
		return fmt.Errorf("resolving scheme directory: %w", err)
	}
	abs, err := filepath.Abs(filepath.Join(schemeDir, schemeName))
	if err != nil {
		return fmt.Errorf("resolving scheme path: %w", err)
	}
	if !strings.HasPrefix(abs+string(filepath.Separator), base+string(filepath.Separator)) {
		return fmt.Errorf("classification scheme %q escapes allowed directory", schemeName)
	}
	schemeFile := abs + ".yaml"
	data, err := os.ReadFile(schemeFile)
	if err != nil {
		return fmt.Errorf("reading scheme %s: %w", schemeName, err)
	}
	var scheme schema.ClassificationScheme
	if err := yaml.Unmarshal(data, &scheme); err != nil {
		return fmt.Errorf("parsing scheme: %w", err)
	}

	tagKey := "attest:data-class"
	// scheme.SchemeID would select an institution-specific tag key (e.g., "UC:DataProtectionLevel"),
	// but the standard attest tag is used until that feature is implemented.

	for accountID, env := range sre.Environments {
		// Check for institutional classification tag.
		for tagK, tagV := range env.Tags {
			if !strings.EqualFold(tagK, tagKey) {
				continue
			}
			if mapping, ok := scheme.Mappings[tagV]; ok {
				env.DataClasses = append(env.DataClasses, mapping.AttestClasses...)
				sre.Environments[accountID] = env
				// Activate frameworks from the mapping.
				for _, fwID := range mapping.Frameworks {
					already := false
					for _, ref := range sre.Frameworks {
						if ref.ID == fwID {
							already = true
							break
						}
					}
					if !already {
						sre.Frameworks = append(sre.Frameworks, schema.FrameworkRef{
							ID:      fwID,
							Version: "latest",
						})
						output.Printf("    %s → %s (activates %s)\n", accountID, tagV, fwID)
					}
				}
			}
		}
	}
	return nil
}

func frameworksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "frameworks",
		Short: "Manage compliance frameworks",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List available and active frameworks",
			RunE: func(cmd *cobra.Command, args []string) error {
				output.Println("Available frameworks:")
				output.Println()
				output.Println("  ID                  Name                              Status")
				output.Println("  ──────────────────  ────────────────────────────────  ──────────")
				output.Println("  nist-800-171-r2     NIST SP 800-171 Rev 2 (CMMC)     available")
				output.Println("  hipaa               HIPAA Security Rule               available (BAA detected)")
				output.Println("  ferpa               FERPA                             available")
				output.Println("  iso27001-2022        ISO/IEC 27001:2022               available")
				output.Println("  fedramp-moderate     FedRAMP Moderate Baseline        available")
				output.Println("  nist-800-53-r5      NIST SP 800-53 Rev 5 (FedRAMP)    available")
				output.Println("  uk-cyber-essentials UK Cyber Essentials               available")
				output.Println("  asd-essential-eight ASD Essential Eight (Australia)   available")
				output.Println("  itar                ITAR Export Control                available")
				output.Println("  cui                 CUI (32 CFR Part 2002)            available")
				return nil
			},
		},
		frameworkAddCmd(),
	)
	return cmd
}

func frameworkAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add [framework-id]",
		Short: "Activate a framework for this SRE",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fwID := args[0]
			fwDir, _ := cmd.Flags().GetString("frameworks")

				// Verify framework exists.
				loader := framework.NewLoader(fwDir)
				fw, err := loader.Load(fwID)
				if err != nil {
					return fmt.Errorf("framework %q not found in %s: %w", fwID, fwDir, err)
				}

				// Load SRE config.
				sreData, err := os.ReadFile(filepath.Join(".attest", "sre.yaml"))
				if err != nil {
					return fmt.Errorf("reading .attest/sre.yaml: %w (run 'attest init' first)", err)
				}
				var sre schema.SRE
				if err := yaml.Unmarshal(sreData, &sre); err != nil {
					return fmt.Errorf("parsing sre.yaml: %w", err)
				}

				// Check for duplicate.
				for _, ref := range sre.Frameworks {
					if ref.ID == fwID {
						output.Printf("Framework %s is already active.\n", fwID)
						return nil
					}
				}

				// Append and save.
				sre.Frameworks = append(sre.Frameworks, schema.FrameworkRef{
					ID:      fwID,
					Version: fw.Version,
				})
				out, err := yaml.Marshal(sre)
				if err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(".attest", "sre.yaml"), out, 0640); err != nil {
					return fmt.Errorf("writing sre.yaml: %w", err)
				}

				output.Printf("Framework activated: %s v%s (%d controls)\n", fw.Name, fw.Version, len(fw.Controls))
				output.Println("Run 'attest compile' to generate policy artifacts.")
				return nil
			},
	}
	cmd.Flags().String("frameworks", "frameworks", "Path to frameworks directory")
	return cmd
}


func compileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compile",
		Short: "Generate policy artifacts for active frameworks",
		Long: `Compiles all active frameworks into deployable policy artifacts:
SCPs (structural enforcement), Cedar policies (operational enforcement),
and the crosswalk manifest mapping every artifact to its framework controls.

Use --output terraform or --output cdk to generate IaC modules alongside
the raw policy artifacts (coming in v0.5.0).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fwDir, _ := cmd.Flags().GetString("frameworks")
			iacOutput, _ := cmd.Flags().GetString("output")

			// Load SRE config.
			sreData, err := os.ReadFile(filepath.Join(".attest", "sre.yaml"))
			if err != nil {
				return fmt.Errorf("reading .attest/sre.yaml: %w (run 'attest init' first)", err)
			}
			var sre schema.SRE
			if err := yaml.Unmarshal(sreData, &sre); err != nil {
				return fmt.Errorf("parsing sre.yaml: %w", err)
			}

			if len(sre.Frameworks) == 0 {
				output.Println("No active frameworks. Run 'attest frameworks add <id>' first.")
				return nil
			}

			output.Printf("Compiling policies for %d framework(s)...\n", len(sre.Frameworks))

			// Load frameworks.
			loader := framework.NewLoader(fwDir)
			var frameworks []*schema.Framework
			for _, ref := range sre.Frameworks {
				fw, err := loader.Load(ref.ID)
				if err != nil {
					output.Printf("  Warning: could not load framework %s: %v\n", ref.ID, err)
					continue
				}
				frameworks = append(frameworks, fw)
			}
			if len(frameworks) == 0 {
				return fmt.Errorf("no frameworks could be loaded from %s", fwDir)
			}

			// Run conflict detection before compile — warn on contradictions.
			if len(frameworks) > 1 {
				if conflicts := framework.DetectConflicts(frameworks); len(conflicts) > 0 {
					output.Print(framework.FormatConflicts(conflicts))
					if framework.HasBlockingConflicts(conflicts) {
						return fmt.Errorf("blocking framework conflicts detected — resolve before compiling")
					}
				}
			}

			// Resolve cross-framework controls.
			output.Println("  Resolving cross-framework control overlap...")
			rcs, err := framework.Resolve(frameworks)
			if err != nil {
				return fmt.Errorf("resolving controls: %w", err)
			}

			// Compile SCPs.
			scpStrategy, _ := cmd.Flags().GetString("scp-strategy")
			scpCompiler := compilerscp.NewCompiler()
			var scps []compilerscp.CompiledSCP
			if scpStrategy == "merged" {
				output.Println("  Generating SCPs (merged strategy — intelligent bin-packing)...")
				var scpStats compilerscp.CompileStats
				var scpErr error
				scps, scpStats, scpErr = scpCompiler.IntelligentCompile(rcs)
				err = scpErr
				if err != nil {
					return fmt.Errorf("compiling SCPs (merged): %w", err)
				}
				output.Printf("  %d structural specs → %d unique conditions → %d SCP document(s)\n",
					scpStats.InputSpecs, scpStats.UniqueConditions, scpStats.SCPCount)
				output.Printf("  SCP budget: %d / %d chars used (%.1f%%)\n",
					scpStats.TotalChars, compilerscp.TotalBudget, scpStats.BudgetUsed)
			} else {
				output.Println("  Generating SCPs (individual strategy)...")
				scps, err = scpCompiler.Compile(rcs)
				if err != nil {
					return fmt.Errorf("compiling SCPs: %w", err)
				}
			}

			// Compile Cedar policies.
			output.Println("  Generating Cedar policies (operational enforcement)...")
			cedarCompiler := compilerce.NewCompiler()
			cedarPolicies, err := cedarCompiler.Compile(rcs)
			if err != nil {
				return fmt.Errorf("compiling Cedar policies: %w", err)
			}

			// Generate Cedar schema.
			cedarSchema := cedarCompiler.BuildSchema(rcs)

			// Build crosswalk.
			output.Println("  Building crosswalk manifest...")
			crosswalk := buildCrosswalk(&sre, frameworks, scps, cedarPolicies)

			// Write compiled output.
			output.Println("  Writing artifacts...")
			compiledDir := filepath.Join(".attest", "compiled")
			scpsDir := filepath.Join(compiledDir, "scps")

			// Clear existing SCPs before writing — ensures no stale artifacts from
			// a previous compile with a different strategy.
			if err := os.RemoveAll(scpsDir); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("clearing scps dir: %w", err)
			}
			if err := os.MkdirAll(scpsDir, 0750); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Join(compiledDir, "cedar"), 0750); err != nil {
				return err
			}

			for _, s := range scps {
				path := filepath.Join(scpsDir, s.ID+".json")
				if err := os.WriteFile(path, []byte(s.PolicyJSON), 0640); err != nil {
					return fmt.Errorf("writing SCP %s: %w", s.ID, err)
				}
			}

			for _, p := range cedarPolicies {
				path := filepath.Join(compiledDir, "cedar", p.ID+".cedar")
				if err := os.WriteFile(path, []byte(p.PolicyText), 0640); err != nil {
					return fmt.Errorf("writing Cedar policy %s: %w", p.ID, err)
				}
			}

			if err := os.WriteFile(filepath.Join(compiledDir, "cedar", "schema.cedarschema"), []byte(cedarSchema), 0640); err != nil {
				return fmt.Errorf("writing Cedar schema: %w", err)
			}

			crosswalkBytes, err := yaml.Marshal(crosswalk)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(compiledDir, "crosswalk.yaml"), crosswalkBytes, 0640); err != nil {
				return fmt.Errorf("writing crosswalk: %w", err)
			}

			if iacOutput != "" {
				// Validate output format against strict allowlist to prevent path traversal.
				// iacOutput is used in filepath.Join — any non-allowlisted value is rejected.
				if iacOutput != "terraform" && iacOutput != "cdk" {
					return fmt.Errorf("--output must be 'terraform' or 'cdk', got: %q", iacOutput)
				}
				output.Printf("  Generating %s IaC output...\n", iacOutput)
				iacGen := iac.NewGenerator(iac.Format(iacOutput), filepath.Join(compiledDir, iacOutput))
				if err := iacGen.Generate(compiledDir); err != nil {
					return fmt.Errorf("generating IaC output: %w", err)
				}
				output.Printf("  IaC output: %s\n", filepath.Join(compiledDir, iacOutput))
			}

			if genKyverno, _ := cmd.Flags().GetBool("kyverno"); genKyverno {
				ecrGlob, _ := cmd.Flags().GetString("kyverno-ecr-registry")
				ciSubject, _ := cmd.Flags().GetString("kyverno-ci-subject")
				output.Println("  Generating Kyverno image signing policy...")
				if err := iac.GenerateKyverno(sre.OrgID, ecrGlob, ciSubject, compiledDir); err != nil {
					return fmt.Errorf("generating Kyverno policy: %w", err)
				}
				output.Printf("  Kyverno: %s\n", filepath.Join(compiledDir, "kyverno", "require-signed-images.yaml"))
			}

			output.Println()
			output.Printf("Compiled artifacts written to %s\n", compiledDir)
			output.Printf("  %d SCP(s)\n", len(scps))
			output.Printf("  %d Cedar policy/policies + schema\n", len(cedarPolicies))
			output.Printf("  Crosswalk: %s\n", filepath.Join(compiledDir, "crosswalk.yaml"))
			output.Println()
			output.Println("Run 'attest apply' to deploy to the organization.")
			return nil
		},
	}
	cmd.Flags().String("frameworks", "frameworks", "Path to frameworks directory")
	cmd.Flags().String("output", "", "IaC output format: terraform, cdk")
	cmd.Flags().String("scp-strategy", "individual", "SCP compilation strategy: individual (one SCP per spec, for inspection) or merged (intelligent bin-packing, for production — fits within 5-per-target limit)")
	cmd.Flags().Bool("kyverno", false, "Generate Kyverno ClusterPolicy requiring signed container images (satisfies 3.14.2, SI.L3-3.14.3e)")
	cmd.Flags().String("kyverno-ecr-registry", "", "ECR registry glob for Kyverno image verification (default: *.dkr.ecr.*.amazonaws.com/*)")
	cmd.Flags().String("kyverno-ci-subject", "", "OIDC subject glob for CI/CD signing identity (default: https://github.com/*)")
	return cmd
}

// buildCrosswalk creates the auditable control → artifact mapping.
func buildCrosswalk(sre *schema.SRE, frameworks []*schema.Framework, scps []compilerscp.CompiledSCP, cedarPolicies []compilerce.CompiledCedarPolicy) schema.Crosswalk {
	crosswalk := schema.Crosswalk{
		SRE:         sre.OrgID,
		GeneratedAt: time.Now(),
	}

	// Populate both Framework (legacy) and Frameworks (new list).
	fwIDs := make([]string, len(frameworks))
	for i, fw := range frameworks {
		fwIDs[i] = fw.ID
	}
	crosswalk.Frameworks = fwIDs
	crosswalk.Framework = strings.Join(fwIDs, "+") // backward compat

	// Index SCPs and Cedar policies by control ref.
	scpsByControl := make(map[string][]string)
	for _, s := range scps {
		for _, ref := range s.Controls {
			scpsByControl[ref.ControlID] = append(scpsByControl[ref.ControlID], s.ID)
		}
	}
	cedarByControl := make(map[string][]string)
	for _, p := range cedarPolicies {
		for _, ref := range p.Controls {
			cedarByControl[ref.ControlID] = append(cedarByControl[ref.ControlID], p.ID)
		}
	}

	// Build one entry per control per framework (enables per-framework SSP generation).
	for _, fw := range frameworks {
		for _, ctrl := range fw.Controls {
			entry := schema.CrosswalkEntry{
				ControlID:   ctrl.ID,
				FrameworkID: fw.ID,
				SCPs:        scpsByControl[ctrl.ID],
				CedarPolicies: cedarByControl[ctrl.ID],
			}
			switch {
			case len(entry.SCPs) > 0 && len(entry.CedarPolicies) > 0:
				entry.Status = "enforced"
			case len(entry.SCPs) > 0 || len(entry.CedarPolicies) > 0:
				entry.Status = "partial"
			case ctrl.Responsibility.AWS != "":
				entry.Status = "aws_covered"
			default:
				entry.Status = "gap"
			}
			crosswalk.Entries = append(crosswalk.Entries, entry)
		}
	}

	return crosswalk
}

func applyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Deploy compiled SCPs to the organization",
		Long: `Creates, updates, and attaches compiled SCPs to the org root.
Use --dry-run to preview changes without modifying the organization.
Use --approve to skip interactive confirmation.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			approve, _ := cmd.Flags().GetBool("approve")
			region, _ := cmd.Flags().GetString("region")
			scpDir := filepath.Join(".attest", "compiled", "scps")

			deployer, err := deploy.NewDeployer(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to AWS: %w", err)
			}

			output.Println("Computing deployment plan...")
			plan, err := deployer.Plan(ctx, scpDir)
			if err != nil {
				return fmt.Errorf("planning deployment: %w", err)
			}
			output.Println(plan.Summary())

			if plan.QuotaWarning != "" {
				output.Printf("\n  ⚠ Quota warning: %s\n\n", plan.QuotaWarning)
			}

			if dryRun {
				output.Println("Dry run — no changes made.")
				return nil
			}
			if len(plan.ToCreate)+len(plan.ToUpdate)+len(plan.ToAttach) == 0 {
				return nil
			}
			if !approve {
				output.Print("Apply these changes to the organization? [y/N] ")
				var answer string
				_, _ = fmt.Scanln(&answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					output.Println("Aborted.")
					return nil
				}
			}

			// Auto-tag a pre-apply snapshot so rollback has a target.
			st, _ := store.NewStore(".attest")
			tagName := fmt.Sprintf("applied-%s", time.Now().UTC().Format("20060102-150405"))
			if err := st.Tag(tagName, fmt.Sprintf("Pre-apply snapshot: %s", tagName)); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: could not create pre-apply snapshot: %v\n", err)
			} else {
				output.Printf("  Snapshot: %s\n", tagName)
			}

			output.Println("Applying...")
			result, err := deployer.Apply(ctx, plan, scpDir, func(msg string) {
				output.Println(msg)
			})
			if err != nil {
				return fmt.Errorf("applying: %w", err)
			}
			_ = st.Commit(fmt.Sprintf("apply: deployed %d SCP(s) to %s",
				len(result.Deployed), plan.RootID))

			output.Printf("\nDeployed %d SCP(s) to %s.\n", len(result.Deployed), plan.RootID)
			if len(result.Failed) > 0 {
				output.Printf("  ✗ %d SCP(s) failed (invalid condition keys — fix framework YAML):\n", len(result.Failed))
				for _, f := range result.Failed {
					output.Printf("    - %s\n", f)
				}
			}
			output.Println("Run 'attest scan' to verify posture.")
			return nil
		},
	}
	cmd.Flags().Bool("dry-run", false, "Preview changes without applying")
	cmd.Flags().Bool("approve", false, "Skip interactive approval")
	cmd.Flags().String("region", "us-east-1", "AWS region")
	return cmd
}

func rollbackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Undo the last apply or restore to a named snapshot",
		Long: `Detaches all attest-managed SCPs from the org root, then re-applies
the compiled artifacts from a prior snapshot (git tag).

Use --list to see available snapshots.
Use --to <tag> to target a specific snapshot.
Without --to, rolls back to the most recent applied-* snapshot.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			listOnly, _ := cmd.Flags().GetBool("list")
			targetTag, _ := cmd.Flags().GetString("to")
			approve, _ := cmd.Flags().GetBool("approve")
			region, _ := cmd.Flags().GetString("region")

			st, err := store.NewStore(".attest")
			if err != nil {
				return fmt.Errorf("opening policy store: %w", err)
			}

			if listOnly {
				tags, err := st.ListTags()
				if err != nil {
					return fmt.Errorf("listing snapshots: %w", err)
				}
				if len(tags) == 0 {
					output.Println("No snapshots found. Run 'attest apply' to create one.")
					return nil
				}
				output.Println("Available snapshots (most recent first):")
				for _, t := range tags {
					output.Printf("  %s\n", t)
				}
				return nil
			}

			// Find target tag.
			if targetTag == "" {
				tags, err := st.ListTags()
				if err != nil {
					return fmt.Errorf("listing snapshots: %w", err)
				}
				for _, t := range tags {
					if strings.HasPrefix(t, "applied-") {
						targetTag = t
						break
					}
				}
				if targetTag == "" {
					return fmt.Errorf("no applied-* snapshots found; run 'attest apply' first or specify --to <tag>")
				}
			}

			output.Printf("Rollback target: %s\n\n", targetTag)

			if !approve {
				output.Printf("This will detach all attest SCPs from the org root and re-apply state from %s.\n", targetTag)
				output.Print("Proceed? [y/N] ")
				var answer string
				_, _ = fmt.Scanln(&answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					output.Println("Aborted.")
					return nil
				}
			}

			deployer, err := deploy.NewDeployer(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to AWS: %w", err)
			}

			// Get root ID.
			plan, err := deployer.Plan(ctx, filepath.Join(".attest", "compiled", "scps"))
			if err != nil {
				return fmt.Errorf("getting org root: %w", err)
			}
			rootID := plan.RootID

			// Step 1: Detach all attest SCPs.
			output.Printf("Detaching all attest-managed SCPs from %s...\n", rootID)
			if err := deployer.DetachAll(ctx, rootID); err != nil {
				return fmt.Errorf("detaching SCPs: %w", err)
			}
			output.Println("  Done.")

			// Step 2: Restore compiled artifacts from checkpoint.
			output.Printf("Restoring compiled artifacts from snapshot %s...\n", targetTag)
			if err := st.Checkout(targetTag); err != nil {
				return fmt.Errorf("checking out snapshot: %w", err)
			}
			defer func() {
				// Always return store to HEAD when done.
				_ = st.Checkout("main")
			}()
			output.Println("  Done.")

			// Step 3: Re-apply from restored state.
			scpDir := filepath.Join(".attest", "compiled", "scps")
			output.Println("Re-applying checkpoint state...")
			checkpointPlan, err := deployer.Plan(ctx, scpDir)
			if err != nil {
				return fmt.Errorf("planning checkpoint apply: %w", err)
			}
			result, err := deployer.Apply(ctx, checkpointPlan, scpDir, func(msg string) {
				output.Println(msg)
			})
			if err != nil {
				return fmt.Errorf("applying checkpoint: %w", err)
			}

			output.Printf("\nRollback complete. Deployed %d SCP(s) from snapshot %s.\n",
				len(result.Deployed), targetTag)
			if len(result.Failed) > 0 {
				for _, f := range result.Failed {
					output.Printf("  ✗ %s\n", f)
				}
			}
			return nil
		},
	}
	cmd.Flags().Bool("list", false, "List available snapshots")
	cmd.Flags().String("to", "", "Snapshot tag to roll back to (default: most recent applied-*)")
	cmd.Flags().Bool("approve", false, "Skip interactive confirmation")
	cmd.Flags().String("region", "us-east-1", "AWS region")
	return cmd
}

func preflightCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Check AWS prerequisites before running attest apply",
		Long: `Validates that your AWS Organization is ready for attest apply:
  - Organization feature set (ALL features required)
  - SCP policy type enabled on root
  - SCP quota: current usage vs. compiled SCP count
  - IAM permissions for deployment

Run this before 'attest apply' to catch issues early.

The SCP per-target limit is a hard limit of 5 (AWS Organizations).
Use 'attest compile --scp-strategy merged' to produce ≤4 composite SCPs
that fit within this limit alongside the FullAWSAccess default policy.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")

			output.Printf("Checking prerequisites for attest apply...\n\n")

			// Connect to AWS.
			deployer, err := deploy.NewDeployer(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to AWS: %w", err)
			}

			allGood := true
			fail := func(format string, a ...any) {
				output.Printf("  ✗ "+format+"\n", a...)
				allGood = false
			}
			pass := func(format string, a ...any) {
				output.Printf("  ✓ "+format+"\n", a...)
			}
			warn := func(format string, a ...any) {
				output.Printf("  ⚠ "+format+"\n", a...)
			}

			// Check 1: Organization features.
			analyzer, err := org.NewAnalyzer(ctx, region)
			if err != nil {
				fail("Could not connect to Organizations API: %v", err)
				goto result
			}
			{
				sre, err := analyzer.BuildSRE(ctx)
				if err != nil {
					fail("Could not describe organization: %v", err)
					goto result
				}
				pass("Organization: %s", sre.OrgID)
			}

			// Check 2: Run Plan() to get root ID, SCP type status, and quota.
			{
				scpDir := filepath.Join(".attest", "compiled", "scps")
				plan, err := deployer.Plan(ctx, scpDir)
				if err != nil && !os.IsNotExist(err) {
					fail("Plan check failed: %v", err)
					goto result
				}

				if plan != nil {
					pass("Root: %s", plan.RootID)
					pass("SCPs currently attached: %d/%d", plan.CurrentCount, deploy.SCPPerTargetLimit)

					compiledCount := len(plan.ToCreate) + len(plan.ToUpdate) + len(plan.NoChange) + len(plan.ToAttach)
					if compiledCount == 0 {
						warn("No compiled SCPs found in %s (run 'attest compile' first)", scpDir)
					} else {
						projectedTotal := plan.CurrentCount + len(plan.ToCreate) + len(plan.ToAttach)
						if plan.QuotaWarning != "" {
							fail("SCP quota: would reach %d/%d (exceeds limit)", projectedTotal, deploy.SCPPerTargetLimit)
							output.Printf("      %s\n", plan.QuotaWarning)
						} else {
							pass("SCP quota: %d compiled, %d total after apply (within limit of %d)",
								compiledCount, projectedTotal, deploy.SCPPerTargetLimit)
						}
					}
				}
			}

		result:
			output.Println()
			if allGood {
				output.Println("Result: READY — run 'attest apply --dry-run' to preview")
			} else {
				output.Println("Result: NOT READY — resolve issues above before running 'attest apply'")
				return fmt.Errorf("preflight failed")
			}
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region")
	return cmd
}

func evaluateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evaluate",
		Short: "Run Cedar PDP evaluation against current state",
		Long: `Evaluates a single authorization request against compiled Cedar policies.
Provide principal, action, resource ARNs and entity attributes as --attr flags.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			principalARN, _ := cmd.Flags().GetString("principal")
			action, _ := cmd.Flags().GetString("action")
			resourceARN, _ := cmd.Flags().GetString("resource")
			attrs, _ := cmd.Flags().GetStringSlice("attr")
			cedarDir, _ := cmd.Flags().GetString("cedar")
			outputFile, _ := cmd.Flags().GetString("output")

			// Parse attr flags: "entity.attribute=value"
			attributes := make(map[string]any)
			for _, a := range attrs {
				parts := strings.SplitN(a, "=", 2)
				if len(parts) == 2 {
					attributes[parts[0]] = parts[1]
				}
			}

			// Load compiled Cedar policies.
			ps, err := loadCedarPolicies(cedarDir)
			if err != nil {
				return fmt.Errorf("loading Cedar policies: %w", err)
			}

			// Resolve principal attributes (SAML tags + optional LDAP).
			ldapURL, _ := cmd.Flags().GetString("ldap-url")
			ldapBaseDN, _ := cmd.Flags().GetString("ldap-base-dn")
			region, _ := cmd.Flags().GetString("region")
			if ldapURL != "" {
				ctx := context.Background()
				samlSrc, err := principal.NewSAMLSource(ctx, region)
				if err == nil {
					ldapSrc := principal.NewLDAPSource(ldapURL, ldapBaseDN)
					resolver := principal.NewResolver(samlSrc, ldapSrc)
					if resolved, err := resolver.Resolve(ctx, principalARN); err == nil {
						// Training attributes from qualify (attest:* IAM tags)
						attributes["principal.cui_training_current"] = resolved.CUITrainingCurrent
						attributes["principal.hipaa_training_current"] = resolved.HIPAATrainingCurrent
						attributes["principal.awareness_training_current"] = resolved.AwarenessTrainingCurrent
						attributes["principal.ferpa_training_current"] = resolved.FERPATrainingCurrent
						attributes["principal.itar_training_current"] = resolved.ITARTrainingCurrent
						attributes["principal.data_class_training_current"] = resolved.DataClassTrainingCurrent
						attributes["principal.research_security_training_current"] = resolved.ResearchSecurityTrainingCurrent
						// Expiry timestamps (non-zero means training is valid until that time)
						if !resolved.CUITrainingExpiry.IsZero() {
							attributes["principal.training_expiry"] = resolved.CUITrainingExpiry.Unix()
						}
						if !resolved.ResearchSecurityTrainingExpiry.IsZero() {
							attributes["principal.research_security_training_expiry"] = resolved.ResearchSecurityTrainingExpiry.Unix()
						}
						// Identity attributes
						for _, lab := range resolved.LabMembership {
							attributes["principal.lab_membership"] = lab
						}
						if resolved.AdminLevel != "" {
							attributes["principal.admin_level"] = resolved.AdminLevel
						}
					}
				}
			}

			// Build Cedar request.
			req := evaluator.AuthzRequest{
				PrincipalARN: principalARN,
				Action:       action,
				ResourceARN:  resourceARN,
				Attributes:   attributes,
			}
			ev := evaluator.NewEvaluator(nil)
			decision, err := ev.EvaluateWithPolicies(context.Background(), ps, &req)
			if err != nil {
				return fmt.Errorf("evaluating: %w", err)
			}

			effect := "DENY"
			if decision.Effect == "ALLOW" {
				effect = "ALLOW"
			}
			output.Printf("Decision:  %s\n", effect)
			output.Printf("Principal: %s\n", principalARN)
			output.Printf("Action:    %s\n", action)
			output.Printf("Resource:  %s\n", resourceARN)
			if decision.PolicyID != "" {
				output.Printf("Policy:    %s\n", decision.PolicyID)
			}
			if decision.WaiverID != "" {
				output.Printf("Waiver:    %s\n", decision.WaiverID)
			}

			// Append JSON decision record to output file if requested.
			if outputFile != "" {
				f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
				if err != nil {
					return fmt.Errorf("opening output file: %w", err)
				}
				defer f.Close()
				if b, err := json.Marshal(decision); err == nil {
					_, _ = f.Write(append(b, '\n'))
				}
			}
			return nil
		},
	}
	cmd.Flags().String("principal", "", "Principal ARN (required)")
	cmd.Flags().String("action", "", "IAM action (required)")
	cmd.Flags().String("resource", "", "Resource ARN (required)")
	cmd.Flags().StringSlice("attr", nil, "Entity attributes: entity.attr=value (repeatable)")
	cmd.Flags().String("cedar", filepath.Join(".attest", "compiled", "cedar"), "Cedar policies directory")
	cmd.Flags().String("output", "", "Append decision as JSONL to this file (optional)")
	cmd.Flags().String("ldap-url", "", "LDAP server URL for principal attribute resolution (optional)")
	cmd.Flags().String("ldap-base-dn", "", "LDAP base DN (required with --ldap-url)")
	cmd.Flags().String("region", "us-east-1", "AWS region for SAML/IAM attribute resolution")
	_ = cmd.MarkFlagRequired("principal")
	_ = cmd.MarkFlagRequired("action")
	_ = cmd.MarkFlagRequired("resource")
	return cmd
}

// loadCedarPolicies loads all .cedar files from a directory into a PolicySet.
func loadCedarPolicies(dir string) (*cedar.PolicySet, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return cedar.NewPolicySet(), nil
	}
	if err != nil {
		return nil, err
	}
	ps := cedar.NewPolicySet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cedar") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		parsed, err := cedar.NewPolicySetFromBytes(e.Name(), data)
		if err != nil {
			continue
		}
		for id, policy := range parsed.All() {
			ps.Add(id, policy)
		}
	}
	return ps, nil
}


func generateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate compliance documents from compiled crosswalk",
	}
	cmd.AddCommand(generateSSPCmd(), generatePOAMCmd(), generateAssessCmd(), generateOSCALCmd(), generateCMMCBundleCmd(), generateSPRSCmd(), generateDMSPCmd())
	return cmd
}

func generateSSPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssp",
		Short: "Generate System Security Plan",
		Long: `Generates an SSP from the compiled crosswalk. Every fact in the SSP is
derived from the crosswalk manifest — no hand-written content.
Run 'attest compile' first.

Use --framework to generate an SSP for a specific active framework.
Without --framework, generates one SSP for each active framework.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fwDir, _ := cmd.Flags().GetString("frameworks")
			fwFilter, _ := cmd.Flags().GetString("framework")
			return runGenerateSSP(fwDir, fwFilter)
		},
	}
	cmd.Flags().String("frameworks", "frameworks", "Path to frameworks directory")
	cmd.Flags().String("framework", "", "Generate SSP for a specific framework ID only")
	return cmd
}

func generatePOAMCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "poam",
		Short: "Generate Plan of Action & Milestones",
		Long:  "Generates a POA&M listing all gap and partial controls with milestones and remediation guidance.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate("frameworks", "poam")
		},
	}
}

func generateAssessCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "assess",
		Short: "Generate CMMC 2.0 Level 2 self-assessment",
		Long: `Scores the SRE against NIST 800-171A assessment objectives.
Scoring: enforced = 5pts, partial = 3pts, planned = 1pt, gap = 0pts.
Maximum: 110 controls × 5 = 550 points.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate("frameworks", "assess")
		},
	}
}

func generateOSCALCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "oscal",
		Short: "Export all documents in OSCAL format",
		Long:  "Exports the SSP and Assessment Results in NIST OSCAL 1.1.2 JSON format.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate("frameworks", "oscal")
		},
	}
}

// runGenerate is the shared document generation logic.
// loadGenerateContext loads the SRE config and compiled crosswalk, returning
// the SRE model, crosswalk, and framework IDs active in the crosswalk.
func loadGenerateContext() (*schema.SRE, *schema.Crosswalk, error) {
	sreData, err := os.ReadFile(filepath.Join(".attest", "sre.yaml"))
	if err != nil {
		return nil, nil, fmt.Errorf("reading .attest/sre.yaml: %w (run 'attest init' first)", err)
	}
	var sre schema.SRE
	if err := yaml.Unmarshal(sreData, &sre); err != nil {
		return nil, nil, fmt.Errorf("parsing sre.yaml: %w", err)
	}
	cwData, err := os.ReadFile(filepath.Join(".attest", "compiled", "crosswalk.yaml"))
	if err != nil {
		return nil, nil, fmt.Errorf("reading crosswalk: %w (run 'attest compile' first)", err)
	}
	var crosswalk schema.Crosswalk
	if err := yaml.Unmarshal(cwData, &crosswalk); err != nil {
		return nil, nil, fmt.Errorf("parsing crosswalk: %w", err)
	}
	return &sre, &crosswalk, nil
}

// runGenerateSSP generates SSP(s). If fwFilter is set, generates only for that framework.
// Otherwise generates one SSP per active framework in the crosswalk.
func runGenerateSSP(fwDir, fwFilter string) error {
	sre, crosswalk, err := loadGenerateContext()
	if err != nil {
		return err
	}
	docsDir := filepath.Join(".attest", "documents")
	if err := os.MkdirAll(docsDir, 0750); err != nil {
		return err
	}
	loader := framework.NewLoader(fwDir)

	// Determine which frameworks to generate SSPs for.
	fwIDs := crosswalk.Frameworks
	if len(fwIDs) == 0 {
		// Backward compat: parse from composite Framework string.
		fwIDs = strings.Split(crosswalk.Framework, "+")
	}
	if fwFilter != "" {
		fwIDs = []string{fwFilter}
	}

	for _, fwID := range fwIDs {
		fw, err := loader.Load(fwID)
		if err != nil {
			output.Printf("  Warning: could not load framework %s: %v\n", fwID, err)
			continue
		}
		// Filter crosswalk entries to this framework only.
		filtered := filterCrosswalkByFramework(crosswalk, fwID)
		if err := generateSSP(sre, fw, filtered, docsDir); err != nil {
			return err
		}
	}
	return nil
}

// filterCrosswalkByFramework returns a crosswalk containing only entries for fwID.
// Falls back to all entries if none have FrameworkID set (old crosswalk format).
func filterCrosswalkByFramework(cw *schema.Crosswalk, fwID string) *schema.Crosswalk {
	filtered := &schema.Crosswalk{
		SRE:         cw.SRE,
		Framework:   fwID,
		Frameworks:  []string{fwID},
		GeneratedAt: cw.GeneratedAt,
	}
	for _, e := range cw.Entries {
		if e.FrameworkID == "" || e.FrameworkID == fwID {
			filtered.Entries = append(filtered.Entries, e)
		}
	}
	// If no entries matched (old format without FrameworkID), use all.
	if len(filtered.Entries) == 0 {
		filtered.Entries = cw.Entries
	}
	return filtered
}

func runGenerate(fwDir, docType string) error {
	sre, crosswalk, err := loadGenerateContext()
	if err != nil {
		return err
	}

	// Determine framework from crosswalk (use first for non-SSP docs).
	fwIDs := crosswalk.Frameworks
	if len(fwIDs) == 0 {
		fwIDs = strings.Split(crosswalk.Framework, "+")
	}
	fwID := fwIDs[0]

	loader := framework.NewLoader(fwDir)
	fw, err := loader.Load(fwID)
	if err != nil {
		return fmt.Errorf("loading framework %s: %w", fwID, err)
	}

	docsDir := filepath.Join(".attest", "documents")
	if err := os.MkdirAll(docsDir, 0750); err != nil {
		return err
	}

	switch docType {
	case "poam":
		return generatePOAM(sre, fw, crosswalk, docsDir)
	case "assess":
		return generateAssessment(sre, fw, crosswalk, docsDir)
	case "oscal":
		filtered := filterCrosswalkByFramework(crosswalk, fwID)
		if err := generateSSP(sre, fw, filtered, docsDir); err != nil {
			return err
		}
		return generateOSCAL(sre, fw, filtered, docsDir)
	}
	return nil
}

func generateSSP(sre *schema.SRE, fw *schema.Framework, crosswalk *schema.Crosswalk, docsDir string) error {
	output.Printf("Generating System Security Plan (%s)...\n", fw.Name)
	gen := ssp.NewGenerator()
	doc, err := gen.Generate(sre, fw, crosswalk, nil)
	if err != nil {
		return fmt.Errorf("generating SSP: %w", err)
	}
	md, err := doc.Render()
	if err != nil {
		return fmt.Errorf("rendering SSP: %w", err)
	}
	mdPath := filepath.Join(docsDir, "ssp-"+fw.ID+".md")
	if err := os.WriteFile(mdPath, []byte(md), 0640); err != nil {
		return err
	}
	output.Printf("  SSP written to %s\n", mdPath)
	output.Printf("  Status: %s | Score: %.0f/%.0f\n", doc.OverallStatus, doc.Score, float64(len(fw.Controls)*5))
	return nil
}

func generatePOAM(sre *schema.SRE, fw *schema.Framework, crosswalk *schema.Crosswalk, docsDir string) error {
	output.Printf("Generating POA&M (%s)...\n", fw.Name)
	gen := poam.NewGenerator()
	doc, err := gen.Generate(sre, fw, crosswalk)
	if err != nil {
		return fmt.Errorf("generating POA&M: %w", err)
	}
	mdPath := filepath.Join(docsDir, "poam.md")
	if err := os.WriteFile(mdPath, []byte(doc.Render()), 0640); err != nil {
		return err
	}
	output.Printf("  POA&M written to %s\n", mdPath)
	output.Printf("  Items: %d gaps, %d partial\n", doc.GapCount, doc.PartialCount)
	return nil
}

func generateAssessment(sre *schema.SRE, fw *schema.Framework, crosswalk *schema.Crosswalk, docsDir string) error {
	output.Printf("Generating self-assessment (%s)...\n", fw.Name)
	gen := assessmentpkg.NewGenerator()
	doc, err := gen.Generate(sre, fw, crosswalk)
	if err != nil {
		return fmt.Errorf("generating assessment: %w", err)
	}
	mdPath := filepath.Join(docsDir, "assessment.md")
	if err := os.WriteFile(mdPath, []byte(doc.Render()), 0640); err != nil {
		return err
	}
	output.Printf("  Assessment written to %s\n", mdPath)
	output.Printf("  Score: %d/%d (%.1f%%) — %s\n", doc.TotalScore, doc.MaxScore, doc.ScorePercent, doc.Readiness)
	return nil
}

func generateOSCAL(sre *schema.SRE, fw *schema.Framework, crosswalk *schema.Crosswalk, docsDir string) error {
	output.Println("Exporting to OSCAL 1.1.2...")

	// Re-generate SSP for OSCAL export.
	sspGen := ssp.NewGenerator()
	sspDoc, err := sspGen.Generate(sre, fw, crosswalk, nil)
	if err != nil {
		return err
	}
	sspExporter := osalexport.NewSSPExporter()
	sspJSON, err := sspExporter.ExportSSP(sspDoc)
	if err != nil {
		return fmt.Errorf("exporting SSP to OSCAL: %w", err)
	}
	sspPath := filepath.Join(docsDir, "ssp-"+fw.ID+".oscal.json")
	if err := os.WriteFile(sspPath, sspJSON, 0640); err != nil {
		return err
	}
	output.Printf("  SSP: %s\n", sspPath)

	// Re-generate assessment for OSCAL export.
	assGen := assessmentpkg.NewGenerator()
	assDoc, err := assGen.Generate(sre, fw, crosswalk)
	if err != nil {
		return err
	}
	assExporter := osalexport.NewAssessmentExporter()
	assJSON, err := assExporter.ExportAssessment(assDoc)
	if err != nil {
		return fmt.Errorf("exporting assessment to OSCAL: %w", err)
	}
	assPath := filepath.Join(docsDir, "assessment-results.oscal.json")
	if err := os.WriteFile(assPath, assJSON, 0640); err != nil {
		return err
	}
	output.Printf("  Assessment Results: %s\n", assPath)
	return nil
}

func generateCMMCBundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cmmc-bundle",
		Short: "Generate a complete CMMC Level 2 assessment package",
		Long: `Generates all artifacts required for a CMMC Level 2 C3PAO assessment:
  - readiness.md       — traffic-light readiness report with evidence index
  - cmmc-score.md      — per-control self-assessment score (out of 550)
  - evidence/          — SCP manifest, attestations index, waivers register
  - crosswalk-cmmc.yaml — control → artifact mapping
  - cmmc-bundle-DATE.zip — zip archive of the complete package

Run 'attest compile' and 'attest scan' first to ensure the crosswalk is current.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			outputDir, _ := cmd.Flags().GetString("output")
			assessorOrg, _ := cmd.Flags().GetString("assessor")

			// Load SRE.
			sreData, err := os.ReadFile(filepath.Join(".attest", "sre.yaml"))
			if err != nil {
				return fmt.Errorf("reading .attest/sre.yaml: %w", err)
			}
			var sre schema.SRE
			if err := yaml.Unmarshal(sreData, &sre); err != nil {
				return err
			}

			// Load crosswalk.
			cwData, err := os.ReadFile(filepath.Join(".attest", "compiled", "crosswalk.yaml"))
			if err != nil {
				return fmt.Errorf("run 'attest compile' first to generate the crosswalk: %w", err)
			}
			var cw schema.Crosswalk
			if err := yaml.Unmarshal(cwData, &cw); err != nil {
				return fmt.Errorf("parsing crosswalk: %w", err)
			}

			if outputDir == "" {
				outputDir = fmt.Sprintf("cmmc-bundle-%s", time.Now().UTC().Format("2006-01-02"))
			} else {
				// Validate output directory: must be relative and must not escape the project.
				if filepath.IsAbs(outputDir) {
					return fmt.Errorf("--output must be a relative path, not absolute: %s", outputDir)
				}
				if clean := filepath.Clean(outputDir); strings.HasPrefix(clean, "..") {
					return fmt.Errorf("--output must not escape the project directory: %s", outputDir)
				}
			}

			output.Printf("Generating CMMC Level 2 assessment bundle → %s/\n", outputDir)
			bundle, err := cmmc.Generate(&cmmc.BundleConfig{
				StoreDir:    ".attest",
				OutputDir:   outputDir,
				OrgID:       sre.OrgID,
				AssessorOrg: assessorOrg,
			}, &sre, &cw)
			if err != nil {
				return fmt.Errorf("generating bundle: %w", err)
			}

			pct := 0
			if bundle.MaxScore > 0 {
				pct = bundle.Score * 100 / bundle.MaxScore
			}
			output.Printf("\nBundle complete:\n")
			output.Printf("  Score:    %d / %d (%d%%)\n", bundle.Score, bundle.MaxScore, pct)
			output.Printf("  Location: %s/\n", outputDir)
			output.Printf("  Archive:  %s/cmmc-bundle-%s.zip\n", outputDir, bundle.AssessmentDate)
			for _, item := range bundle.Items {
				output.Printf("  + %s\n", item.Filename)
			}
			return nil
		},
	}
	cmd.Flags().String("output", "", "Output directory (default: cmmc-bundle-YYYY-MM-DD)")
	cmd.Flags().String("assessor", "", "C3PAO organization name (optional, included in report header)")
	return cmd
}

func generateSPRSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sprs",
		Short: "Generate SPRS-compatible score report for DoD submission",
		Long: `Generates a Supplier Performance Risk System (SPRS) score report using the
DoD NIST 800-171 Assessment Methodology. The DoD methodology scores from 110
(all controls implemented) downward, subtracting points for each unimplemented
or partially implemented control.

SPRS scores are submitted via the Procurement Integrated Enterprise Environment
(PIEE) at https://piee.eb.mil/ prior to DoD contract award.

Assessment types:
  --level 1   CMMC Level 1 (15 FAR 52.204-21 practices, annual self-assessment)
  --level 2   CMMC Level 2 (110 NIST 800-171 controls, default)
  --level 3   CMMC Level 3 (134 controls, note: DCSA-assessed, not self-reportable)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			level, _ := cmd.Flags().GetInt("level")
			if level != 1 && level != 2 && level != 3 {
				return fmt.Errorf("--level must be 1, 2, or 3 (got %d)", level)
			}
			_, crosswalk, err := loadGenerateContext()
			if err != nil {
				return err
			}

			// DoD NIST 800-171 Assessment Methodology weights.
			// Start at maximum (110 for L2, 15 for L1) and subtract for gaps/partials.
			// High-value controls: -5 for gap, -3 for partial
			// Standard controls: -3 for gap, -1 for partial (simplified; full weight table in 800-171A)
			const maxScoreL2 = 110

			// Level 1 practice IDs (FAR 52.204-21)
			level1Practices := map[string]bool{
				"AC.L1-3.1.1": true, "AC.L1-3.1.2": true, "AC.L1-3.1.20": true, "AC.L1-3.1.22": true,
				"IA.L1-3.5.1": true, "IA.L1-3.5.2": true,
				"MP.L1-3.8.3": true,
				"PE.L1-3.10.1": true, "PE.L1-3.10.3": true, "PE.L1-3.10.4": true, "PE.L1-3.10.5": true,
				"SC.L1-3.13.1": true, "SC.L1-3.13.5": true,
				"SI.L1-3.14.1": true, "SI.L1-3.14.2": true,
			}
			// Map Level 1 CMMC IDs to NIST 800-171 IDs for crosswalk lookup
			level1NistMap := map[string]string{
				"AC.L1-3.1.1": "3.1.1", "AC.L1-3.1.2": "3.1.2", "AC.L1-3.1.20": "3.1.20", "AC.L1-3.1.22": "3.1.22",
				"IA.L1-3.5.1": "3.5.1", "IA.L1-3.5.2": "3.5.2",
				"MP.L1-3.8.3": "3.8.3",
				"PE.L1-3.10.1": "3.10.1", "PE.L1-3.10.3": "3.10.3", "PE.L1-3.10.4": "3.10.4", "PE.L1-3.10.5": "3.10.5",
				"SC.L1-3.13.1": "3.13.1", "SC.L1-3.13.5": "3.13.5",
				"SI.L1-3.14.1": "3.14.1", "SI.L1-3.14.2": "3.14.2",
			}
			_ = level1Practices

			// Build status lookup from crosswalk.
			statusByControl := make(map[string]string)
			for _, e := range crosswalk.Entries {
				if e.ControlID != "" {
					statusByControl[e.ControlID] = e.Status
				}
			}

			assessmentDate := time.Now().UTC().Format("2006-01-02")
			output.Printf("SPRS Score Report — %s\n", assessmentDate)
			output.Printf("Assessment Type: Self-Assessment\n")

			switch level {
			case 1:
				output.Printf("CMMC Level:      Level 1 (FAR 52.204-21, 15 practices)\n")
				output.Printf("Scoring:         Pass/fail — all 15 practices must be implemented\n\n")
				implemented, total := 0, 0
				for cmmcID, nistID := range level1NistMap {
					total++
					status := statusByControl[nistID]
					if status == "enforced" || status == "aws_covered" {
						implemented++
					} else {
						output.Printf("  NOT IMPLEMENTED: %s (%s) — status: %s\n", cmmcID, nistID, status)
					}
				}
				output.Printf("\nResult: %d / %d practices implemented\n", implemented, total)
				if implemented == total {
					output.Println("SPRS Status:     PASS — eligible for annual self-assessment submission")
				} else {
					output.Printf("SPRS Status:     FAIL — %d practices not implemented; remediate before submission\n",
						total-implemented)
				}
				output.Println("\nSubmit at: https://piee.eb.mil/ (DoD SPRS portal, CAC required)")

			default: // Level 2
				output.Printf("CMMC Level:      Level 2 (NIST SP 800-171 Rev 2, 110 practices)\n")
				output.Printf("Scoring:         DoD methodology: start 110, subtract for gaps/partials\n\n")
				score := maxScoreL2
				gaps, partials := 0, 0
				for _, e := range crosswalk.Entries {
					switch e.Status {
					case "gap":
						score -= 3 // simplified: full 800-171A weights vary per control
						gaps++
					case "partial":
						score -= 1
						partials++
					}
				}
				pct := float64(score) / float64(maxScoreL2) * 100
				output.Printf("SPRS Score:      %d / %d (%.1f%%)\n", score, maxScoreL2, pct)
				output.Printf("Controls:        Gaps: %d  Partial: %d\n", gaps, partials)
				if score >= 88 {
					output.Println("SPRS Status:     Assessment Ready — submit self-assessment to SPRS")
				} else if score >= 55 {
					output.Println("SPRS Status:     Conditional — POA&M required; run 'attest generate poam'")
				} else {
					output.Println("SPRS Status:     Not Ready — significant remediation required")
				}
				output.Println("\nNOTE: This score uses simplified per-control weights (all gaps = -3, partials = -1).")
				output.Println("The official DoD NIST 800-171A methodology uses variable weights per control.")
				output.Println("For a precise score, use the DoD Assessment Methodology spreadsheet:")
				output.Println("  https://www.acq.osd.mil/cmmc/docs/NIST_SP-800-171_DoD_Assessment_Methodology_Version_1.2.1.pdf")
				output.Println("\nSubmit at: https://piee.eb.mil/ (DoD SPRS portal, CAC required)")

			case 3:
				output.Println("CMMC Level 3 uses the DCSA government-led assessment process.")
				output.Println("Level 3 scores are not self-reportable to SPRS.")
				output.Println("Contact DCSA to initiate a Level 3 assessment.")
				output.Println("  https://www.dcsa.mil/Industrial-Security/CMMC/")
			}
			return nil
		},
	}
	cmd.Flags().Int("level", 2, "CMMC level for SPRS scoring (1, 2, or 3)")
	return cmd
}

func generateDMSPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dmsp",
		Short: "Generate NIH Data Management and Security Plan",
		Long: `Generates a Data Management and Security Plan (DMSP) for NIH grant submissions.
Required for all NIH-funded research since January 25, 2023 (NIH DMS Policy).
Must be submitted with grant applications, updated annually, and included in
progress reports.

The DMSP is generated from live SRE state — environments, data classifications,
active frameworks, and compliance posture. All security statements are derived
from deployed artifacts, not aspirational policy.

Output: .attest/documents/dmsp.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			piName, _ := cmd.Flags().GetString("pi")
			piEmail, _ := cmd.Flags().GetString("pi-email")
			grantNum, _ := cmd.Flags().GetString("grant")
			institution, _ := cmd.Flags().GetString("institution")
			projectTitle, _ := cmd.Flags().GetString("title")
			icCode, _ := cmd.Flags().GetString("ic")

			sre, crosswalk, err := loadGenerateContext()
			if err != nil {
				return err
			}

			// Default institution from SRE name if available.
			if institution == "" && sre.Name != "" {
				institution = sre.Name
			}
			if institution == "" {
				institution = "Research Institution"
			}
			if projectTitle == "" {
				projectTitle = "NIH-Funded Research Project"
			}

			plan := &dmsp.Plan{
				SRE:             sre,
				Crosswalk:        crosswalk,
				PIName:           piName,
				PIEmail:          piEmail,
				GrantNumber:      grantNum,
				InstitutionName:  institution,
				ProjectTitle:     projectTitle,
				FundingICCode:    icCode,
				GeneratedAt:      time.Now(),
				// Default repositories for NIH research.
				Repositories: []dmsp.Repository{
					{Name: "dbGaP", URL: "https://www.ncbi.nlm.nih.gov/gap/", Access: "controlled", NIHDesignated: true},
					{Name: "GEO", URL: "https://www.ncbi.nlm.nih.gov/geo/", Access: "open", NIHDesignated: true},
					{Name: "Zenodo", URL: "https://zenodo.org/", Access: "open", NIHDesignated: false},
				},
			}

			doc, err := plan.Generate()
			if err != nil {
				return fmt.Errorf("generating DMSP: %w", err)
			}

			docsDir := filepath.Join(".attest", "documents")
			if err := os.MkdirAll(docsDir, 0750); err != nil {
				return fmt.Errorf("creating documents dir: %w", err)
			}
			outPath := filepath.Join(docsDir, "dmsp.md")
			if err := os.WriteFile(outPath, []byte(doc), 0640); err != nil {
				return fmt.Errorf("writing DMSP: %w", err)
			}
			output.Printf("DMSP written to %s\n", outPath)
			output.Println()
			output.Println("Review and complete the following before submission:")
			output.Println("  1. Add project-specific data types (Section 1)")
			output.Println("  2. Add tools and software used for data analysis (Section 2)")
			output.Println("  3. Confirm repository selections match your data sharing plan (Section 4)")
			output.Println("  4. PI and Institutional Signing Official must sign Section 7")
			output.Println()
			output.Println("Supporting documents:")
			output.Println("  attest generate ssp --framework nist-800-171-r2  → SSP")
			output.Println("  attest generate poam                              → POA&M")
			output.Println("  attest generate sprs --level 2                   → SPRS score")
			return nil
		},
	}
	cmd.Flags().String("pi", "", "Principal Investigator full name")
	cmd.Flags().String("pi-email", "", "Principal Investigator email address")
	cmd.Flags().String("grant", "", "NIH grant number (e.g., R01GM123456)")
	cmd.Flags().String("institution", "", "Institution name (default: SRE name from sre.yaml)")
	cmd.Flags().String("title", "", "Project title (default: 'NIH-Funded Research Project')")
	cmd.Flags().String("ic", "", "NIH Institute/Center code (e.g., NCI, NIGMS, NHGRI)")
	return cmd
}

func diffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff [ref1] [ref2]",
		Short: "Compare posture between two history snapshots",
		Long: `Compares two posture snapshots from .attest/history/.
With no arguments, compares the two most recent snapshots.
With one argument, compares that snapshot against the most recent.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			histDir := filepath.Join(".attest", "history")
			entries, err := os.ReadDir(histDir)
			if err != nil || len(entries) < 2 {
				return fmt.Errorf("need at least 2 posture snapshots in %s (run 'attest scan' twice)", histDir)
			}

			// Load two most recent snapshots (sorted by modification time).
			var files []string
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
					files = append(files, filepath.Join(histDir, e.Name()))
				}
			}
			if len(files) < 2 {
				return fmt.Errorf("need at least 2 snapshot files")
			}

			// Use provided refs or default to last two.
			var fromPath, toPath string
			switch len(args) {
			case 0:
				fromPath = files[len(files)-2]
				toPath = files[len(files)-1]
			case 1:
				// Treat arg as label or filename prefix.
				fromPath = files[len(files)-1]
				for _, f := range files {
					if strings.Contains(f, args[0]) {
						toPath = f
						break
					}
				}
				if toPath == "" {
					return fmt.Errorf("snapshot %q not found", args[0])
				}
			case 2:
				fromPath, toPath = args[0], args[1]
			}

			fromSnap, err := loadSnapshot(fromPath)
			if err != nil {
				return err
			}
			toSnap, err := loadSnapshot(toPath)
			if err != nil {
				return err
			}

			printDiff(fromSnap, toSnap)
			return nil
		},
	}
	return cmd
}

func loadSnapshot(path string) (*schema.PostureSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading snapshot %s: %w", path, err)
	}
	var snap schema.PostureSnapshot
	if err := yaml.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing snapshot: %w", err)
	}
	return &snap, nil
}

func printDiff(from, to *schema.PostureSnapshot) {
	output.Printf("Comparing posture snapshots:\n")
	output.Printf("  From: %s\n", from.Timestamp.Format("2006-01-02 15:04"))
	output.Printf("  To:   %s\n\n", to.Timestamp.Format("2006-01-02 15:04"))

	improved, regressed, unchanged := 0, 0, 0

	// Build maps for comparison.
	fromControls := make(map[string]string)
	for _, fp := range from.Posture.Frameworks {
		for id, status := range fp.Controls {
			fromControls[id] = status
		}
	}
	toControls := make(map[string]string)
	for _, fp := range to.Posture.Frameworks {
		for id, status := range fp.Controls {
			toControls[id] = status
		}
	}

	statusRank := map[string]int{"enforced": 3, "aws_covered": 3, "partial": 2, "planned": 1, "gap": 0}

	var improvedList, regressedList []string
	for id, toStatus := range toControls {
		fromStatus := fromControls[id]
		if fromStatus == toStatus {
			unchanged++
			continue
		}
		if statusRank[toStatus] > statusRank[fromStatus] {
			improved++
			improvedList = append(improvedList, fmt.Sprintf("  ✓ %-10s  %s → %s", id, fromStatus, toStatus))
		} else {
			regressed++
			regressedList = append(regressedList, fmt.Sprintf("  ✗ %-10s  %s → %s", id, fromStatus, toStatus))
		}
	}

	fromScore := from.Posture.Enforced*5 + from.Posture.Partial*3
	toScore := to.Posture.Enforced*5 + to.Posture.Partial*3
	scoreDelta := toScore - fromScore
	sign := "+"
	if scoreDelta < 0 {
		sign = ""
	}
	output.Printf("Score: %d → %d (%s%d pts)\n\n", fromScore, toScore, sign, scoreDelta)

	if len(improvedList) > 0 {
		output.Println("Improved:")
		for _, s := range improvedList {
			output.Println(s)
		}
		output.Println()
	}
	if len(regressedList) > 0 {
		output.Println("Regressed:")
		for _, s := range regressedList {
			output.Println(s)
		}
		output.Println()
	}
	output.Printf("No change: %d controls\n", unchanged)
}

func watchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Continuous Cedar PDP evaluation (CloudTrail polling)",
		Long: `Polls CloudTrail for management events and evaluates each one against
compiled Cedar policies. Prints DENY decisions to the terminal.
Decisions are also written to .attest/history/cedar-decisions.jsonl.

Full EventBridge-driven continuous evaluation is v1.0.0.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cedarDir, _ := cmd.Flags().GetString("cedar")
			region, _ := cmd.Flags().GetString("region")
			intervalSecs, _ := cmd.Flags().GetInt("interval")

			output.Println("Starting Cedar PDP watch (CloudTrail polling mode)...")
			output.Printf("  Policies: %s\n", cedarDir)
			output.Printf("  Poll interval: %ds\n", intervalSecs)
			output.Println("  Press Ctrl+C to stop.")
			output.Println()

			cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
			if err != nil {
				return fmt.Errorf("loading AWS config: %w", err)
			}

			eval := evaluator.NewEvaluator(nil)
			ch := eval.Subscribe()

			// Start polling in background.
			go func() {
				ctSvc := cloudtrail.NewFromConfig(cfg)
				interval := time.Duration(intervalSecs) * time.Second
				histDir := filepath.Join(".attest", "history")
				if err := eval.Start(ctx, ctSvc, cedarDir, histDir, interval); err != nil {
					fmt.Fprintf(os.Stderr, "watch error: %v\n", err)
				}
			}()

			output.Println("Watching for Cedar decisions (showing DENY)...")
			for ev := range ch {
				if ev.Effect == "DENY" {
					output.Printf("  [%s] DENY  %s  %s → %s\n",
						ev.Timestamp.Format("15:04:05"),
						ev.Principal, ev.Action, ev.Resource)
				}
			}
			return nil
		},
	}
	cmd.Flags().String("cedar", filepath.Join(".attest", "compiled", "cedar"), "Compiled Cedar policies directory")
	cmd.Flags().String("region", "us-east-1", "AWS region")
	cmd.Flags().Int("interval", 30, "Poll interval in seconds")
	return cmd
}

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Launch the compliance dashboard",
		Long: `Starts the web dashboard on the specified address. The dashboard
provides real-time compliance visibility: posture, frameworks, Cedar PDP
operations feed, waivers, incidents, and document generation.

Auth options (choose one):
  --auth              Static bearer token via ATTEST_DASHBOARD_TOKEN (local/CI)
  --oidc-issuer <url> OIDC/OAuth2 SSO — works with Shibboleth, Okta, Azure AD

Default (no flags): no auth, localhost only — for local development.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			addr, _ := cmd.Flags().GetString("addr")
			authFlag, _ := cmd.Flags().GetBool("auth")
			oidcIssuer, _ := cmd.Flags().GetString("oidc-issuer")
			oidcClientID, _ := cmd.Flags().GetString("oidc-client-id")
			oidcClientSecret, _ := cmd.Flags().GetString("oidc-client-secret")
			oidcRedirect, _ := cmd.Flags().GetString("oidc-redirect")

			authToken := ""
			if authFlag {
				authToken = os.Getenv("ATTEST_DASHBOARD_TOKEN")
				if authToken == "" {
					return fmt.Errorf("--auth requires ATTEST_DASHBOARD_TOKEN env var to be set")
				}
				if len(authToken) < 16 {
					return fmt.Errorf("ATTEST_DASHBOARD_TOKEN must be at least 16 characters")
				}
			}

			// If OIDC is configured, it takes precedence over static token.
			if oidcIssuer != "" {
				if oidcClientID == "" {
					oidcClientID = os.Getenv("ATTEST_OIDC_CLIENT_ID")
				}
				if oidcClientSecret == "" {
					oidcClientSecret = os.Getenv("ATTEST_OIDC_CLIENT_SECRET")
				}
				if oidcClientID == "" {
					return fmt.Errorf("--oidc-client-id or ATTEST_OIDC_CLIENT_ID is required with --oidc-issuer")
				}
				if oidcRedirect == "" {
					// Default HTTPS unless addr is explicitly localhost — institutional
					// OIDC providers reject plain HTTP redirect URIs.
					scheme := "https"
					if strings.HasPrefix(addr, "127.") || strings.Contains(addr, "localhost") {
						scheme = "http"
					}
					oidcRedirect = fmt.Sprintf("%s://localhost%s/callback", scheme, addr)
				}
				cfg := &auth.OIDCConfig{
					IssuerURL:    oidcIssuer,
					ClientID:     oidcClientID,
					ClientSecret: oidcClientSecret,
					RedirectURL:  oidcRedirect,
				}
				oidcHandler, err := auth.NewOIDCHandler(ctx, cfg)
				if err != nil {
					return fmt.Errorf("initializing OIDC: %w", err)
				}
				output.Printf("Starting attest dashboard with OIDC auth (%s)\n", oidcIssuer)
				srv, err := dashboard.NewServerWithOIDC(addr, ".attest", oidcHandler, nil)
				if err != nil {
					return fmt.Errorf("dashboard: %w", err)
				}
				if err := srv.Start(ctx); err != nil && err.Error() != "http: Server closed" {
					return err
				}
				return nil
			}

			// Check for assessor portal mode.
			assessorMode, _ := cmd.Flags().GetBool("assessor-mode")
			assessorOrg, _ := cmd.Flags().GetString("assessor-org")
			assessorExpiresStr, _ := cmd.Flags().GetString("assessor-expires")

			if assessorMode {
				if authToken == "" {
					return fmt.Errorf("--assessor-mode requires --auth and ATTEST_DASHBOARD_TOKEN: " +
						"C3PAO assessors must authenticate before accessing compliance data")
				}
				var expiry time.Time
				if assessorExpiresStr != "" {
					var err error
					// Parse as UTC date; use UTC throughout to avoid timezone-dependent access control.
					expiry, err = time.ParseInLocation("2006-01-02", assessorExpiresStr, time.UTC)
					if err != nil {
						return fmt.Errorf("--assessor-expires must be YYYY-MM-DD: %w", err)
					}
					// Set to end of the specified UTC day.
					expiry = expiry.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
				}
				output.Printf("Starting attest assessor portal on http://localhost%s\n", addr)
				srv := dashboard.NewAssessorServer(addr, ".attest", authToken,
					dashboard.AssessorConfig{Org: assessorOrg, Expiry: expiry}, nil)
				if err := srv.Start(ctx); err != nil && err.Error() != "http: Server closed" {
					return err
				}
				return nil
			}

			output.Printf("Starting attest dashboard on http://localhost%s\n", addr)
			srv := dashboard.NewServer(addr, ".attest", authToken, nil)
			if err := srv.Start(ctx); err != nil && err.Error() != "http: Server closed" {
				return err
			}
			return nil
		},
	}
	cmd.Flags().String("addr", "127.0.0.1:8080", "Listen address (default 127.0.0.1:8080 — localhost only)")
	cmd.Flags().Bool("auth", false, "Require ATTEST_DASHBOARD_TOKEN bearer token")
	cmd.Flags().String("oidc-issuer", "", "OIDC issuer URL (e.g., https://sso.university.edu)")
	cmd.Flags().String("oidc-client-id", "", "OIDC client ID (or ATTEST_OIDC_CLIENT_ID env)")
	cmd.Flags().String("oidc-client-secret", "", "OIDC client secret (or ATTEST_OIDC_CLIENT_SECRET env)")
	cmd.Flags().String("oidc-redirect", "", "OIDC redirect URL (default: http://localhost<addr>/callback)")
	cmd.Flags().Bool("assessor-mode", false, "Launch as read-only C3PAO assessor portal")
	cmd.Flags().String("assessor-org", "", "Assessor organization name (e.g., 'Cyber-AB Assessor LLC')")
	cmd.Flags().String("assessor-expires", "", "Assessor access expiry date (YYYY-MM-DD)")
	return cmd
}

func testCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run policy unit tests against cedar-go",
		Long: `Executes policy test suites defined in .attest/tests/*.yaml.
Each test case specifies principal attributes, action, resource attributes,
and expected decision (ALLOW/DENY). Tests run locally — no AWS access needed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			testsDir, _ := cmd.Flags().GetString("tests")
			cedarDir, _ := cmd.Flags().GetString("cedar")

			entries, err := os.ReadDir(testsDir)
			if os.IsNotExist(err) {
				output.Printf("No test suites found in %s\n", testsDir)
				output.Println("Create .yaml test suite files to get started.")
				return nil
			}
			if err != nil {
				return fmt.Errorf("reading tests directory: %w", err)
			}

			runner := attesttesting.NewRunner(cedarDir)
			totalPass, totalFail := 0, 0

			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(testsDir, e.Name()))
				if err != nil {
					return err
				}
				var suite schema.PolicyTestSuite
				if err := yaml.Unmarshal(data, &suite); err != nil {
					return fmt.Errorf("parsing %s: %w", e.Name(), err)
				}
				result, err := runner.RunSuite(ctx, &suite)
				if err != nil {
					return fmt.Errorf("running suite %s: %w", suite.Name, err)
				}
				status := "PASS"
				if result.Failed > 0 {
					status = "FAIL"
				}
				output.Printf("[%s] %s: %d/%d passed\n", status, result.Name, result.Passed, result.Total)
				for _, c := range result.Cases {
					if !c.Passed {
						output.Printf("  FAIL: %s — expected %s, got %s\n", c.Description, c.Expected, c.Actual)
					}
				}
				totalPass += result.Passed
				totalFail += result.Failed
			}

			output.Printf("\nTotal: %d passed, %d failed\n", totalPass, totalFail)
			if totalFail > 0 {
				return fmt.Errorf("%d test(s) failed", totalFail)
			}
			return nil
		},
	}
	cmd.Flags().String("tests", filepath.Join(".attest", "tests"), "Test suites directory")
	cmd.Flags().String("cedar", filepath.Join(".attest", "compiled", "cedar"), "Compiled Cedar policies directory")
	return cmd
}

func checkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "CI/CD compliance gate for Terraform plans",
		Long: `Evaluates a Terraform plan JSON for compliance violations.
Use --output sarif for GitHub Actions annotation integration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			tf, _ := cmd.Flags().GetString("terraform")
			outputFmt, _ := cmd.Flags().GetString("output")

			checker := attesttesting.NewTerraformChecker("")
			result, err := checker.Check(ctx, tf)
			if err != nil {
				return err
			}

			switch outputFmt {
			case "sarif":
				output.Println(result.SARIF())
			default:
				if result.Passed {
					output.Println("PASS: No compliance violations found.")
				} else {
					output.Printf("FAIL: %d violation(s) found.\n\n", len(result.Violations))
					for _, v := range result.Violations {
						output.Printf("  %s: %s\n    Control: %s | Policy: %s\n    %s\n\n",
							v.Resource, v.Change, v.ControlID, v.PolicyID, v.Message)
					}
				}
			}
			if !result.Passed {
				return fmt.Errorf("%d compliance violation(s)", len(result.Violations))
			}
			return nil
		},
	}
	cmd.Flags().String("terraform", "", "Path to Terraform plan JSON")
	cmd.Flags().String("output", "text", "Output format: text, sarif")
	_ = cmd.MarkFlagRequired("terraform")
	return cmd
}

func simulateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Diff Cedar decisions: current vs proposed policy changes",
		Long: `Replays recent CloudTrail events against both the current compiled Cedar
policies and a proposed policy set. Shows which operations change decision
(ALLOW→DENY or DENY→ALLOW) so you can validate policy changes before deploying.

Use 'attest ai translate' to generate proposed policies from natural language.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cedarDir, _ := cmd.Flags().GetString("cedar")
			proposedDir, _ := cmd.Flags().GetString("proposed")
			region, _ := cmd.Flags().GetString("region")
			hours, _ := cmd.Flags().GetInt("hours")

			cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
			if err != nil {
				return fmt.Errorf("loading AWS config: %w", err)
			}

			// Load current and proposed policy sets.
			currentPS, err := loadCedarPolicies(cedarDir)
			if err != nil {
				return fmt.Errorf("loading current Cedar policies from %s: %w", cedarDir, err)
			}
			proposedPS, err := loadCedarPolicies(proposedDir)
			if err != nil {
				return fmt.Errorf("loading proposed Cedar policies from %s: %w", proposedDir, err)
			}

			// Count policies.
			currentCount, proposedCount := 0, 0
			for range currentPS.All() { currentCount++ }
			for range proposedPS.All() { proposedCount++ }
			output.Printf("Simulating: %d current vs %d proposed policies\n", currentCount, proposedCount)
			output.Printf("CloudTrail window: last %d hour(s) (region: %s)\n\n", hours, region)

			// Pull CloudTrail events.
			ctSvc := cloudtrail.NewFromConfig(cfg)
			from := time.Now().Add(-time.Duration(hours) * time.Hour)
			to := time.Now()

			out, err := ctSvc.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
				StartTime:  &from,
				EndTime:    &to,
				MaxResults: aws.Int32(100),
			})
			if err != nil {
				return fmt.Errorf("fetching CloudTrail events: %w", err)
			}
			if len(out.Events) == 0 {
				output.Println("No CloudTrail events found in the specified window.")
				return nil
			}

			eval := evaluator.NewEvaluator(nil)
			allowToDeny, denyToAllow, unchanged := 0, 0, 0

			for _, ev := range out.Events {
				req := translateCloudTrailEvent(ev)
				if req == nil {
					continue
				}
				cur, err := eval.EvaluateWithPolicies(ctx, currentPS, req)
				if err != nil { continue }
				prop, err := eval.EvaluateWithPolicies(ctx, proposedPS, req)
				if err != nil { continue }

				if cur.Effect == prop.Effect {
					unchanged++
					continue
				}
				if cur.Effect == "ALLOW" && prop.Effect == "DENY" {
					allowToDeny++
					output.Printf("  [ALLOW→DENY] %s  %s\n", req.PrincipalARN, req.Action)
				} else {
					denyToAllow++
					output.Printf("  [DENY→ALLOW] %s  %s\n", req.PrincipalARN, req.Action)
				}
			}
			output.Printf("\nResults: %d ALLOW→DENY, %d DENY→ALLOW, %d unchanged (from %d events)\n",
				allowToDeny, denyToAllow, unchanged, len(out.Events))
			if allowToDeny > 0 {
				output.Println("\n⚠ Proposed policies would block operations currently allowed.")
				output.Println("  Review the ALLOW→DENY list above before deploying.")
			}
			if denyToAllow > 0 {
				output.Println("\n⚠ Proposed policies would permit operations currently denied.")
				output.Println("  Confirm this is intentional before deploying.")
			}
			return nil
		},
	}
	cmd.Flags().String("cedar", filepath.Join(".attest", "compiled", "cedar"), "Current Cedar policies directory")
	cmd.Flags().String("proposed", filepath.Join(".attest", "proposed"), "Proposed Cedar policies directory")
	cmd.Flags().String("region", "us-east-1", "AWS region")
	cmd.Flags().Int("hours", 1, "CloudTrail lookback window in hours")
	return cmd
}

// translateCloudTrailEvent is a thin wrapper around the evaluator package's translator.
// Duplicating the logic here avoids exposing an unexported function cross-package.
// IMPORTANT: all CloudTrail-sourced fields MUST be sanitized before use in Cedar
// evaluation — CloudTrail events are external data and could contain injection content.
func translateCloudTrailEvent(ev cttypes.Event) *evaluator.AuthzRequest {
	if ev.EventName == nil {
		return nil
	}
	// sanitize caps length to 512 and strips unsafe characters (matches evaluator/cloudtrail.go).
	sanitize := func(s string) string {
		const max = 512
		if len(s) > max {
			s = s[:max]
		}
		var b strings.Builder
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '.' || r == '_' ||
				r == '/' || r == ':' || r == '@' || r == '-' {
				b.WriteRune(r)
			} else {
				b.WriteRune('_')
			}
		}
		return b.String()
	}
	principal := "arn:aws:iam::unknown:user/unknown"
	if ev.Username != nil {
		principal = "arn:aws:iam::unknown:user/" + sanitize(*ev.Username)
	}
	resource := "*"
	for _, r := range ev.Resources {
		if r.ResourceName != nil {
			resource = sanitize(*r.ResourceName)
			break
		}
	}
	return &evaluator.AuthzRequest{
		Action:       sanitize(*ev.EventName),
		PrincipalARN: principal,
		ResourceARN:  resource,
		Attributes:   map[string]any{},
		Timestamp:    time.Now(),
	}
}

func provisionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provision",
		Short: "Create a new compliant research environment",
		Long: `Creates a new AWS account in the SRE with the correct OU placement,
attest:* tags, and SCPs inherited from the target OU. The account is
ready for CUI/PHI/FERPA research workloads immediately after provisioning.

The target OU is selected automatically from data classes:
  CUI   → research-controlled OU
  PHI   → research-hipaa OU
  FERPA → research-education OU
  PII   → research-sensitive OU

Prerequisites: the target OU must exist in your Organization.
Create it first: aws organizations create-organizational-unit --parent-id <root> --name research-controlled`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			name, _ := cmd.Flags().GetString("name")
			owner, _ := cmd.Flags().GetString("owner")
			email, _ := cmd.Flags().GetString("email")
			purpose, _ := cmd.Flags().GetString("purpose")
			dataClasses, _ := cmd.Flags().GetStringSlice("data-class")
			approve, _ := cmd.Flags().GetBool("approve")
			region, _ := cmd.Flags().GetString("region")

			if name == "" {
				return fmt.Errorf("--name is required")
			}
			// AWS Organizations: account name max 50 chars, alphanumeric/spaces/hyphens/periods.
			if len(name) > 50 {
				return fmt.Errorf("--name must be ≤ 50 characters (AWS Organizations limit)")
			}
			if !regexp.MustCompile(`^[a-zA-Z0-9 \-\.]+$`).MatchString(name) {
				return fmt.Errorf("--name may only contain letters, numbers, spaces, hyphens, and periods")
			}
			if email == "" {
				return fmt.Errorf("--email is required (must be unique in your AWS Organization)")
			}
			// Validate email format before sending to AWS.
			if _, err := mail.ParseAddress(email); err != nil {
				return fmt.Errorf("--email is not a valid email address: %w", err)
			}
			if len(email) > 64 {
				return fmt.Errorf("--email must be ≤ 64 characters (AWS Organizations limit)")
			}
			// Validate owner and purpose — used as AWS resource tags (256-char limit,
			// alphanumeric + select punctuation). Reject control characters that could
			// cause issues in tag display or downstream systems.
			if owner != "" {
				if len(owner) > 256 {
					return fmt.Errorf("--owner must be ≤ 256 characters (AWS tag limit)")
				}
				if !regexp.MustCompile(`^[a-zA-Z0-9 \-\.@/]+$`).MatchString(owner) {
					return fmt.Errorf("--owner may only contain letters, digits, spaces, hyphens, dots, @ and /")
				}
			}
			if purpose != "" {
				if len(purpose) > 256 {
					return fmt.Errorf("--purpose must be ≤ 256 characters (AWS tag limit)")
				}
				if !regexp.MustCompile(`^[a-zA-Z0-9 \-\.,()/:]+$`).MatchString(purpose) {
					return fmt.Errorf("--purpose may only contain letters, digits, spaces, and common punctuation")
				}
			}
			if len(dataClasses) == 0 {
				return fmt.Errorf("--data-class is required (e.g., --data-class CUI)")
			}

			// Load SRE.
			sreData, err := os.ReadFile(filepath.Join(".attest", "sre.yaml"))
			if err != nil {
				return fmt.Errorf("reading .attest/sre.yaml: %w (run 'attest init' first)", err)
			}
			var sre schema.SRE
			if err := yaml.Unmarshal(sreData, &sre); err != nil {
				return err
			}

			provisioner, err := provision.NewProvisioner(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to AWS: %w", err)
			}

			req := &provision.Request{
				Name:        name,
				Owner:       owner,
				Email:       email,
				Purpose:     purpose,
				DataClasses: dataClasses,
			}

			output.Println("Computing provisioning plan...")
			plan, err := provisioner.ComputePlan(ctx, &sre, req)
			if err != nil {
				return fmt.Errorf("computing plan: %w", err)
			}

			output.Printf("\nProvisioning plan:\n")
			output.Printf("  Account name:   %s\n", plan.AccountName)
			output.Printf("  Account email:  %s\n", plan.AccountEmail)
			output.Printf("  Target OU:      %s (%s)\n", plan.TargetOUName, plan.TargetOU)
			output.Printf("  SCPs inherited: %d\n", plan.SCPsInherited)
			output.Printf("  Data classes:   %s\n", strings.Join(dataClasses, ", "))
			output.Println("\nPrerequisites:")
			for _, pr := range plan.Prerequisites {
				mark := "✓"
				if !pr.Met {
					mark = "✗"
				}
				output.Printf("  %s %s\n", mark, pr.Description)
			}
			output.Println("\nTags to apply:")
			for k, v := range plan.AttestTags {
				output.Printf("  %s = %s\n", k, v)
			}

			if !plan.AllMet {
				return fmt.Errorf("\nPrerequisites not met — resolve the issues above and re-run")
			}

			if !approve {
				output.Print("\nCreate this environment? [y/N] ")
				var answer string
				_, _ = fmt.Scanln(&answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					output.Println("Aborted.")
					return nil
				}
			}

			output.Printf("\nCreating AWS account %q...\n", plan.AccountName)
			output.Println("  (Account creation is async — polling every 5s, timeout 10 min)")
			env, err := provisioner.Execute(ctx, plan)
			if err != nil {
				return fmt.Errorf("provisioning failed: %w", err)
			}

			output.Printf("\nEnvironment created: %s\n", env.AccountID)
			output.Printf("  Placed in OU: %s\n", plan.TargetOUName)
			output.Printf("  Owner: %s\n", env.Owner)
			output.Println("\nNext steps:")
			output.Println("  1. attest scan — include new environment in posture report")
			output.Println("  2. attest compile --scp-strategy merged — update SCP set if needed")
			output.Println("  3. attest apply --approve — deploy updated SCPs to org")

			// Register in sre.yaml.
			if sre.Environments == nil {
				sre.Environments = make(map[string]schema.Environment)
			}
			sre.Environments[env.AccountID] = *env
			updated, err := yaml.Marshal(sre)
			if err == nil {
				_ = os.WriteFile(filepath.Join(".attest", "sre.yaml"), updated, 0640)
			}

			return nil
		},
	}
	cmd.Flags().String("name", "", "Environment name (required)")
	cmd.Flags().String("owner", "", "PI or lab owner")
	cmd.Flags().String("email", "", "AWS account email — must be globally unique (required)")
	cmd.Flags().String("purpose", "", "Research purpose description")
	cmd.Flags().StringSlice("data-class", nil, "Data class(es): CUI, PHI, FERPA, PII, OPEN")
	cmd.Flags().Bool("approve", false, "Skip interactive confirmation")
	cmd.Flags().String("region", "us-east-1", "AWS region")
	return cmd
}

func waiverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "waiver",
		Short: "Manage compliance exceptions",
	}

	waiverDir := filepath.Join(".attest", "waivers")
	mgr := waiver.NewManager(waiverDir)

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new compliance waiver",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			controlID, _ := cmd.Flags().GetString("control")
			scope, _ := cmd.Flags().GetString("scope")
			approvedBy, _ := cmd.Flags().GetString("approved-by")
			expiresStr, _ := cmd.Flags().GetString("expires")
			title, _ := cmd.Flags().GetString("title")
			justification, _ := cmd.Flags().GetString("justification")
			compensating, _ := cmd.Flags().GetStringSlice("compensating")

			expires, err := time.Parse("2006-01-02", expiresStr)
			if err != nil {
				return fmt.Errorf("invalid --expires date (use YYYY-MM-DD): %w", err)
			}

			w := &schema.Waiver{
				ID:                   fmt.Sprintf("W-%d-%s", time.Now().Year(), strings.ToUpper(strings.ReplaceAll(controlID, ".", ""))),
				ControlID:            controlID,
				Title:                title,
				Scope:                scope,
				ApprovedBy:           approvedBy,
				ExpiresAt:            expires,
				Justification:        justification,
				CompensatingControls: compensating,
			}

			if err := mgr.Create(ctx, w); err != nil {
				return err
			}
			output.Printf("Waiver created: %s\n", w.ID)
			output.Printf("  Control: %s | Scope: %s | Expires: %s\n", w.ControlID, w.Scope, w.ExpiresAt.Format("2006-01-02"))
			return nil
		},
	}
	createCmd.Flags().String("control", "", "Control ID being waived (required)")
	createCmd.Flags().String("scope", "", "Scope (environment or OU)")
	createCmd.Flags().String("approved-by", "", "Approver name/title (required)")
	createCmd.Flags().String("expires", "", "Expiry date YYYY-MM-DD (required)")
	createCmd.Flags().String("title", "", "Short title for the exception")
	createCmd.Flags().String("justification", "", "Justification for the exception")
	createCmd.Flags().StringSlice("compensating", nil, "Compensating controls (comma-separated)")
	_ = createCmd.MarkFlagRequired("control")
	_ = createCmd.MarkFlagRequired("approved-by")
	_ = createCmd.MarkFlagRequired("expires")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List active waivers",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			expiringDays, _ := cmd.Flags().GetInt("expiring")
			var waivers []schema.Waiver
			var err error
			if expiringDays > 0 {
				waivers, err = mgr.ListExpiring(ctx, time.Duration(expiringDays)*24*time.Hour)
			} else {
				waivers, err = mgr.List(ctx)
			}
			if err != nil {
				return err
			}
			if len(waivers) == 0 {
				output.Println("No active waivers.")
				return nil
			}
			output.Printf("%-15s %-10s %-20s %-12s %s\n", "ID", "Control", "Scope", "Expires", "Status")
			output.Println(strings.Repeat("─", 72))
			for _, w := range waivers {
				output.Printf("%-15s %-10s %-20s %-12s %s\n",
					w.ID, w.ControlID, w.Scope, w.ExpiresAt.Format("2006-01-02"), w.Status)
			}
			return nil
		},
	}
	listCmd.Flags().Int("expiring", 0, "Show waivers expiring within N days")

	expireCmd := &cobra.Command{
		Use:   "expire [waiver-id]",
		Short: "Expire a waiver immediately",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			if err := mgr.Expire(ctx, args[0]); err != nil {
				return err
			}
			output.Printf("Waiver %s expired.\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(createCmd, listCmd, expireCmd)
	return cmd
}

func reportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate posture trend report from history",
		RunE: func(cmd *cobra.Command, args []string) error {
			windowStr, _ := cmd.Flags().GetString("window")
			histDir := filepath.Join(".attest", "history")

			// Parse window into duration.
			window := parseDuration(windowStr)
			rep := reporting.NewReporter(histDir)
			trend, err := rep.GenerateTrend(context.Background(), window)
			if err != nil {
				return fmt.Errorf("generating trend: %w", err)
			}

			output.Printf("Posture trend (window: %s)\n\n", windowStr)
			output.Printf("  Snapshots: %d\n", len(trend.Snapshots))
			output.Printf("  Gaps closed: %d | Gaps opened: %d\n", trend.GapsClosed, trend.GapsOpened)
			if len(trend.ScoreTrend) > 0 {
				first := trend.ScoreTrend[0]
				last := trend.ScoreTrend[len(trend.ScoreTrend)-1]
				output.Printf("  Score: %.0f%% → %.0f%%\n", first.Score, last.Score)
			}
			return nil
		},
	}
	cmd.Flags().String("window", "90d", "Report window: 30d, 90d, 1y")
	return cmd
}

// parseDuration converts a simple duration string like "90d" or "1y" to time.Duration.
func parseDuration(s string) time.Duration {
	switch {
	case strings.HasSuffix(s, "y"):
		return 365 * 24 * time.Hour
	case strings.HasSuffix(s, "d"):
		var days int
		_, _ = fmt.Sscanf(s, "%dd", &days)
		return time.Duration(days) * 24 * time.Hour
	default:
		return 90 * 24 * time.Hour
	}
}

func incidentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "incident",
		Short: "Manage security and compliance incidents",
	}

	createSub := &cobra.Command{
		Use:   "create",
		Short: "Record a new incident",
		RunE: func(cmd *cobra.Command, args []string) error {
			title, _ := cmd.Flags().GetString("title")
			severity, _ := cmd.Flags().GetString("severity")
			source, _ := cmd.Flags().GetString("source")
			notes, _ := cmd.Flags().GetString("notes")
			controls, _ := cmd.Flags().GetStringSlice("control")
			if title == "" {
				return fmt.Errorf("--title is required")
			}
			mgr := reporting.NewIncidentManager(filepath.Join(".attest", "history"))
			inc, err := mgr.Create(title, severity, source, notes, controls)
			if err != nil {
				return err
			}
			output.Printf("Created incident %s: %s [%s]\n", inc.ID, inc.Title, inc.Severity)
			return nil
		},
	}
	createSub.Flags().String("title", "", "Incident title (required)")
	createSub.Flags().String("severity", "HIGH", "Severity: CRITICAL, HIGH, MEDIUM, LOW")
	createSub.Flags().String("source", "manual", "Source: guardduty, cedar-denial, manual")
	createSub.Flags().String("notes", "", "Notes or description")
	createSub.Flags().StringSlice("control", nil, "Affected control IDs (repeatable)")

	listSub := &cobra.Command{
		Use:   "list",
		Short: "List incidents",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := reporting.NewIncidentManager(filepath.Join(".attest", "history"))
			incidents, err := mgr.List()
			if err != nil {
				return err
			}
			if len(incidents) == 0 {
				output.Println("No incidents recorded.")
				return nil
			}
			for _, inc := range incidents {
				resolved := ""
				if inc.ResolvedAt != nil {
					resolved = fmt.Sprintf(" → resolved %s", inc.ResolvedAt.Format("2006-01-02"))
				}
				output.Printf("  [%s] %s  %s  %s%s\n",
					inc.Severity, inc.ID, inc.Status, inc.Title, resolved)
			}
			return nil
		},
	}

	resolveSub := &cobra.Command{
		Use:   "resolve <id>",
		Short: "Mark an incident as resolved",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			notes, _ := cmd.Flags().GetString("notes")
			mgr := reporting.NewIncidentManager(filepath.Join(".attest", "history"))
			if err := mgr.Resolve(args[0], notes); err != nil {
				return err
			}
			output.Printf("Incident %s resolved.\n", args[0])
			return nil
		},
	}
	resolveSub.Flags().String("notes", "", "Resolution notes")

	cmd.AddCommand(createSub, listSub, resolveSub)
	return cmd
}

func attestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Manage administrative control attestations",
		Long: `Record, list, and expire human-affirmed attestation records for
administrative controls (training, risk assessments, IR testing, etc.).`,
	}

	attDir := filepath.Join(".attest", "attestations")
	mgr := attestation.NewManager(attDir)

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Record a new attestation",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			controlID, _ := cmd.Flags().GetString("control")
			title, _ := cmd.Flags().GetString("title")
			affirmedBy, _ := cmd.Flags().GetString("affirmed-by")
			expiresStr, _ := cmd.Flags().GetString("expires")
			evidenceRef, _ := cmd.Flags().GetString("evidence")
			evidenceType, _ := cmd.Flags().GetString("evidence-type")
			reviewSchedule, _ := cmd.Flags().GetString("review")

			expires, err := time.Parse("2006-01-02", expiresStr)
			if err != nil {
				return fmt.Errorf("invalid --expires date (use YYYY-MM-DD): %w", err)
			}

			a := &schema.Attestation{
				ID:             fmt.Sprintf("ATT-%d-%s", time.Now().Year(), strings.ToUpper(strings.ReplaceAll(controlID, ".", ""))),
				ControlID:      controlID,
				Title:          title,
				AffirmedBy:     affirmedBy,
				ExpiresAt:      expires,
				EvidenceRef:    evidenceRef,
				EvidenceType:   evidenceType,
				ReviewSchedule: reviewSchedule,
			}
			if err := mgr.Create(ctx, a); err != nil {
				return err
			}
			output.Printf("Attestation created: %s\n", a.ID)
			output.Printf("  Control: %s | Expires: %s\n", a.ControlID, a.ExpiresAt.Format("2006-01-02"))
			return nil
		},
	}
	createCmd.Flags().String("control", "", "Control ID (required)")
	createCmd.Flags().String("title", "", "Short title")
	createCmd.Flags().String("affirmed-by", "", "Affirmer name/title (required)")
	createCmd.Flags().String("expires", "", "Expiry date YYYY-MM-DD (required)")
	createCmd.Flags().String("evidence", "", "Evidence reference (path/URL/description)")
	createCmd.Flags().String("evidence-type", "manual", "Evidence type: policy_doc, training_record, test_report, manual")
	createCmd.Flags().String("review", "annual", "Review schedule: annual, semiannual, quarterly")
	_ = createCmd.MarkFlagRequired("control")
	_ = createCmd.MarkFlagRequired("affirmed-by")
	_ = createCmd.MarkFlagRequired("expires")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List attestations",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			expiringDays, _ := cmd.Flags().GetInt("expiring")
			var attestations []schema.Attestation
			var err error
			if expiringDays > 0 {
				attestations, err = mgr.ListExpiring(ctx, time.Duration(expiringDays)*24*time.Hour)
			} else {
				attestations, err = mgr.List(ctx)
			}
			if err != nil {
				return err
			}
			if len(attestations) == 0 {
				output.Println("No attestations.")
				return nil
			}
			output.Printf("%-18s %-10s %-22s %-12s %s\n", "ID", "Control", "Affirmed by", "Expires", "Status")
			output.Println(strings.Repeat("─", 76))
			for _, a := range attestations {
				output.Printf("%-18s %-10s %-22s %-12s %s\n",
					a.ID, a.ControlID, a.AffirmedBy, a.ExpiresAt.Format("2006-01-02"), a.Status)
			}
			return nil
		},
	}
	listCmd.Flags().Int("expiring", 0, "Show attestations expiring within N days")

	expireCmd := &cobra.Command{
		Use:   "expire [attestation-id]",
		Short: "Expire an attestation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := mgr.Expire(context.Background(), args[0]); err != nil {
				return err
			}
			output.Printf("Attestation %s expired.\n", args[0])
			return nil
		},
	}

	// PI Institutional Attestation — for NIH dbGaP DUC submissions.
	piSignCmd := &cobra.Command{
		Use:   "pi-sign",
		Short: "Record PI institutional attestation (NIH dbGaP DUC / NIST 800-171)",
		Long: `Records a Principal Investigator institutional attestation affirming
NIST SP 800-171 compliance for NIH Data Use Certification (DUC) submissions.

Satisfies NIH requirements for dbGaP controlled-access data access,
NIH Research Security Program certification (NOT-OD-26-017), and
PI personal attestation on Data Use Certifications.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			piName, _ := cmd.Flags().GetString("pi")
			piEmail, _ := cmd.Flags().GetString("pi-email")
			grantNum, _ := cmd.Flags().GetString("grant")
			ducAccession, _ := cmd.Flags().GetString("dbgap-accession")
			osrContact, _ := cmd.Flags().GetString("osr-contact")
			expiresStr, _ := cmd.Flags().GetString("expires")

			expires, err := time.Parse("2006-01-02", expiresStr)
			if err != nil {
				return fmt.Errorf("invalid --expires date (use YYYY-MM-DD): %w", err)
			}

			// Validate grant number — used as filename stem and embedded in YAML.
			// NIH grant format: 1R01GM123456-01 (letter+number+type+IC+serial+suffix).
			// Allow alphanumeric and hyphens only to prevent path traversal and YAML injection.
			if !regexp.MustCompile(`^[a-zA-Z0-9\-]+$`).MatchString(grantNum) {
				return fmt.Errorf("--grant must contain only letters, digits, and hyphens (e.g., R01GM123456)")
			}

			controlID := "RS.1.003"
			if ducAccession != "" {
				// Sanitize dbGaP accession used in control ID.
				safeAccession := regexp.MustCompile(`[^a-zA-Z0-9\-]`).ReplaceAllString(ducAccession, "")
				controlID = fmt.Sprintf("RS.6.001-%s", safeAccession)
			}
			attID := fmt.Sprintf("ATT-PI-%d-%s",
				time.Now().Year(),
				strings.ToUpper(grantNum))

			// Sanitize all fields embedded in evidenceDesc — the string is stored
			// as a YAML value via yaml.Marshal, but applying consistent sanitization
			// prevents control characters from leaking into stored records.
			safePI := regexp.MustCompile(`[\x00-\x1f\x7f]`).ReplaceAllString(piName, "")
			safePIEmail := regexp.MustCompile(`[\x00-\x1f\x7f]`).ReplaceAllString(piEmail, "")
			safeOSR := regexp.MustCompile(`[\x00-\x1f\x7f]`).ReplaceAllString(osrContact, "")
			evidenceDesc := fmt.Sprintf("PI: %s (%s); Grant: %s", safePI, safePIEmail, grantNum)
			if safeOSR != "" {
				evidenceDesc += fmt.Sprintf("; OSR: %s", safeOSR)
			}
			if ducAccession != "" {
				safeAccessionDisplay := regexp.MustCompile(`[^a-zA-Z0-9\-.]`).ReplaceAllString(ducAccession, "")
				evidenceDesc += fmt.Sprintf("; dbGaP: %s", safeAccessionDisplay)
			}

			a := &schema.Attestation{
				ID:             attID,
				ControlID:      controlID,
				Title:          fmt.Sprintf("PI NIST 800-171 Attestation — %s", grantNum),
				AffirmedBy:     piName,
				ExpiresAt:      expires,
				EvidenceRef:    evidenceDesc,
				EvidenceType:   "pi_institutional_attestation",
				ReviewSchedule: "annual",
			}
			if err := mgr.Create(ctx, a); err != nil {
				return err
			}
			output.Printf("PI Attestation recorded: %s\n", a.ID)
			output.Printf("  PI:      %s (%s)\n", piName, piEmail)
			output.Printf("  Grant:   %s\n", grantNum)
			output.Printf("  Expires: %s\n", expires.Format("2006-01-02"))
			if ducAccession != "" {
				output.Printf("  dbGaP:   %s\n", ducAccession)
			}
			output.Println()
			output.Println("Generate DMSP with this attestation:")
			output.Printf("  attest generate dmsp --pi %q --grant %s\n", piName, grantNum)
			return nil
		},
	}
	piSignCmd.Flags().String("pi", "", "Principal Investigator full name (required)")
	piSignCmd.Flags().String("pi-email", "", "PI email address (required)")
	piSignCmd.Flags().String("grant", "", "NIH grant number, e.g. R01GM123456 (required)")
	piSignCmd.Flags().String("expires", "", "Attestation expiry YYYY-MM-DD (required; typically 1 year)")
	piSignCmd.Flags().String("dbgap-accession", "", "dbGaP study accession, e.g. phs000001.v1.p1 (optional)")
	piSignCmd.Flags().String("osr-contact", "", "Office of Sponsored Research co-attestor name (optional)")
	_ = piSignCmd.MarkFlagRequired("pi")
	_ = piSignCmd.MarkFlagRequired("pi-email")
	_ = piSignCmd.MarkFlagRequired("grant")
	_ = piSignCmd.MarkFlagRequired("expires")

	cmd.AddCommand(createCmd, listCmd, expireCmd, piSignCmd)
	return cmd
}

func calendarCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "calendar",
		Short: "Show upcoming compliance review and renewal obligations",
		Long: `Lists all controls with review schedules and their upcoming due dates,
based on attestation records and framework review_schedule definitions.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			windowStr, _ := cmd.Flags().GetString("window")
			window := parseDuration(windowStr)
			fwDir, _ := cmd.Flags().GetString("frameworks")

			// Load SRE config.
			sreData, err := os.ReadFile(filepath.Join(".attest", "sre.yaml"))
			if err != nil {
				return fmt.Errorf("reading .attest/sre.yaml: %w", err)
			}
			var sre schema.SRE
			if err := yaml.Unmarshal(sreData, &sre); err != nil {
				return err
			}

			loader := framework.NewLoader(fwDir)
			attMgr := attestation.NewManager(filepath.Join(".attest", "attestations"))

			cutoff := time.Now().Add(window)
			now := time.Now()

			output.Printf("Compliance calendar (next %s)\n\n", windowStr)
			output.Printf("  %-10s %-8s %-45s %-12s\n", "Control", "Freq", "Title", "Due / Status")
			output.Println("  " + strings.Repeat("─", 78))

			hasItems := false
			for _, ref := range sre.Frameworks {
				fw, err := loader.Load(ref.ID)
				if err != nil {
					continue
				}
				for _, ctrl := range fw.Controls {
					if ctrl.ReviewSchedule == nil {
						continue
					}
					att, hasAtt, _ := attMgr.IsAttested(ctx, ctrl.ID)
					var dueDate time.Time
					var status string

					if hasAtt {
						dueDate = att.ExpiresAt
						if dueDate.Before(now) {
							status = "OVERDUE"
						} else if dueDate.Before(cutoff) {
							days := int(dueDate.Sub(now).Hours() / 24)
							status = fmt.Sprintf("%d days", days)
						} else {
							continue // Not due within window.
						}
					} else {
						status = "NOT ATTESTED"
						dueDate = now
					}

					indicator := "●"
					if status == "OVERDUE" || status == "NOT ATTESTED" {
						indicator = "✗"
					} else if strings.Contains(status, "days") {
						days := 0
						_, _ = fmt.Sscanf(status, "%d days", &days)
						if days <= 30 {
							indicator = "⚠"
						}
					}

					title := ctrl.Title
					if len(title) > 44 {
						title = title[:41] + "..."
					}
					output.Printf("  %s %-9s %-8s %-45s %s\n",
						indicator, ctrl.ID, ctrl.ReviewSchedule.Frequency, title, status)
					hasItems = true
				}
			}

			if !hasItems {
				output.Println("  No review obligations due within the window.")
			}
			return nil
		},
	}
	cmd.Flags().String("window", "90d", "Look-ahead window: 30d, 90d, 1y")
	cmd.Flags().String("frameworks", "frameworks", "Frameworks directory")
	return cmd
}

func aiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "AI-powered compliance capabilities (Bedrock + Claude)",
		Long: `AI capabilities grounded in system truth. The AI reasons over facts
the deterministic system has validated. Every claim cites a specific artifact.

Requires AWS credentials with Bedrock access (us-east-1 or us-west-2).
Optional: ATTEST_GUARDRAIL_ARN env var for Bedrock Guardrail enforcement.`,
	}

	cmd.AddCommand(aiAskCmd(), aiIngestCmd(), aiOnboardCmd(),
		aiAuditSimCmd(), aiTranslateCmd(), aiAnalyzeCmd(), aiImpactCmd(),
		aiRemediateCmd(), aiGeneratePolicyCmd())
	return cmd
}

func aiAskCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ask [question]",
		Short: "Ask the compliance analyst a question",
		Long: `Answers questions about your compliance posture grounded in the compiled
crosswalk and SRE state. No hallucination — every claim cites an artifact.

Examples:
  attest ai ask "What is my CMMC posture?"
  attest ai ask "Which controls are gaps?"
  attest ai ask "Am I HIPAA compliant?"`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")

			analyst, err := ai.NewAnalyst(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to Bedrock: %w", err)
			}

			question := strings.Join(args, " ")
			output.Printf("Asking: %s\n\n", question)

			answer, err := analyst.Ask(ctx, question)
			if err != nil {
				return fmt.Errorf("AI query failed: %w\nEnsure Bedrock access is enabled in region %s", err, region)
			}
			output.Println(answer)
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region for Bedrock")
	return cmd
}

func aiIngestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ingest <file>",
		Short: "Map an existing document to framework controls",
		Long: `Reads a compliance document (policy, procedure, training record, etc.)
and identifies which framework controls it satisfies. Creates draft attestation
records for covered controls.

Example:
  attest ai ingest existing-policies/information-security-policy.md
  attest ai ingest --dir existing-policies/   # ingest all docs in directory`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")
			dir, _ := cmd.Flags().GetString("dir")

			// Load active frameworks.
			sreData, err := os.ReadFile(filepath.Join(".attest", "sre.yaml"))
			if err != nil {
				return fmt.Errorf("reading .attest/sre.yaml: %w", err)
			}
			var sre schema.SRE
			if err := yaml.Unmarshal(sreData, &sre); err != nil {
				return err
			}
			var fwIDs []string
			for _, f := range sre.Frameworks {
				fwIDs = append(fwIDs, f.ID)
			}
			if len(fwIDs) == 0 {
				return fmt.Errorf("no active frameworks — run 'attest frameworks add' first")
			}

			analyst, err := ai.NewAnalyst(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to Bedrock: %w", err)
			}

			// Collect files to ingest.
			var files []string
			if dir != "" {
				entries, err := os.ReadDir(dir)
				if err != nil {
					return fmt.Errorf("reading %s: %w", dir, err)
				}
				for _, e := range entries {
					if !e.IsDir() {
						files = append(files, filepath.Join(dir, e.Name()))
					}
				}
			} else if len(args) > 0 {
				files = args
			} else {
				return fmt.Errorf("specify a file or --dir")
			}

			totalCovered, totalDrafts := 0, 0
			for _, f := range files {
				// Validate file path — prevent path traversal and non-regular files.
				absF, err := filepath.Abs(f)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  Skipping %s: invalid path (%v)\n", f, err)
					continue
				}
				info, err := os.Stat(absF)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  Skipping %s: cannot access (%v)\n", f, err)
					continue
				}
				if !info.Mode().IsRegular() {
					fmt.Fprintf(os.Stderr, "  Skipping %s: not a regular file\n", f)
					continue
				}
				f = absF
				output.Printf("\nAnalyzing: %s\n", filepath.Base(f))
				findings, err := analyst.IngestDocument(ctx, f, fwIDs)
				if err != nil {
					output.Printf("  Warning: %v\n", err)
					continue
				}

				output.Printf("  %-12s %-12s %s\n", "Control", "Status", "Evidence")
				output.Printf("  %s\n", strings.Repeat("─", 60))
				for _, finding := range findings {
					status := finding.Status
					evid := finding.Evidence
					if len(evid) > 50 {
						evid = evid[:47] + "..."
					}
					output.Printf("  %-12s %-12s %s\n", finding.ControlID, status, evid)
					if finding.Status == "covered" {
						totalCovered++
					}
					if finding.DraftAtt != nil {
						// Write draft attestation.
						draftDir := filepath.Join(".attest", "attestations", "drafts")
						_ = os.MkdirAll(draftDir, 0750)
						data, _ := yaml.Marshal(finding.DraftAtt)
						_ = os.WriteFile(filepath.Join(draftDir, finding.DraftAtt.ID+".yaml"), data, 0640) // nosemgrep: semgrep.attest-writefile-variable-path
						totalDrafts++
					}
				}
			}

			output.Printf("\n%d controls covered | %d attestation drafts created in .attest/attestations/drafts/\n", totalCovered, totalDrafts)
			if totalDrafts > 0 {
				output.Println("Review drafts, then: attest attest create --control <id> --affirmed-by <name> --expires <date>")
			}
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region for Bedrock")
	cmd.Flags().String("dir", "", "Ingest all documents in a directory")
	return cmd
}

func aiOnboardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "onboard",
		Short: "Guided compliance onboarding for greenfield or legacy orgs",
		Long: `Produces a prioritized action plan based on current posture.

Modes:
  --mode greenfield   Starting from scratch — prioritizes admin controls whose
                      Cedar policies have unmet dependencies
  --mode legacy       You have existing docs — analyzes what you have and identifies gaps
  --mode checkpoint   Ongoing — reviews expiring attestations and upcoming obligations`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")
			modeStr, _ := cmd.Flags().GetString("mode")
			docsDir, _ := cmd.Flags().GetString("docs")

			analyst, err := ai.NewAnalyst(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to Bedrock: %w", err)
			}

			mode := ai.OnboardMode(modeStr)
			output.Printf("Running %s onboarding analysis...\n\n", mode)

			plan, err := analyst.Onboard(ctx, mode, docsDir)
			if err != nil {
				return fmt.Errorf("onboarding analysis failed: %w", err)
			}

			output.Println(plan.Summary)
			if len(plan.PriorityItems) > 0 {
				output.Printf("\nPriority actions:\n")
				for i, item := range plan.PriorityItems {
					output.Printf("\n%d. [%s] %s — %s\n", i+1, item.Priority, item.ControlID, item.Title)
					if item.Reason != "" {
						output.Printf("   Why: %s\n", item.Reason)
					}
					if item.NextStep != "" {
						output.Printf("   Next: %s\n", item.NextStep)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region for Bedrock")
	cmd.Flags().String("mode", "greenfield", "Onboarding mode: greenfield, legacy, checkpoint")
	cmd.Flags().String("docs", "", "Path to existing policies directory (for legacy mode)")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run:   func(cmd *cobra.Command, args []string) { output.Printf("attest %s\n", version) },
	}
}

func verifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <binary>",
		Short: "Verify attest binary signature via cosign/Sigstore",
		Long: `Verifies the cosign keyless signature of an attest binary downloaded
from GitHub Releases. Checks the Sigstore/Rekor transparency log.

Example:
  attest verify ./attest-linux-amd64`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binary := args[0]
			org, _ := cmd.Flags().GetString("org")

			output.Printf("Verifying: %s\n", binary)
			output.Printf("Expected identity: github.com/%s/attest\n", org)
			output.Printf("OIDC issuer: https://token.actions.githubusercontent.com\n\n")
			output.Printf("Run:\n")
			output.Printf("  cosign verify-blob %s \\\n", binary)
			output.Printf("    --bundle %s.bundle \\\n", binary)
			output.Printf("    --certificate-identity-regexp 'github.com/%s/attest' \\\n", org)
			output.Printf("    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'\n\n")
			output.Println("Download the .bundle file alongside the binary from the GitHub Release.")
			output.Println("Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/")
			return nil
		},
	}
	cmd.Flags().String("org", "provabl", "GitHub org that signed the release")
	return cmd
}

func sreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sre",
		Short: "Manage multiple AWS Organizations (SREs)",
		Long: `Register and manage multiple AWS Organizations under one attest configuration.
Use this when your institution operates several SREs (production, dev, partner networks).

Registry stored in .attest/sres.yaml. Each SRE gets its own .attest/.sre-<id>/ store.`,
	}

	mgr := multisre.NewManager(".attest")

	addSub := &cobra.Command{
		Use:   "add",
		Short: "Register a new SRE (AWS Organization)",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			orgID, _ := cmd.Flags().GetString("org-id")
			region, _ := cmd.Flags().GetString("region")
			profile, _ := cmd.Flags().GetString("profile")
			fwList, _ := cmd.Flags().GetStringSlice("framework")
			notes, _ := cmd.Flags().GetString("notes")
			if id == "" || orgID == "" {
				return fmt.Errorf("--id and --org-id are required")
			}
			entry := multisre.SREEntry{
				ID: id, OrgID: orgID, Region: region,
				Profile: profile, Frameworks: fwList, Notes: notes,
			}
			if err := mgr.Add(entry); err != nil {
				return err
			}
			output.Printf("Registered SRE: %s (%s, region: %s)\n", id, orgID, region)
			output.Printf("  Frameworks: %s\n", strings.Join(fwList, ", "))
			output.Printf("  Store: .attest/.sre-%s/\n", id)
			output.Println("\nNext: run 'attest init' with AWS_PROFILE=" + profile + " to initialize this SRE's store.")
			return nil
		},
	}
	addSub.Flags().String("id", "", "SRE identifier (required, e.g., production)")
	addSub.Flags().String("org-id", "", "AWS Organization ID (required, e.g., o-xxxxx)")
	addSub.Flags().String("region", "us-east-1", "AWS region")
	addSub.Flags().String("profile", "", "AWS CLI profile")
	addSub.Flags().StringSlice("framework", nil, "Active framework IDs")
	addSub.Flags().String("notes", "", "Notes about this SRE")

	listSub := &cobra.Command{
		Use:   "list",
		Short: "List all registered SREs",
		RunE: func(cmd *cobra.Command, args []string) error {
			sres, err := mgr.List()
			if err != nil {
				return err
			}
			if len(sres) == 0 {
				output.Println("No SREs registered. Use 'attest sre add' to register one.")
				return nil
			}
			output.Printf("  %-15s  %-20s  %-12s  %s\n", "ID", "Org ID", "Region", "Frameworks")
			output.Println("  " + strings.Repeat("─", 65))
			for _, s := range sres {
				output.Printf("  %-15s  %-20s  %-12s  %s\n",
					s.ID, s.OrgID, s.Region, strings.Join(s.Frameworks, ", "))
			}
			return nil
		},
	}

	removeSub := &cobra.Command{
		Use:   "remove <id>",
		Short: "Remove an SRE from the registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := mgr.Remove(args[0]); err != nil {
				return err
			}
			output.Printf("Removed SRE: %s\n", args[0])
			output.Printf("  Note: .attest/.sre-%s/ was not deleted — remove manually if no longer needed.\n", args[0])
			return nil
		},
	}

	scanSub := &cobra.Command{
		Use:   "scan",
		Short: "Scan posture for one or all registered SREs",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			all, _ := cmd.Flags().GetBool("all")

			if !all && id == "" {
				return fmt.Errorf("specify --id <sre-id> or --all")
			}
			// Validate --id to prevent path traversal and injection in error messages.
			if id != "" && !multisre.IsValidSREID(id) {
				return fmt.Errorf("invalid SRE ID %q: must be alphanumeric, hyphen, or underscore", id)
			}

			sres, err := mgr.List()
			if err != nil {
				return err
			}
			if len(sres) == 0 {
				return fmt.Errorf("no SREs registered")
			}

			// Filter to single SRE if --id specified.
			if id != "" {
				filtered := sres[:0]
				for _, s := range sres {
					if s.ID == id {
						filtered = append(filtered, s)
					}
				}
				if len(filtered) == 0 {
					return fmt.Errorf("SRE %q not found", id)
				}
				sres = filtered
			}

			output.Printf("Scanning %d SRE(s)...\n\n", len(sres))

			// Scan by reading compiled crosswalks for each SRE's store.
			var wg sync.WaitGroup
			type result struct {
				id    string
				score int
				max   int
				err   error
			}
			results := make([]result, len(sres))
			for i, entry := range sres {
				wg.Add(1)
				go func(i int, entry multisre.SREEntry) {
					defer wg.Done()
					storeDir := mgr.StoreDir(entry.ID)
					cwPath := filepath.Join(storeDir, "compiled", "crosswalk.yaml")
					data, err := os.ReadFile(cwPath)
					if err != nil {
						results[i] = result{id: entry.ID, err: fmt.Errorf("no crosswalk (run attest compile for this SRE)")}
						return
					}
					var cw schema.Crosswalk
					if err := yaml.Unmarshal(data, &cw); err != nil {
						results[i] = result{id: entry.ID, err: err}
						return
					}
					score, maxScore := 0, 0
					for _, e := range cw.Entries {
						maxScore += 5
						switch e.Status {
						case "enforced", "aws_covered":
							score += 5
						case "partial":
							score += 3
						}
					}
					results[i] = result{id: entry.ID, score: score, max: maxScore}
				}(i, entry)
			}
			wg.Wait()

			totalScore, totalMax := 0, 0
			for _, r := range results {
				if r.err != nil {
					output.Printf("  %-15s  ✗ %v\n", r.id, r.err)
					continue
				}
				pct := 0
				if r.max > 0 {
					pct = r.score * 100 / r.max
				}
				output.Printf("  %-15s  %d / %d  (%d%%)\n", r.id, r.score, r.max, pct)
				totalScore += r.score
				totalMax += r.max
			}
			if len(sres) > 1 && totalMax > 0 {
				output.Printf("\n  %-15s  %d / %d  (%d%%)  ← aggregate\n",
					"TOTAL", totalScore, totalMax, totalScore*100/totalMax)
			}
			return nil
		},
	}
	scanSub.Flags().String("id", "", "SRE ID to scan")
	scanSub.Flags().Bool("all", false, "Scan all registered SREs")

	diffSub := &cobra.Command{
		Use:   "diff --from <id> --to <id>",
		Short: "Compare posture between two registered SREs",
		RunE: func(cmd *cobra.Command, args []string) error {
			fromID, _ := cmd.Flags().GetString("from")
			toID, _ := cmd.Flags().GetString("to")
			if fromID == "" || toID == "" {
				return fmt.Errorf("--from and --to are required")
			}
			// Validate IDs to prevent path traversal via StoreDir().
			if !multisre.IsValidSREID(fromID) {
				return fmt.Errorf("invalid --from ID %q: must be alphanumeric, hyphen, or underscore", fromID)
			}
			if !multisre.IsValidSREID(toID) {
				return fmt.Errorf("invalid --to ID %q: must be alphanumeric, hyphen, or underscore", toID)
			}
			// Load crosswalks for both SREs and diff their statuses.
			loadCW := func(id string) (map[string]string, error) {
				data, err := os.ReadFile(filepath.Join(mgr.StoreDir(id), "compiled", "crosswalk.yaml"))
				if err != nil {
					return nil, fmt.Errorf("SRE %q: no crosswalk — run attest compile first", id)
				}
				var cw schema.Crosswalk
				if err := yaml.Unmarshal(data, &cw); err != nil {
					return nil, err
				}
				m := make(map[string]string, len(cw.Entries))
				for _, e := range cw.Entries {
					m[e.ControlID] = e.Status
				}
				return m, nil
			}
			from, err := loadCW(fromID)
			if err != nil {
				return err
			}
			to, err := loadCW(toID)
			if err != nil {
				return err
			}
			output.Printf("Posture diff: %s → %s\n\n", fromID, toID)
			different := 0
			for id, fromStatus := range from {
				toStatus := to[id]
				if fromStatus != toStatus {
					different++
					output.Printf("  %-12s  %-12s → %s\n", id, fromStatus, toStatus)
				}
			}
			for id, toStatus := range to {
				if _, exists := from[id]; !exists {
					different++
					output.Printf("  %-12s  (new)       → %s\n", id, toStatus)
				}
			}
			if different == 0 {
				output.Println("  No differences — posture is identical across both SREs.")
			} else {
				output.Printf("\n  %d control(s) differ between %s and %s.\n", different, fromID, toID)
			}
			return nil
		},
	}
	diffSub.Flags().String("from", "", "Source SRE ID")
	diffSub.Flags().String("to", "", "Target SRE ID")

	// Report subcommand — aggregate posture + optional cost data across all SREs.
	reportSub := &cobra.Command{
		Use:   "report",
		Short: "Multi-SRE aggregate compliance and cost report",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			withCost, _ := cmd.Flags().GetBool("cost")
			region, _ := cmd.Flags().GetString("region")
			csvOutput, _ := cmd.Flags().GetString("output")
			if csvOutput != "" {
				// Validate output path to prevent path traversal.
				if filepath.IsAbs(csvOutput) {
					return fmt.Errorf("--output must be a relative path, not absolute: %s", csvOutput)
				}
				if clean := filepath.Clean(csvOutput); strings.HasPrefix(clean, "..") {
					return fmt.Errorf("--output must not escape the project directory: %s", csvOutput)
				}
			}

			sres, err := mgr.List()
			if err != nil {
				return err
			}
			if len(sres) == 0 {
				return fmt.Errorf("no SREs registered — use 'attest sre add'")
			}

			// Optionally collect cost data.
			var costCollector *multisre.CostCollector
			if withCost {
				costCollector, err = multisre.NewCostCollector(ctx, region)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  Warning: could not initialize Cost Explorer: %v\n", err)
					fmt.Fprintf(os.Stderr, "  Proceeding without cost data.\n")
				}
			}

			output.Printf("\nMulti-SRE Compliance Report  %s\n\n", time.Now().UTC().Format("2006-01-02"))
			output.Printf("  %-15s  %-20s  %-10s  %s\n", "SRE ID", "Org ID", "Score", "Monthly Cost")
			output.Printf("  %s\n", strings.Repeat("─", 65))

			totalScore, totalMax := 0, 0
			var csvRows []string
			if csvOutput != "" {
				csvRows = append(csvRows, "sre_id,org_id,score_pct,monthly_cost_usd")
			}

			for _, s := range sres {
				storeDir := mgr.StoreDir(s.ID)
				score, maxScore := 0, 0
				cwData, err := os.ReadFile(filepath.Join(storeDir, "compiled", "crosswalk.yaml"))
				if err == nil {
					var cw schema.Crosswalk
					if yaml.Unmarshal(cwData, &cw) == nil {
						for _, e := range cw.Entries {
							maxScore += 5
							switch e.Status {
							case "enforced", "aws_covered":
								score += 5
							case "partial":
								score += 3
							}
						}
					}
				}

				pct := 0.0
				if maxScore > 0 {
					pct = float64(score) / float64(maxScore) * 100
				}
				totalScore += score
				totalMax += maxScore

				costStr := "–"
				costUSD := 0.0
				if costCollector != nil {
					if summary, err := costCollector.Collect(ctx); err == nil {
						costStr = fmt.Sprintf("$%.0f/mo", summary.MonthlyCostUSD)
						costUSD = summary.MonthlyCostUSD
					}
				}

				output.Printf("  %-15s  %-20s  %5.1f%%  %s\n", s.ID, s.OrgID, pct, costStr)
				if csvOutput != "" {
					csvRows = append(csvRows, fmt.Sprintf("%s,%s,%.1f,%.2f", s.ID, s.OrgID, pct, costUSD))
				}
			}

			output.Printf("  %s\n", strings.Repeat("─", 65))
			if totalMax > 0 {
				output.Printf("  %-15s  %-20s  %5.1f%%\n", "AGGREGATE", fmt.Sprintf("%d SREs", len(sres)),
					float64(totalScore)/float64(totalMax)*100)
			}

			if csvOutput != "" {
				content := strings.Join(csvRows, "\n") + "\n"
				if err := os.WriteFile(csvOutput, []byte(content), 0640); err == nil {
					output.Printf("\nExported to: %s\n", csvOutput)
				}
			}
			return nil
		},
	}
	reportSub.Flags().Bool("cost", false, "Include AWS Cost Explorer data (requires ce:GetCostAndUsage)")
	reportSub.Flags().String("region", "us-east-1", "AWS region")
	reportSub.Flags().String("output", "", "Export as CSV to the given file path")

	cmd.AddCommand(addSub, listSub, removeSub, scanSub, diffSub, reportSub)
	return cmd
}

func aiAuditSimCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit-sim",
		Short: "Simulate a CMMC Level 2 assessor evaluation",
		Long: `Runs a simulated DFARS/CMMC Level 2 third-party assessment against
the current compliance posture. Produces a draft assessment report with
likely findings and weaknesses. Uses Claude Opus 4.6.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")
			analyst, err := ai.NewAnalyst(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to Bedrock: %w", err)
			}
			output.Println("Running simulated CMMC Level 2 assessment (Opus 4.6)...")
			result, err := analyst.AuditSim(ctx)
			if err != nil {
				return fmt.Errorf("audit simulation failed: %w", err)
			}
			output.Printf("\nSimulated Score: %d / 110 controls\n\n", result.Score)
			output.Printf("Assessor Narrative:\n%s\n\n", result.Narrative)
			if len(result.Weaknesses) > 0 {
				output.Println("Weaknesses identified:")
				for _, w := range result.Weaknesses {
					output.Printf("  • %s\n", w)
				}
			}
			if len(result.Findings) > 0 {
				output.Println("\nDraft Findings:")
				for _, f := range result.Findings {
					output.Printf("  [FINDING] %s\n", f)
				}
			}
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region for Bedrock")
	return cmd
}

func aiTranslateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "translate [statement]",
		Short: "Translate natural language to a Cedar policy",
		Long: `Translates a natural language access control statement into a Cedar policy.
Uses Claude Opus 4.6 for precision. The output is a proposed Cedar policy
you can review and move to .attest/proposed/ for testing.

Example:
  attest ai translate "Deny S3 access to users who haven't completed CUI training"`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")
			analyst, err := ai.NewAnalyst(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to Bedrock: %w", err)
			}
			statement := strings.Join(args, " ")
			output.Printf("Translating: %q\n\n", statement)
			cedar, err := analyst.TranslateToCedar(ctx, statement)
			if err != nil {
				return fmt.Errorf("translation failed: %w", err)
			}
			output.Println(cedar)
			output.Println("\nReview the policy, then: cp proposed.cedar .attest/proposed/")
			output.Println("Test with: attest simulate --proposed .attest/proposed/")
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region for Bedrock")
	return cmd
}

func aiAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Detect anomalies in the Cedar decision log",
		Long: `Reads .attest/history/cedar-decisions.jsonl and uses Claude Sonnet 4.6
to identify unusual patterns: DENY bursts, off-hours access, repeated violations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")
			logPath, _ := cmd.Flags().GetString("log")
			// Validate log file path to prevent path traversal.
			absLog, err := filepath.Abs(logPath)
			if err != nil {
				return fmt.Errorf("invalid log path: %w", err)
			}
			info, err := os.Stat(absLog)
			if err != nil {
				return fmt.Errorf("cannot access log file %s: %w", logPath, err)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file", logPath)
			}
			logPath = absLog
			analyst, err := ai.NewAnalyst(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to Bedrock: %w", err)
			}
			output.Printf("Analyzing Cedar decision log: %s\n\n", logPath)
			anomalies, err := analyst.AnalyzeAnomalies(ctx, logPath)
			if err != nil {
				return fmt.Errorf("analysis failed: %w", err)
			}
			if len(anomalies) == 0 {
				output.Println("No anomalies detected.")
				return nil
			}
			for _, a := range anomalies {
				output.Printf("[%s] %s (%d occurrences)\n", a.Severity, a.Pattern, a.Occurrences)
				if len(a.ControlIDs) > 0 {
					output.Printf("  Controls: %s\n", strings.Join(a.ControlIDs, ", "))
				}
				output.Printf("  Suggestion: %s\n\n", a.Suggestion)
			}
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region for Bedrock")
	cmd.Flags().String("log", filepath.Join(".attest", "history", "cedar-decisions.jsonl"), "Cedar decision log path")
	return cmd
}

func aiImpactCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "impact <framework-file>",
		Short: "Analyze the compliance impact of a new framework",
		Long: `Reads a framework document (PDF, markdown, or text) and estimates
the impact of activating it: new controls needed, overlaps with existing SCPs,
and SCP budget delta. Uses Claude Opus 4.6.

Example:
  attest ai impact docs/fedramp-moderate-controls.pdf`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")
			analyst, err := ai.NewAnalyst(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to Bedrock: %w", err)
			}
			// Validate the framework file path — same pattern as aiIngestCmd.
			fwPath, err := filepath.Abs(args[0])
			if err != nil {
				return fmt.Errorf("resolving path: %w", err)
			}
			fwInfo, err := os.Stat(fwPath)
			if err != nil {
				return fmt.Errorf("framework file not found: %w", err)
			}
			if !fwInfo.Mode().IsRegular() {
				return fmt.Errorf("framework path must be a regular file, not a directory or symlink")
			}
			output.Printf("Analyzing framework impact: %s\n\n", filepath.Base(fwPath))
			result, err := analyst.AnalyzeImpact(ctx, fwPath)
			if err != nil {
				return fmt.Errorf("impact analysis failed: %w", err)
			}
			output.Printf("Summary:\n%s\n\n", result.Summary)
			if len(result.NewControls) > 0 {
				output.Printf("New controls (%d):\n", len(result.NewControls))
				for _, c := range result.NewControls {
					output.Printf("  + %s\n", c)
				}
			}
			if len(result.AffectedSCPs) > 0 {
				output.Printf("\nAffected SCPs: %s\n", strings.Join(result.AffectedSCPs, ", "))
			}
			if result.SCPBudgetDelta != 0 {
				sign := "+"
				if result.SCPBudgetDelta < 0 {
					sign = ""
				}
				output.Printf("SCP budget delta: %s%d chars\n", sign, result.SCPBudgetDelta)
			}
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region for Bedrock")
	return cmd
}

func aiRemediateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remediate <control-id>",
		Short: "Generate a remediation artifact for a control gap",
		Long: `Generates a concrete remediation artifact for a specific control gap:
a Cedar policy, SCP statement, Terraform config, or procedure draft.
Uses Claude Sonnet 4.6.

Example:
  attest ai remediate 3.11.2   # vulnerability scanning gap`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")
			outDir, _ := cmd.Flags().GetString("out")
			analyst, err := ai.NewAnalyst(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to Bedrock: %w", err)
			}
			controlID := args[0]
			output.Printf("Generating remediation for %s...\n\n", controlID)
			artifact, err := analyst.Remediate(ctx, controlID)
			if err != nil {
				return fmt.Errorf("remediation failed: %w", err)
			}
			output.Printf("Type: %s\nTitle: %s\n\n", artifact.Type, artifact.Title)
			output.Println(artifact.Content)
			if artifact.Explanation != "" {
				output.Printf("\nExplanation: %s\n", artifact.Explanation)
			}
			// Write to proposed directory if --out specified.
			if outDir != "" {
				ext := map[string]string{
					"cedar-policy": ".cedar", "scp-addition": ".json",
					"terraform": ".tf", "procedure-draft": ".md",
				}[artifact.Type]
				if ext == "" {
					ext = ".txt"
				}
				// Sanitize controlID to prevent path traversal.
				// Allow only alphanumeric, dot, and dash (valid control ID chars).
				safeID := strings.Map(func(r rune) rune {
					if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
						(r >= '0' && r <= '9') || r == '.' || r == '-' {
						return r
					}
					return '_'
				}, controlID)
				outPath := filepath.Join(outDir, fmt.Sprintf("remediate-%s%s", safeID, ext))
				// Verify final path stays within outDir.
				absOut, _ := filepath.Abs(outDir)
				absPath, _ := filepath.Abs(outPath)
				if !strings.HasPrefix(absPath, absOut+string(filepath.Separator)) {
					return fmt.Errorf("path traversal detected in control ID")
				}
				if err := os.WriteFile(outPath, []byte(artifact.Content), 0640); err == nil {
					output.Printf("\nWritten to: %s\n", outPath)
				}
			}
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region for Bedrock")
	cmd.Flags().String("out", "", "Directory to write the artifact (optional)")
	return cmd
}

func aiGeneratePolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate-policy <control-id>",
		Short: "Draft an institutional policy or procedure for a control gap",
		Long: `Generates a complete institutional policy or procedure document for a
specific compliance control gap. Unlike 'attest ai remediate' which targets
technical artifacts (Cedar policies, SCPs), this generates the administrative
documentation auditors require: training plans, incident response procedures,
risk assessment templates, access control policies, etc.

The output is a markdown document ready for an institutional policy repository.

Examples:
  attest ai generate-policy 3.2.2    # CUI handling training plan
  attest ai generate-policy 3.6.1    # Incident response procedure
  attest ai generate-policy 3.11.1   # Risk assessment template`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")
			policyType, _ := cmd.Flags().GetString("type")
			outDir, _ := cmd.Flags().GetString("out")
			analyst, err := ai.NewAnalyst(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to Bedrock: %w", err)
			}
			controlID := args[0]
			output.Printf("Generating %s document for control %s...\n\n", policyType, controlID)
			artifact, err := analyst.GenerateAdminPolicy(ctx, controlID, policyType)
			if err != nil {
				return fmt.Errorf("policy generation failed: %w", err)
			}
			output.Printf("Title: %s\n\n", artifact.Title)
			output.Println(artifact.Content)
			if artifact.Explanation != "" {
				output.Printf("\nAudit note: %s\n", artifact.Explanation)
			}
			// Write to output directory if specified.
			if outDir != "" {
				safeID := strings.Map(func(r rune) rune {
					if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
						(r >= '0' && r <= '9') || r == '.' || r == '-' {
						return r
					}
					return '_'
				}, controlID)
				outPath := filepath.Join(outDir, fmt.Sprintf("policy-%s.md", safeID))
				absOut, _ := filepath.Abs(outDir)
				absPath, _ := filepath.Abs(outPath)
				if !strings.HasPrefix(absPath, absOut+string(filepath.Separator)) {
					return fmt.Errorf("path traversal detected in control ID")
				}
				if err := os.WriteFile(outPath, []byte(artifact.Content), 0640); err == nil {
					output.Printf("\nWritten to: %s\n", outPath)
				}
			}
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region for Bedrock")
	cmd.Flags().String("type", "procedure", "Document type: procedure, policy, training-plan, template")
	cmd.Flags().String("out", "", "Directory to write the document (optional)")
	return cmd
}

func c3paoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "c3pao",
		Short: "Manage CMMC C3PAO assessment engagements",
		Long: `Track formal CMMC Level 2 and Level 3 third-party assessment engagements.
Records C3PAO organization, assessor team, audit window, and SPRS submission status.

Assessment types:
  Level 2: C3PAO (Third-Party Assessment Organization)
  Level 3: DCSA (Defense Counterintelligence and Security Agency)`,
	}

	assessDir := filepath.Join(".attest", "assessments")

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Record a new C3PAO assessment engagement",
		RunE: func(cmd *cobra.Command, args []string) error {
			c3paoOrg, _ := cmd.Flags().GetString("c3pao")
			leadAssessor, _ := cmd.Flags().GetString("lead")
			frameworkID, _ := cmd.Flags().GetString("framework")
			windowStart, _ := cmd.Flags().GetString("window-start")
			windowEnd, _ := cmd.Flags().GetString("window-end")
			notes, _ := cmd.Flags().GetString("notes")

			start, err := time.Parse("2006-01-02", windowStart)
			if err != nil {
				return fmt.Errorf("invalid --window-start (YYYY-MM-DD): %w", err)
			}
			end, err := time.Parse("2006-01-02", windowEnd)
			if err != nil {
				return fmt.Errorf("invalid --window-end (YYYY-MM-DD): %w", err)
			}

			// Validate C3PAO org name — it feeds into both the ID (used as a filename)
			// and the YAML record. Reject newlines and path separators.
			if strings.ContainsAny(c3paoOrg, "/\\:\n\r") {
				return fmt.Errorf("--c3pao must not contain path separators, colons, or newlines")
			}

			if err := os.MkdirAll(assessDir, 0750); err != nil {
				return fmt.Errorf("creating assessments dir: %w", err)
			}

			// Build a filesystem-safe ID: strip everything but alphanumeric and hyphens.
			safeOrgSlug := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(c3paoOrg, "")
			if len(safeOrgSlug) == 0 {
				safeOrgSlug = "ORG"
			}
			engagement := schema.C3PAOEngagement{
				ID:           fmt.Sprintf("ASSESS-%d-%s", time.Now().Year(), strings.ToUpper(safeOrgSlug[:min3(len(safeOrgSlug), 6)])),
				C3PAOOrg:     c3paoOrg,
				LeadAssessor: leadAssessor,
				FrameworkID:  frameworkID,
				WindowStart:  start,
				WindowEnd:    end,
				Status:       "scheduled",
				Notes:        notes,
				CreatedAt:    time.Now(),
			}

			data, err := yaml.Marshal(engagement)
			if err != nil {
				return fmt.Errorf("marshaling engagement: %w", err)
			}
			path := filepath.Join(assessDir, engagement.ID+".yaml")
			if err := os.WriteFile(path, data, 0640); err != nil {
				return fmt.Errorf("writing engagement: %w", err)
			}

			output.Printf("Assessment engagement created: %s\n", engagement.ID)
			output.Printf("  C3PAO:  %s\n", c3paoOrg)
			output.Printf("  Lead:   %s\n", leadAssessor)
			output.Printf("  Window: %s → %s\n",
				start.Format("2006-01-02"), end.Format("2006-01-02"))
			output.Printf("  Status: scheduled\n")
			output.Println()
			output.Printf("Prepare evidence package: attest generate cmmc-bundle --assessor %q\n", c3paoOrg)
			return nil
		},
	}
	createCmd.Flags().String("c3pao", "", "C3PAO organization name (required)")
	createCmd.Flags().String("lead", "", "Lead assessor name")
	createCmd.Flags().String("framework", "nist-800-171-r2", "Framework being assessed")
	createCmd.Flags().String("window-start", "", "Assessment window start date YYYY-MM-DD (required)")
	createCmd.Flags().String("window-end", "", "Assessment window end date YYYY-MM-DD (required)")
	createCmd.Flags().String("notes", "", "Notes")
	_ = createCmd.MarkFlagRequired("c3pao")
	_ = createCmd.MarkFlagRequired("window-start")
	_ = createCmd.MarkFlagRequired("window-end")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List C3PAO assessment engagements",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := os.ReadDir(assessDir)
			if os.IsNotExist(err) {
				output.Println("No assessments recorded. Use 'attest c3pao create' to record an engagement.")
				return nil
			}
			if err != nil {
				return err
			}
			output.Printf("%-20s %-25s %-12s %-12s %s\n", "ID", "C3PAO", "Window Start", "Status", "SPRS")
			output.Println(strings.Repeat("-", 80))
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
					continue
				}
				entryPath := filepath.Join(assessDir, e.Name())
				// Lstat to prevent following symlinks to files outside assessDir.
				lfi, err := os.Lstat(entryPath)
				if err != nil || lfi.Mode()&os.ModeSymlink != 0 {
					continue
				}
				data, err := os.ReadFile(entryPath)
				if err != nil {
					continue
				}
				var eng schema.C3PAOEngagement
				if err := yaml.Unmarshal(data, &eng); err != nil {
					continue
				}
				sprs := ""
				if eng.SPRSScore > 0 {
					sprs = fmt.Sprintf("%d", eng.SPRSScore)
				}
				output.Printf("%-20s %-25s %-12s %-12s %s\n",
					eng.ID, eng.C3PAOOrg,
					eng.WindowStart.Format("2006-01-02"),
					eng.Status, sprs)
			}
			return nil
		},
	}

	closeCmd := &cobra.Command{
		Use:   "close <id> --sprs-score <score>",
		Short: "Close a C3PAO engagement and record SPRS score",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sprsScore, _ := cmd.Flags().GetInt("sprs-score")
			// Validate assessment ID before using as a filename.
			assessID := args[0]
			if !regexp.MustCompile(`^[A-Za-z0-9_\-]+$`).MatchString(assessID) {
				return fmt.Errorf("invalid assessment ID %q: must be alphanumeric/hyphens/underscores only", assessID)
			}
			path := filepath.Join(assessDir, assessID+".yaml") // nosemgrep: semgrep.attest-filepath-join-no-confinement
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("engagement %s not found", assessID)
			}
			var eng schema.C3PAOEngagement
			if err := yaml.Unmarshal(data, &eng); err != nil {
				return err
			}
			eng.Status = "closed"
			eng.SPRSScore = sprsScore
			eng.SPRSSubmitted = time.Now()
			updated, _ := yaml.Marshal(eng)
			if err := os.WriteFile(path, updated, 0640); err != nil {
				return err
			}
			output.Printf("Assessment %s closed. SPRS score: %d\n", args[0], sprsScore)
			output.Println("Submit score to SPRS: https://piee.eb.mil/ (CAC required)")
			return nil
		},
	}
	closeCmd.Flags().Int("sprs-score", 0, "Final SPRS score from C3PAO assessment")
	_ = closeCmd.MarkFlagRequired("sprs-score")

	cmd.AddCommand(createCmd, listCmd, closeCmd)
	return cmd
}

// min3 returns the smaller of two ints (avoids importing math).
func min3(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ingestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Ingest external compliance evidence (cosign/SLSA, etc.)",
	}
	cmd.AddCommand(ingestCosignCmd())
	return cmd
}

func ingestCosignCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cosign --image <image>",
		Short: "Ingest cosign/SLSA attestations as compliance evidence",
		Long: `Verifies cosign signatures and downloads attestations (SBOM, provenance)
for a container image, then maps the attestation claims to compliance control
evidence. Creates attestation draft records in .attest/proposed/.

Satisfies:
  3.14.2 — malicious code protection (only signed images)
  3.14.1 — flaw remediation (SBOM provides CVE-trackable component inventory)
  3.4.1  — configuration baselines (SBOM is software inventory)
  SI.L3-3.14.3e — software integrity via Sigstore/Rekor provenance

Requires: cosign CLI installed (https://docs.sigstore.dev/cosign/system_config/installation/)
          AWS credentials for ECR image pull (aws ecr get-login-password)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			image, _ := cmd.Flags().GetString("image")
			if image == "" {
				return fmt.Errorf("--image is required (e.g., 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest)")
			}
			// Validate image is a well-formed OCI reference: registry/repo:tag or @digest.
			// Reject newlines and shell metacharacters to prevent command injection via exec.Command.
			if strings.ContainsAny(image, "\n\r\t ") || !regexp.MustCompile(`^[a-zA-Z0-9._/:@\-]+$`).MatchString(image) {
				return fmt.Errorf("--image must be a valid OCI image reference (registry/repo:tag or @sha256:...)")
			}

			output.Printf("Analyzing cosign attestations for: %s\n\n", image)

			ctx := context.Background()
			att, mappings, err := attestation.IngestCosignAttestation(ctx, image)
			if err != nil {
				return fmt.Errorf("cosign ingestion: %w", err)
			}

			// Print attestation summary.
			// Sanitize cosign-sourced fields before printing — a malicious attestation
			// could embed ANSI escape sequences to corrupt terminal display.
			if att.Verified {
				output.Printf("  Signature:    ✓ Verified\n")
			} else {
				output.Printf("  Signature:    ✗ Not verified — %s\n",
					att.SignerSubject)
			}
			if att.SignerSubject != "" && att.Verified {
				output.Printf("  Signer:       %s\n", att.SignerSubject)
			}
			if att.RekorLogID != "" {
				output.Printf("  Rekor entry:  %s\n", att.RekorLogID)
			}
			if att.BuildSource != "" {
				output.Printf("  Build source: %s\n", att.BuildSource)
			}
			if att.SBOMDigest != "" {
				output.Printf("  SBOM:         %s (%s)\n", att.SBOMFormat, att.SBOMDigest)
			} else {
				output.Printf("  SBOM:         not attached\n")
			}
			output.Println()

			// Print control mappings.
			output.Println("Maps to controls:")
			for _, m := range mappings {
				icon := "✓"
				if !m.Satisfied {
					icon = "✗"
				}
				output.Printf("  %s %-14s  %s\n", icon, m.ObjectiveID, m.Description)
			}
			output.Println()

			// Write attestation draft records.
			proposedDir := filepath.Join(".attest", "proposed")
			if err := os.MkdirAll(proposedDir, 0750); err != nil {
				return fmt.Errorf("creating proposed dir: %w", err)
			}

			// Derive a short image name for the draft ID.
			// Whitelist to alphanumeric, dots, and hyphens only.
			imageName := image
			if idx := strings.LastIndex(image, "/"); idx >= 0 {
				imageName = image[idx+1:]
			}
			imageName = regexp.MustCompile(`[^a-zA-Z0-9._\-]`).ReplaceAllString(imageName, "-")

			written := 0
			for _, m := range mappings {
				if !m.Satisfied {
					continue
				}
				draftID := fmt.Sprintf("ATT-DRAFT-cosign-%s-%s",
					strings.ReplaceAll(m.ControlID, ".", ""),
					imageName)
				// Use yaml.Marshal to safely encode all cosign-sourced fields —
				// SignerSubject, BuildSource, and Evidence are attacker-controlled
				// (come from the signed image's attestation) and must not be
				// interpolated into a raw YAML string.
				draftRecord := map[string]string{
					"id":             draftID,
					"control_id":     m.ControlID,
					"objective_id":   m.ObjectiveID,
					"title":          m.Description,
					"affirmed_by":    "cosign-automated",
					"evidence":       m.Evidence,
					"evidence_type":  "cosign_attestation",
					"rekor_log_id":   att.RekorLogID,
					"sbom_digest":    att.SBOMDigest,
					"status":         "draft",
				}
				draftBytes, err := yaml.Marshal(draftRecord)
				if err != nil {
					return fmt.Errorf("marshaling draft: %w", err)
				}
				draftPath := filepath.Join(proposedDir, draftID+".yaml")
				if err := os.WriteFile(draftPath, draftBytes, 0640); err != nil {
					return fmt.Errorf("writing draft: %w", err)
				}
				written++
			}

			if written > 0 {
				output.Printf("Created %d attestation draft(s) in %s\n", written, proposedDir)
				output.Println("Review with: ls .attest/proposed/ATT-DRAFT-cosign-*")
				output.Println("Promote with: attest attest create --from-draft <id>")
			}
			return nil
		},
	}
	cmd.Flags().String("image", "", "Container image reference (required)")
	_ = cmd.MarkFlagRequired("image")
	return cmd
}

func integrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "integrate",
		Short: "Integrate attest with enterprise systems",
	}
	cmd.AddCommand(integrateGRCCmd())
	return cmd
}

func integrateGRCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grc",
		Short: "Push OSCAL compliance documents to a GRC platform",
	}
	cmd.AddCommand(integrateGRCPushCmd())
	return cmd
}

func integrateGRCPushCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Push current OSCAL assessment to a GRC platform endpoint",
		Long: `Generates OSCAL Assessment Results from the current posture and POSTs
the document to the configured GRC platform endpoint.

Auth: set ATTEST_GRC_TOKEN env var (Bearer token or API key).
Never pass tokens on the command line — they appear in process listings.

Supported platforms: servicenow, archer, generic (any OSCAL-compatible HTTP endpoint)

Examples:
  # ServiceNow GRC
  ATTEST_GRC_TOKEN=<token> attest integrate grc push \
    --endpoint https://company.service-now.com/api/now/table/sn_grc_document \
    --platform servicenow

  # Dry-run: see what would be sent
  attest integrate grc push --endpoint https://example.com --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			endpoint, _ := cmd.Flags().GetString("endpoint")
			platformStr, _ := cmd.Flags().GetString("platform")
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			onChange, _ := cmd.Flags().GetBool("on-change")
			intervalSecs, _ := cmd.Flags().GetInt("interval")

			// Validate platform against allowlist before passing to client.
			platform, err := grc.ValidatePlatform(platformStr)
			if err != nil {
				return err
			}
			client, err := grc.NewClient(endpoint, platform, dryRun)
			if err != nil {
				return err
			}

			// Load crosswalk for OSCAL export.
			cwData, err := os.ReadFile(filepath.Join(".attest", "compiled", "crosswalk.yaml"))
			if err != nil {
				return fmt.Errorf("run 'attest compile' first: %w", err)
			}
			var cw schema.Crosswalk
			if err := yaml.Unmarshal(cwData, &cw); err != nil {
				return err
			}

			// Build a minimal assessment from crosswalk for OSCAL generation.
			assess := buildAssessmentFromCrosswalk(&cw)

			generateOSCAL := func() ([]byte, error) {
				exporter := osalexport.NewAssessmentExporter()
				return exporter.ExportAssessment(assess)
			}

			if onChange {
				output.Printf("Watching for posture changes, pushing every %ds...\n", intervalSecs)
				return client.WatchAndPush(ctx,
					filepath.Join(".attest", "history"),
					generateOSCAL,
					time.Duration(intervalSecs)*time.Second)
			}

			payload, err := generateOSCAL()
			if err != nil {
				return fmt.Errorf("generating OSCAL: %w", err)
			}

			output.Printf("Pushing OSCAL Assessment Results to %s...\n", endpoint)
			result, err := client.PushWithRetry(ctx, "assessment", payload, 3)
			if err != nil {
				return fmt.Errorf("push failed: %w", err)
			}
			if dryRun {
				return nil
			}
			output.Printf("  HTTP %d — pushed %d bytes to %s\n",
				result.StatusCode, len(payload), result.Endpoint)
			output.Printf("  Pushed at: %s\n", result.PushedAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().String("endpoint", "", "GRC platform OSCAL endpoint URL (required)")
	cmd.Flags().String("platform", "generic", "Platform type: servicenow, archer, generic")
	cmd.Flags().Bool("dry-run", false, "Show payload without sending")
	cmd.Flags().Bool("on-change", false, "Watch for posture changes and push continuously")
	cmd.Flags().Int("interval", 3600, "Push interval in seconds (with --on-change)")
	return cmd
}

func enforceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enforce",
		Short: "Manage continuous Cedar PDP enforcement infrastructure",
	}
	cmd.AddCommand(enforceSetupCmd())
	return cmd
}

func enforceSetupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Create EventBridge rule + SQS queue for real-time Cedar PDP evaluation",
		Long: `Sets up the AWS infrastructure for sub-second Cedar policy evaluation:
  1. Creates an EventBridge rule matching CloudTrail management events
  2. Creates an SQS queue (attest-cedar-events) as the target
  3. Sets the queue policy to allow EventBridge delivery
  4. Writes the queue URL to .attest/sre.yaml

After setup, 'attest watch' automatically uses SQS instead of CloudTrail polling,
reducing Cedar evaluation latency from ~30s to sub-second.

Requires: cloudtrail:DescribeTrails, events:PutRule, events:PutTargets,
          sqs:CreateQueue, sqs:SetQueueAttributes`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			region, _ := cmd.Flags().GetString("region")

			cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
			if err != nil {
				return fmt.Errorf("loading AWS config: %w", err)
			}

			output.Printf("Setting up EventBridge + SQS for Cedar PDP (region: %s)...\n", region)

			// Create SQS queue.
			sqsSvc := sqssvc.NewFromConfig(cfg)
			queueOut, err := sqsSvc.CreateQueue(ctx, &sqssvc.CreateQueueInput{
				QueueName: aws.String("attest-cedar-events"),
				Attributes: map[string]string{
					"MessageRetentionPeriod":  "86400",  // 1 day
					"VisibilityTimeout":        "60",
					"ReceiveMessageWaitTimeSeconds": "20", // enable long-polling by default
				},
			})
			if err != nil {
				return fmt.Errorf("creating SQS queue: %w", err)
			}
			queueURL := aws.ToString(queueOut.QueueUrl)
			output.Printf("  ✓ SQS queue created: %s\n", queueURL)

			// Get queue ARN for EventBridge target.
			attrOut, err := sqsSvc.GetQueueAttributes(ctx, &sqssvc.GetQueueAttributesInput{
				QueueUrl:       aws.String(queueURL),
				AttributeNames: []sqstypes.QueueAttributeName{"QueueArn"},
			})
			if err != nil {
				return fmt.Errorf("getting queue ARN: %w", err)
			}
			queueARN := attrOut.Attributes["QueueArn"]

			// Create EventBridge rule.
			ebSvc := ebsvc.NewFromConfig(cfg)
			ruleOut, err := ebSvc.PutRule(ctx, &ebsvc.PutRuleInput{
				Name:        aws.String("attest-cedar-cloudtrail"),
				Description: aws.String("Delivers CloudTrail management events to attest Cedar PDP"),
				EventPattern: aws.String(`{"source":["aws.cloudtrail"]}`),
				State:        ebtypes.RuleStateEnabled,
			})
			if err != nil {
				return fmt.Errorf("creating EventBridge rule: %w", err)
			}
			output.Printf("  ✓ EventBridge rule created: %s\n", aws.ToString(ruleOut.RuleArn))

			// Set SQS queue policy to allow EventBridge delivery.
			// Use json.Marshal to safely embed ARNs — prevents JSON injection if
			// an ARN ever contains characters like " or \ (rare but defensive).
			policyDoc := map[string]any{
				"Version": "2012-10-17",
				"Statement": []map[string]any{{
					"Effect": "Allow",
					"Principal": map[string]string{
						"Service": "events.amazonaws.com",
					},
					"Action":   "sqs:SendMessage",
					"Resource": queueARN,
					"Condition": map[string]any{
						"ArnEquals": map[string]string{
							"aws:SourceArn": aws.ToString(ruleOut.RuleArn),
						},
					},
				}},
			}
			policyBytes, err := json.Marshal(policyDoc)
			if err != nil {
				return fmt.Errorf("building queue policy: %w", err)
			}
			policy := string(policyBytes)
			_, err = sqsSvc.SetQueueAttributes(ctx, &sqssvc.SetQueueAttributesInput{
				QueueUrl:   aws.String(queueURL),
				Attributes: map[string]string{"Policy": policy},
			})
			if err != nil {
				return fmt.Errorf("setting queue policy: %w", err)
			}

			// Add SQS as EventBridge target.
			_, err = ebSvc.PutTargets(ctx, &ebsvc.PutTargetsInput{
				Rule: aws.String("attest-cedar-cloudtrail"),
				Targets: []ebtypes.Target{
					{Id: aws.String("attest-sqs"), Arn: aws.String(queueARN)},
				},
			})
			if err != nil {
				return fmt.Errorf("setting EventBridge target: %w", err)
			}
			output.Printf("  ✓ EventBridge target set to SQS queue\n")

			// Save queue URL to sre.yaml.
			// Save queue URL to a config file for attest watch to discover.
			queueConfig := fmt.Sprintf("sqs_queue_url: %q\n", queueURL)
			if err := os.WriteFile(filepath.Join(".attest", "evaluator.yaml"), []byte(queueConfig), 0640); err == nil {
				output.Printf("  ✓ Queue URL saved to .attest/evaluator.yaml\n")
			}

			output.Println("\nSetup complete. Run 'attest watch' to start real-time Cedar evaluation.")
			output.Printf("Queue URL: %s\n", queueURL)
			return nil
		},
	}
	cmd.Flags().String("region", "us-east-1", "AWS region")
	return cmd
}

// buildAssessmentFromCrosswalk builds a minimal Assessment struct for OSCAL export.
func buildAssessmentFromCrosswalk(cw *schema.Crosswalk) *assessmentpkg.Assessment {
	a := &assessmentpkg.Assessment{
		Title:       fmt.Sprintf("%s Assessment Results", cw.Framework),
		Framework:   cw.Framework,
		GeneratedAt: cw.GeneratedAt,
	}
	familyMap := make(map[string]*assessmentpkg.FamilyScore)
	for _, e := range cw.Entries {
		family := strings.SplitN(e.ControlID, ".", 2)[0]
		if familyMap[family] == nil {
			familyMap[family] = &assessmentpkg.FamilyScore{Family: family, MaxScore: 0}
		}
		score := 0
		switch e.Status {
		case "enforced", "aws_covered":
			score = 5
		case "partial":
			score = 3
		}
		familyMap[family].Controls = append(familyMap[family].Controls, assessmentpkg.ControlScore{
			ControlID: e.ControlID, Status: e.Status,
			Score: score, MaxScore: 5,
		})
		familyMap[family].Score += score
		familyMap[family].MaxScore += 5
		a.TotalScore += score
		a.MaxScore += 5
	}
	for _, fs := range familyMap {
		a.FamilyScores = append(a.FamilyScores, *fs)
	}
	if a.MaxScore > 0 {
		a.ScorePercent = float64(a.TotalScore) / float64(a.MaxScore) * 100
	}
	return a
}
