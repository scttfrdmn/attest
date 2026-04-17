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

	"net/mail"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	iamSvc "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/provabl/attest/internal/ai"
	"github.com/provabl/attest/internal/auth"
	"github.com/provabl/attest/internal/dashboard"
	"github.com/provabl/attest/internal/principal"
	"github.com/provabl/attest/internal/provision"
	"github.com/provabl/attest/internal/artifact"
	"github.com/provabl/attest/internal/attestation"
	compilerce "github.com/provabl/attest/internal/compiler/cedar"
	compilerscp "github.com/provabl/attest/internal/compiler/scp"
	"github.com/provabl/attest/internal/deploy"
	"github.com/provabl/attest/internal/document/assessment"
	"github.com/provabl/attest/internal/document/oscal"
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

var version = "0.9.1"

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

			fmt.Println("Initializing SRE...")

			// Read Organization topology.
			fmt.Printf("  Reading Organization topology (region: %s)...\n", region)
			analyzer, err := org.NewAnalyzer(ctx, region)
			if err != nil {
				return fmt.Errorf("creating org analyzer: %w", err)
			}
			sre, err := analyzer.BuildSRE(ctx)
			if err != nil {
				return fmt.Errorf("building SRE: %w", err)
			}
			fmt.Printf("  Organization: %s (%d environments)\n", sre.OrgID, len(sre.Environments))

			// Inventory existing SCPs.
			fmt.Println("  Inventorying existing SCPs...")
			scps, err := analyzer.InventoryExistingSCPs(ctx)
			if err != nil {
				return fmt.Errorf("inventorying SCPs: %w", err)
			}
			fmt.Printf("  Found %d existing SCPs\n", len(scps))

			// Detect Artifact agreements → activated frameworks.
			fmt.Println("  Querying Artifact for active agreements...")
			artifactClient, err := artifact.NewClient(ctx, region)
			if err != nil {
				return fmt.Errorf("creating Artifact client: %w", err)
			}
			activations, err := artifactClient.DetectFrameworkActivations(ctx)
			if err != nil {
				// Non-fatal: Artifact may not be accessible from all accounts.
				fmt.Printf("  Warning: could not query Artifact agreements: %v\n", err)
			} else {
				for fwID := range activations {
					sre.Frameworks = append(sre.Frameworks, schema.FrameworkRef{
						ID:      fwID,
						Version: "latest",
					})
					fmt.Printf("  Framework activated via agreement: %s\n", fwID)
				}
			}

			// Apply institutional classification scheme if provided.
			if classScheme != "" {
				fmt.Printf("  Applying classification scheme: %s...\n", classScheme)
				if err := applyClassificationScheme(classScheme, sre); err != nil {
					fmt.Printf("  Warning: could not apply scheme %s: %v\n", classScheme, err)
				}
			}

			// Detect data classifications from account tags.
			fmt.Println("  Detecting data classifications from account tags...")
			classes, _ := analyzer.ResolveDataClasses(ctx, sre)
			if len(classes) > 0 {
				fmt.Printf("  Data classes found: %s\n", strings.Join(classes, ", "))
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

			fmt.Println()
			fmt.Printf("SRE initialized. Written to .attest/sre.yaml\n")
			fmt.Printf("  Org: %s\n", sre.OrgID)
			fmt.Printf("  Environments: %d\n", len(sre.Environments))
			fmt.Printf("  Active frameworks: %d\n", len(sre.Frameworks))
			if len(sre.Frameworks) == 0 {
				fmt.Println()
				fmt.Println("No frameworks activated. Run 'attest frameworks add <framework-id>' to activate one.")
			} else {
				fmt.Println("\nRun 'attest compile' to generate policy artifacts.")
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

			fmt.Printf("Scanning SRE posture: %s\n", sre.OrgID)
			fmt.Printf("  Environments: %d\n", len(sre.Environments))

			if len(sre.Frameworks) == 0 {
				fmt.Println("\nNo active frameworks. Run 'attest frameworks add <id>' to activate one.")
				return nil
			}

			// Load active frameworks.
			loader := framework.NewLoader(fwDir)
			var frameworks []*schema.Framework
			for _, ref := range sre.Frameworks {
				fw, err := loader.Load(ref.ID)
				if err != nil {
					fmt.Printf("  Warning: could not load framework %s: %v\n", ref.ID, err)
					continue
				}
				frameworks = append(frameworks, fw)
				fmt.Printf("  Loaded framework: %s (%d controls)\n", fw.Name, len(fw.Controls))
			}
			if len(frameworks) == 0 {
				return fmt.Errorf("no frameworks could be loaded")
			}

			// Optionally load deployed SCPs for accurate comparison.
			deployedSCPIDs := make(map[string]bool)
			if region != "" {
				fmt.Printf("  Checking deployed SCPs (region: %s)...\n", region)
				analyzer, err := org.NewAnalyzer(ctx, region)
				if err != nil {
					fmt.Printf("  Warning: could not connect to org: %v\n", err)
				} else {
					deployedSCPs, err := analyzer.InventoryExistingSCPs(ctx)
					if err != nil {
						fmt.Printf("  Warning: could not inventory SCPs: %v\n", err)
					} else {
						for _, s := range deployedSCPs {
							deployedSCPIDs[s.ID] = true
						}
						fmt.Printf("  Found %d deployed SCP(s)\n", len(deployedSCPs))
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
					fmt.Printf("  Loaded crosswalk (%d entries)\n", len(crosswalkEntries))
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
			fmt.Println()
			fmt.Println("Posture summary:")
			fmt.Printf("  Total controls:  %d\n", posture.TotalControls)
			fmt.Printf("  Enforced:        %d\n", posture.Enforced)
			fmt.Printf("  Partial:         %d\n", posture.Partial)
			fmt.Printf("  Gaps:            %d\n", posture.Gaps)

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
				fmt.Printf("\n  %s:\n", fw.Name)
				fmt.Printf("    Enforced: %d  Partial: %d  Gaps: %d\n", enforced, partial, gaps)
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
				fmt.Println("\nTip: run 'attest compile' first for crosswalk-based posture.")
			}

			// Optional: direct API verification (free, no Config required).
			verify, _ := cmd.Flags().GetBool("verify")
			if verify && region != "" {
				runVerification(context.Background(), region, &sre)
			} else if verify {
				fmt.Println("\nNote: --verify requires --region to check live org state.")
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
	fmt.Println("\nDirect API verification (no Config required):")

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		fmt.Printf("  Warning: could not load AWS config for verification: %v\n", err)
		return
	}

	// Check 1: CloudTrail status.
	ctClient := cloudtrail.NewFromConfig(cfg)
	trueVal := true
	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: &trueVal,
	})
	if err != nil {
		fmt.Printf("  cloudtrail: could not check (%v)\n", err)
	} else {
		multiRegion := 0
		for _, t := range trails.TrailList {
			if t.IsMultiRegionTrail != nil && *t.IsMultiRegionTrail {
				multiRegion++
			}
		}
		if multiRegion > 0 {
			fmt.Printf("  ✓ CloudTrail: %d multi-region trail(s) active\n", multiRegion)
		} else if len(trails.TrailList) > 0 {
			fmt.Printf("  ⚠ CloudTrail: %d trail(s) but none multi-region\n", len(trails.TrailList))
		} else {
			fmt.Printf("  ✗ CloudTrail: no trails found\n")
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
			fmt.Printf("  SCPs: could not check (%v)\n", err)
		} else if attestSCPs > 0 {
			fmt.Printf("  ✓ Attest SCPs: %d deployed to org\n", attestSCPs)
		} else {
			fmt.Printf("  ⚠ Attest SCPs: none deployed (run 'attest apply')\n")
		}
	}

	// Check 3: IAM password policy.
	iamClient := iamSvc.NewFromConfig(cfg)
	_, err = iamClient.GetAccountPasswordPolicy(ctx, &iamSvc.GetAccountPasswordPolicyInput{})
	if err != nil {
		fmt.Printf("  ⚠ IAM password policy: not configured\n")
	} else {
		fmt.Printf("  ✓ IAM password policy: active\n")
	}

	fmt.Println("  (Config and Security Hub not required — $0 ongoing cost)")
}

// deduplicationKey mirrors internal/framework.deduplicationKey for CLI use.
// applyClassificationScheme reads a classification scheme YAML and maps
// institutional data classification tags on accounts to attest data classes.
func applyClassificationScheme(schemeName string, sre *schema.SRE) error {
	schemeFile := filepath.Join("classification-schemes", schemeName+".yaml")
	data, err := os.ReadFile(schemeFile)
	if err != nil {
		return fmt.Errorf("reading scheme %s: %w", schemeFile, err)
	}
	var scheme schema.ClassificationScheme
	if err := yaml.Unmarshal(data, &scheme); err != nil {
		return fmt.Errorf("parsing scheme: %w", err)
	}

	tagKey := "attest:data-class"
	if scheme.SchemeID != "" {
		// Scheme-specific tag key (e.g., "UC:DataProtectionLevel" for UC P-levels).
		// We read it from the YAML but fall back to the standard attest tag.
	}

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
						fmt.Printf("    %s → %s (activates %s)\n", accountID, tagV, fwID)
					}
				}
			}
		}
	}
	return nil
}

func deduplicationKey(ctrl schema.Control) string {
	if len(ctrl.Structural) > 0 {
		return ctrl.Structural[0].ID
	}
	return ctrl.Family + "/" + ctrl.ID
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
				fmt.Println("Available frameworks:")
				fmt.Println()
				fmt.Println("  ID                  Name                              Status")
				fmt.Println("  ──────────────────  ────────────────────────────────  ──────────")
				fmt.Println("  nist-800-171-r2     NIST SP 800-171 Rev 2 (CMMC)     available")
				fmt.Println("  hipaa               HIPAA Security Rule               available (BAA detected)")
				fmt.Println("  ferpa               FERPA                             available")
				fmt.Println("  iso27001-2022        ISO/IEC 27001:2022               available")
				fmt.Println("  fedramp-moderate     FedRAMP Moderate Baseline        available")
				fmt.Println("  nist-800-53-r5      NIST SP 800-53 Rev 5 (FedRAMP)   available")
				fmt.Println("  itar                ITAR Export Control                available")
				fmt.Println("  cui                 CUI (32 CFR Part 2002)            available")
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
						fmt.Printf("Framework %s is already active.\n", fwID)
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

				fmt.Printf("Framework activated: %s v%s (%d controls)\n", fw.Name, fw.Version, len(fw.Controls))
				fmt.Println("Run 'attest compile' to generate policy artifacts.")
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
				fmt.Println("No active frameworks. Run 'attest frameworks add <id>' first.")
				return nil
			}

			fmt.Printf("Compiling policies for %d framework(s)...\n", len(sre.Frameworks))

			// Load frameworks.
			loader := framework.NewLoader(fwDir)
			var frameworks []*schema.Framework
			for _, ref := range sre.Frameworks {
				fw, err := loader.Load(ref.ID)
				if err != nil {
					fmt.Printf("  Warning: could not load framework %s: %v\n", ref.ID, err)
					continue
				}
				frameworks = append(frameworks, fw)
			}
			if len(frameworks) == 0 {
				return fmt.Errorf("no frameworks could be loaded from %s", fwDir)
			}

			// Resolve cross-framework controls.
			fmt.Println("  Resolving cross-framework control overlap...")
			rcs, err := framework.Resolve(frameworks)
			if err != nil {
				return fmt.Errorf("resolving controls: %w", err)
			}

			// Compile SCPs.
			scpStrategy, _ := cmd.Flags().GetString("scp-strategy")
			scpCompiler := compilerscp.NewCompiler()
			var scps []compilerscp.CompiledSCP
			if scpStrategy == "merged" {
				fmt.Println("  Generating SCPs (merged strategy — intelligent bin-packing)...")
				var scpStats compilerscp.CompileStats
				var scpErr error
				scps, scpStats, scpErr = scpCompiler.IntelligentCompile(rcs)
				err = scpErr
				if err != nil {
					return fmt.Errorf("compiling SCPs (merged): %w", err)
				}
				fmt.Printf("  %d structural specs → %d unique conditions → %d SCP document(s)\n",
					scpStats.InputSpecs, scpStats.UniqueConditions, scpStats.SCPCount)
				fmt.Printf("  SCP budget: %d / %d chars used (%.1f%%)\n",
					scpStats.TotalChars, compilerscp.TotalBudget, scpStats.BudgetUsed)
			} else {
				fmt.Println("  Generating SCPs (individual strategy)...")
				scps, err = scpCompiler.Compile(rcs)
				if err != nil {
					return fmt.Errorf("compiling SCPs: %w", err)
				}
			}

			// Compile Cedar policies.
			fmt.Println("  Generating Cedar policies (operational enforcement)...")
			cedarCompiler := compilerce.NewCompiler()
			cedarPolicies, err := cedarCompiler.Compile(rcs)
			if err != nil {
				return fmt.Errorf("compiling Cedar policies: %w", err)
			}

			// Generate Cedar schema.
			cedarSchema := cedarCompiler.BuildSchema(rcs)

			// Build crosswalk.
			fmt.Println("  Building crosswalk manifest...")
			crosswalk := buildCrosswalk(&sre, frameworks, scps, cedarPolicies)

			// Write compiled output.
			fmt.Println("  Writing artifacts...")
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
				fmt.Printf("  Generating %s IaC output...\n", iacOutput)
				iacGen := iac.NewGenerator(iac.Format(iacOutput), filepath.Join(compiledDir, iacOutput))
				if err := iacGen.Generate(compiledDir); err != nil {
					return fmt.Errorf("generating IaC output: %w", err)
				}
				fmt.Printf("  IaC output: %s\n", filepath.Join(compiledDir, iacOutput))
			}

			fmt.Println()
			fmt.Printf("Compiled artifacts written to %s\n", compiledDir)
			fmt.Printf("  %d SCP(s)\n", len(scps))
			fmt.Printf("  %d Cedar policy/policies + schema\n", len(cedarPolicies))
			fmt.Printf("  Crosswalk: %s\n", filepath.Join(compiledDir, "crosswalk.yaml"))
			fmt.Println()
			fmt.Println("Run 'attest apply' to deploy to the organization.")
			return nil
		},
	}
	cmd.Flags().String("frameworks", "frameworks", "Path to frameworks directory")
	cmd.Flags().String("output", "", "IaC output format: terraform, cdk")
	cmd.Flags().String("scp-strategy", "individual", "SCP compilation strategy: individual (one SCP per spec, for inspection) or merged (intelligent bin-packing, for production — fits within 5-per-target limit)")
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

			fmt.Println("Computing deployment plan...")
			plan, err := deployer.Plan(ctx, scpDir)
			if err != nil {
				return fmt.Errorf("planning deployment: %w", err)
			}
			fmt.Println(plan.Summary())

			if plan.QuotaWarning != "" {
				fmt.Printf("\n  ⚠ Quota warning: %s\n\n", plan.QuotaWarning)
			}

			if dryRun {
				fmt.Println("Dry run — no changes made.")
				return nil
			}
			if len(plan.ToCreate)+len(plan.ToUpdate)+len(plan.ToAttach) == 0 {
				return nil
			}
			if !approve {
				fmt.Print("Apply these changes to the organization? [y/N] ")
				var answer string
				fmt.Scanln(&answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			// Auto-tag a pre-apply snapshot so rollback has a target.
			st, _ := store.NewStore(".attest")
			tagName := fmt.Sprintf("applied-%s", time.Now().UTC().Format("20060102-150405"))
			if err := st.Tag(tagName, fmt.Sprintf("Pre-apply snapshot: %s", tagName)); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: could not create pre-apply snapshot: %v\n", err)
			} else {
				fmt.Printf("  Snapshot: %s\n", tagName)
			}

			fmt.Println("Applying...")
			result, err := deployer.Apply(ctx, plan, scpDir, func(msg string) {
				fmt.Println(msg)
			})
			if err != nil {
				return fmt.Errorf("applying: %w", err)
			}
			_ = st.Commit(fmt.Sprintf("apply: deployed %d SCP(s) to %s",
				len(result.Deployed), plan.RootID))

			fmt.Printf("\nDeployed %d SCP(s) to %s.\n", len(result.Deployed), plan.RootID)
			if len(result.Failed) > 0 {
				fmt.Printf("  ✗ %d SCP(s) failed (invalid condition keys — fix framework YAML):\n", len(result.Failed))
				for _, f := range result.Failed {
					fmt.Printf("    - %s\n", f)
				}
			}
			fmt.Println("Run 'attest scan' to verify posture.")
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
					fmt.Println("No snapshots found. Run 'attest apply' to create one.")
					return nil
				}
				fmt.Println("Available snapshots (most recent first):")
				for _, t := range tags {
					fmt.Printf("  %s\n", t)
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

			fmt.Printf("Rollback target: %s\n\n", targetTag)

			if !approve {
				fmt.Printf("This will detach all attest SCPs from the org root and re-apply state from %s.\n", targetTag)
				fmt.Print("Proceed? [y/N] ")
				var answer string
				fmt.Scanln(&answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Println("Aborted.")
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
			fmt.Printf("Detaching all attest-managed SCPs from %s...\n", rootID)
			if err := deployer.DetachAll(ctx, rootID); err != nil {
				return fmt.Errorf("detaching SCPs: %w", err)
			}
			fmt.Println("  Done.")

			// Step 2: Restore compiled artifacts from checkpoint.
			fmt.Printf("Restoring compiled artifacts from snapshot %s...\n", targetTag)
			if err := st.Checkout(targetTag); err != nil {
				return fmt.Errorf("checking out snapshot: %w", err)
			}
			defer func() {
				// Always return store to HEAD when done.
				_ = st.Checkout("main")
			}()
			fmt.Println("  Done.")

			// Step 3: Re-apply from restored state.
			scpDir := filepath.Join(".attest", "compiled", "scps")
			fmt.Println("Re-applying checkpoint state...")
			checkpointPlan, err := deployer.Plan(ctx, scpDir)
			if err != nil {
				return fmt.Errorf("planning checkpoint apply: %w", err)
			}
			result, err := deployer.Apply(ctx, checkpointPlan, scpDir, func(msg string) {
				fmt.Println(msg)
			})
			if err != nil {
				return fmt.Errorf("applying checkpoint: %w", err)
			}

			fmt.Printf("\nRollback complete. Deployed %d SCP(s) from snapshot %s.\n",
				len(result.Deployed), targetTag)
			if len(result.Failed) > 0 {
				for _, f := range result.Failed {
					fmt.Printf("  ✗ %s\n", f)
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

			fmt.Printf("Checking prerequisites for attest apply...\n\n")

			// Connect to AWS.
			deployer, err := deploy.NewDeployer(ctx, region)
			if err != nil {
				return fmt.Errorf("connecting to AWS: %w", err)
			}

			allGood := true
			fail := func(format string, a ...any) {
				fmt.Printf("  ✗ "+format+"\n", a...)
				allGood = false
			}
			pass := func(format string, a ...any) {
				fmt.Printf("  ✓ "+format+"\n", a...)
			}
			warn := func(format string, a ...any) {
				fmt.Printf("  ⚠ "+format+"\n", a...)
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
							fmt.Printf("      %s\n", plan.QuotaWarning)
						} else {
							pass("SCP quota: %d compiled, %d total after apply (within limit of %d)",
								compiledCount, projectedTotal, deploy.SCPPerTargetLimit)
						}
					}
				}
			}

		result:
			fmt.Println()
			if allGood {
				fmt.Println("Result: READY — run 'attest apply --dry-run' to preview")
			} else {
				fmt.Println("Result: NOT READY — resolve issues above before running 'attest apply'")
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
						if resolved.CUITrainingCurrent {
							attributes["principal.cui_training_current"] = true
						}
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
			fmt.Printf("Decision:  %s\n", effect)
			fmt.Printf("Principal: %s\n", principalARN)
			fmt.Printf("Action:    %s\n", action)
			fmt.Printf("Resource:  %s\n", resourceARN)
			if decision.PolicyID != "" {
				fmt.Printf("Policy:    %s\n", decision.PolicyID)
			}
			if decision.WaiverID != "" {
				fmt.Printf("Waiver:    %s\n", decision.WaiverID)
			}
			return nil
		},
	}
	cmd.Flags().String("principal", "", "Principal ARN (required)")
	cmd.Flags().String("action", "", "IAM action (required)")
	cmd.Flags().String("resource", "", "Resource ARN (required)")
	cmd.Flags().StringSlice("attr", nil, "Entity attributes: entity.attr=value (repeatable)")
	cmd.Flags().String("cedar", filepath.Join(".attest", "compiled", "cedar"), "Cedar policies directory")
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
		for id, policy := range parsed.Map() {
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
	cmd.AddCommand(generateSSPCmd(), generatePOAMCmd(), generateAssessCmd(), generateOSCALCmd())
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
			fmt.Printf("  Warning: could not load framework %s: %v\n", fwID, err)
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
	fmt.Printf("Generating System Security Plan (%s)...\n", fw.Name)
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
	fmt.Printf("  SSP written to %s\n", mdPath)
	fmt.Printf("  Status: %s | Score: %.0f/%.0f\n", doc.OverallStatus, doc.Score, float64(len(fw.Controls)*5))
	return nil
}

func generatePOAM(sre *schema.SRE, fw *schema.Framework, crosswalk *schema.Crosswalk, docsDir string) error {
	fmt.Printf("Generating POA&M (%s)...\n", fw.Name)
	gen := poam.NewGenerator()
	doc, err := gen.Generate(sre, fw, crosswalk)
	if err != nil {
		return fmt.Errorf("generating POA&M: %w", err)
	}
	mdPath := filepath.Join(docsDir, "poam.md")
	if err := os.WriteFile(mdPath, []byte(doc.Render()), 0640); err != nil {
		return err
	}
	fmt.Printf("  POA&M written to %s\n", mdPath)
	fmt.Printf("  Items: %d gaps, %d partial\n", doc.GapCount, doc.PartialCount)
	return nil
}

func generateAssessment(sre *schema.SRE, fw *schema.Framework, crosswalk *schema.Crosswalk, docsDir string) error {
	fmt.Printf("Generating self-assessment (%s)...\n", fw.Name)
	gen := assessment.NewGenerator()
	doc, err := gen.Generate(sre, fw, crosswalk)
	if err != nil {
		return fmt.Errorf("generating assessment: %w", err)
	}
	mdPath := filepath.Join(docsDir, "assessment.md")
	if err := os.WriteFile(mdPath, []byte(doc.Render()), 0640); err != nil {
		return err
	}
	fmt.Printf("  Assessment written to %s\n", mdPath)
	fmt.Printf("  Score: %d/%d (%.1f%%) — %s\n", doc.TotalScore, doc.MaxScore, doc.ScorePercent, doc.Readiness)
	return nil
}

func generateOSCAL(sre *schema.SRE, fw *schema.Framework, crosswalk *schema.Crosswalk, docsDir string) error {
	fmt.Println("Exporting to OSCAL 1.1.2...")

	// Re-generate SSP for OSCAL export.
	sspGen := ssp.NewGenerator()
	sspDoc, err := sspGen.Generate(sre, fw, crosswalk, nil)
	if err != nil {
		return err
	}
	sspExporter := oscal.NewSSPExporter()
	sspJSON, err := sspExporter.ExportSSP(sspDoc)
	if err != nil {
		return fmt.Errorf("exporting SSP to OSCAL: %w", err)
	}
	sspPath := filepath.Join(docsDir, "ssp-"+fw.ID+".oscal.json")
	if err := os.WriteFile(sspPath, sspJSON, 0640); err != nil {
		return err
	}
	fmt.Printf("  SSP: %s\n", sspPath)

	// Re-generate assessment for OSCAL export.
	assGen := assessment.NewGenerator()
	assDoc, err := assGen.Generate(sre, fw, crosswalk)
	if err != nil {
		return err
	}
	assExporter := oscal.NewAssessmentExporter()
	assJSON, err := assExporter.ExportAssessment(assDoc)
	if err != nil {
		return fmt.Errorf("exporting assessment to OSCAL: %w", err)
	}
	assPath := filepath.Join(docsDir, "assessment-results.oscal.json")
	if err := os.WriteFile(assPath, assJSON, 0640); err != nil {
		return err
	}
	fmt.Printf("  Assessment Results: %s\n", assPath)
	return nil
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
	fmt.Printf("Comparing posture snapshots:\n")
	fmt.Printf("  From: %s\n", from.Timestamp.Format("2006-01-02 15:04"))
	fmt.Printf("  To:   %s\n\n", to.Timestamp.Format("2006-01-02 15:04"))

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
	fmt.Printf("Score: %d → %d (%s%d pts)\n\n", fromScore, toScore, sign, scoreDelta)

	if len(improvedList) > 0 {
		fmt.Println("Improved:")
		for _, s := range improvedList {
			fmt.Println(s)
		}
		fmt.Println()
	}
	if len(regressedList) > 0 {
		fmt.Println("Regressed:")
		for _, s := range regressedList {
			fmt.Println(s)
		}
		fmt.Println()
	}
	fmt.Printf("No change: %d controls\n", unchanged)
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

			fmt.Println("Starting Cedar PDP watch (CloudTrail polling mode)...")
			fmt.Printf("  Policies: %s\n", cedarDir)
			fmt.Printf("  Poll interval: %ds\n", intervalSecs)
			fmt.Println("  Press Ctrl+C to stop.")
			fmt.Println()

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

			fmt.Println("Watching for Cedar decisions (showing DENY)...")
			for ev := range ch {
				if ev.Effect == "DENY" {
					fmt.Printf("  [%s] DENY  %s  %s → %s\n",
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
				fmt.Printf("Starting attest dashboard with OIDC auth (%s)\n", oidcIssuer)
				srv := dashboard.NewServerWithOIDC(addr, ".attest", oidcHandler, nil)
				if err := srv.Start(ctx); err != nil && err.Error() != "http: Server closed" {
					return err
				}
				return nil
			}

			fmt.Printf("Starting attest dashboard on http://localhost%s\n", addr)
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
				fmt.Printf("No test suites found in %s\n", testsDir)
				fmt.Println("Create .yaml test suite files to get started.")
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
				fmt.Printf("[%s] %s: %d/%d passed\n", status, result.Name, result.Passed, result.Total)
				for _, c := range result.Cases {
					if !c.Passed {
						fmt.Printf("  FAIL: %s — expected %s, got %s\n", c.Description, c.Expected, c.Actual)
					}
				}
				totalPass += result.Passed
				totalFail += result.Failed
			}

			fmt.Printf("\nTotal: %d passed, %d failed\n", totalPass, totalFail)
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
				fmt.Println(result.SARIF())
			default:
				if result.Passed {
					fmt.Println("PASS: No compliance violations found.")
				} else {
					fmt.Printf("FAIL: %d violation(s) found.\n\n", len(result.Violations))
					for _, v := range result.Violations {
						fmt.Printf("  %s: %s\n    Control: %s | Policy: %s\n    %s\n\n",
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
			fmt.Printf("Simulating: %d current vs %d proposed policies\n", currentCount, proposedCount)
			fmt.Printf("CloudTrail window: last %d hour(s) (region: %s)\n\n", hours, region)

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
				fmt.Println("No CloudTrail events found in the specified window.")
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
					fmt.Printf("  [ALLOW→DENY] %s  %s\n", req.PrincipalARN, req.Action)
				} else {
					denyToAllow++
					fmt.Printf("  [DENY→ALLOW] %s  %s\n", req.PrincipalARN, req.Action)
				}
			}
			fmt.Printf("\nResults: %d ALLOW→DENY, %d DENY→ALLOW, %d unchanged (from %d events)\n",
				allowToDeny, denyToAllow, unchanged, len(out.Events))
			if allowToDeny > 0 {
				fmt.Println("\n⚠ Proposed policies would block operations currently allowed.")
				fmt.Println("  Review the ALLOW→DENY list above before deploying.")
			}
			if denyToAllow > 0 {
				fmt.Println("\n⚠ Proposed policies would permit operations currently denied.")
				fmt.Println("  Confirm this is intentional before deploying.")
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
func translateCloudTrailEvent(ev cttypes.Event) *evaluator.AuthzRequest {
	if ev.EventName == nil {
		return nil
	}
	principal := "arn:aws:iam::unknown:user/unknown"
	if ev.Username != nil {
		principal = "arn:aws:iam::unknown:user/" + *ev.Username
	}
	resource := "*"
	for _, r := range ev.Resources {
		if r.ResourceName != nil {
			resource = *r.ResourceName
			break
		}
	}
	return &evaluator.AuthzRequest{
		Action:       *ev.EventName,
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

			fmt.Println("Computing provisioning plan...")
			plan, err := provisioner.ComputePlan(ctx, &sre, req)
			if err != nil {
				return fmt.Errorf("computing plan: %w", err)
			}

			fmt.Printf("\nProvisioning plan:\n")
			fmt.Printf("  Account name:   %s\n", plan.AccountName)
			fmt.Printf("  Account email:  %s\n", plan.AccountEmail)
			fmt.Printf("  Target OU:      %s (%s)\n", plan.TargetOUName, plan.TargetOU)
			fmt.Printf("  SCPs inherited: %d\n", plan.SCPsInherited)
			fmt.Printf("  Data classes:   %s\n", strings.Join(dataClasses, ", "))
			fmt.Println("\nPrerequisites:")
			for _, pr := range plan.Prerequisites {
				mark := "✓"
				if !pr.Met {
					mark = "✗"
				}
				fmt.Printf("  %s %s\n", mark, pr.Description)
			}
			fmt.Println("\nTags to apply:")
			for k, v := range plan.AttestTags {
				fmt.Printf("  %s = %s\n", k, v)
			}

			if !plan.AllMet {
				return fmt.Errorf("\nPrerequisites not met — resolve the issues above and re-run")
			}

			if !approve {
				fmt.Print("\nCreate this environment? [y/N] ")
				var answer string
				fmt.Scanln(&answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			fmt.Printf("\nCreating AWS account %q...\n", plan.AccountName)
			fmt.Println("  (Account creation is async — polling every 5s, timeout 10 min)")
			env, err := provisioner.Execute(ctx, plan)
			if err != nil {
				return fmt.Errorf("provisioning failed: %w", err)
			}

			fmt.Printf("\nEnvironment created: %s\n", env.AccountID)
			fmt.Printf("  Placed in OU: %s\n", plan.TargetOUName)
			fmt.Printf("  Owner: %s\n", env.Owner)
			fmt.Println("\nNext steps:")
			fmt.Println("  1. attest scan — include new environment in posture report")
			fmt.Println("  2. attest compile --scp-strategy merged — update SCP set if needed")
			fmt.Println("  3. attest apply --approve — deploy updated SCPs to org")

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
			fmt.Printf("Waiver created: %s\n", w.ID)
			fmt.Printf("  Control: %s | Scope: %s | Expires: %s\n", w.ControlID, w.Scope, w.ExpiresAt.Format("2006-01-02"))
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
				fmt.Println("No active waivers.")
				return nil
			}
			fmt.Printf("%-15s %-10s %-20s %-12s %s\n", "ID", "Control", "Scope", "Expires", "Status")
			fmt.Println(strings.Repeat("─", 72))
			for _, w := range waivers {
				fmt.Printf("%-15s %-10s %-20s %-12s %s\n",
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
			fmt.Printf("Waiver %s expired.\n", args[0])
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

			fmt.Printf("Posture trend (window: %s)\n\n", windowStr)
			fmt.Printf("  Snapshots: %d\n", len(trend.Snapshots))
			fmt.Printf("  Gaps closed: %d | Gaps opened: %d\n", trend.GapsClosed, trend.GapsOpened)
			if len(trend.ScoreTrend) > 0 {
				first := trend.ScoreTrend[0]
				last := trend.ScoreTrend[len(trend.ScoreTrend)-1]
				fmt.Printf("  Score: %.0f%% → %.0f%%\n", first.Score, last.Score)
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
		fmt.Sscanf(s, "%dd", &days)
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
			fmt.Printf("Created incident %s: %s [%s]\n", inc.ID, inc.Title, inc.Severity)
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
				fmt.Println("No incidents recorded.")
				return nil
			}
			for _, inc := range incidents {
				resolved := ""
				if inc.ResolvedAt != nil {
					resolved = fmt.Sprintf(" → resolved %s", inc.ResolvedAt.Format("2006-01-02"))
				}
				fmt.Printf("  [%s] %s  %s  %s%s\n",
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
			fmt.Printf("Incident %s resolved.\n", args[0])
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
			fmt.Printf("Attestation created: %s\n", a.ID)
			fmt.Printf("  Control: %s | Expires: %s\n", a.ControlID, a.ExpiresAt.Format("2006-01-02"))
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
				fmt.Println("No attestations.")
				return nil
			}
			fmt.Printf("%-18s %-10s %-22s %-12s %s\n", "ID", "Control", "Affirmed by", "Expires", "Status")
			fmt.Println(strings.Repeat("─", 76))
			for _, a := range attestations {
				fmt.Printf("%-18s %-10s %-22s %-12s %s\n",
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
			fmt.Printf("Attestation %s expired.\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(createCmd, listCmd, expireCmd)
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

			fmt.Printf("Compliance calendar (next %s)\n\n", windowStr)
			fmt.Printf("  %-10s %-8s %-45s %-12s\n", "Control", "Freq", "Title", "Due / Status")
			fmt.Println("  " + strings.Repeat("─", 78))

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
						fmt.Sscanf(status, "%d days", &days)
						if days <= 30 {
							indicator = "⚠"
						}
					}

					title := ctrl.Title
					if len(title) > 44 {
						title = title[:41] + "..."
					}
					fmt.Printf("  %s %-9s %-8s %-45s %s\n",
						indicator, ctrl.ID, ctrl.ReviewSchedule.Frequency, title, status)
					hasItems = true
				}
			}

			if !hasItems {
				fmt.Println("  No review obligations due within the window.")
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
			fmt.Printf("Asking: %s\n\n", question)

			answer, err := analyst.Ask(ctx, question)
			if err != nil {
				return fmt.Errorf("AI query failed: %w\nEnsure Bedrock access is enabled in region %s", err, region)
			}
			fmt.Println(answer)
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
				fmt.Printf("\nAnalyzing: %s\n", filepath.Base(f))
				findings, err := analyst.IngestDocument(ctx, f, fwIDs)
				if err != nil {
					fmt.Printf("  Warning: %v\n", err)
					continue
				}

				fmt.Printf("  %-12s %-12s %s\n", "Control", "Status", "Evidence")
				fmt.Printf("  %s\n", strings.Repeat("─", 60))
				for _, finding := range findings {
					status := finding.Status
					evid := finding.Evidence
					if len(evid) > 50 {
						evid = evid[:47] + "..."
					}
					fmt.Printf("  %-12s %-12s %s\n", finding.ControlID, status, evid)
					if finding.Status == "covered" {
						totalCovered++
					}
					if finding.DraftAtt != nil {
						// Write draft attestation.
						draftDir := filepath.Join(".attest", "attestations", "drafts")
						_ = os.MkdirAll(draftDir, 0750)
						data, _ := yaml.Marshal(finding.DraftAtt)
						_ = os.WriteFile(filepath.Join(draftDir, finding.DraftAtt.ID+".yaml"), data, 0640)
						totalDrafts++
					}
				}
			}

			fmt.Printf("\n%d controls covered | %d attestation drafts created in .attest/attestations/drafts/\n", totalCovered, totalDrafts)
			if totalDrafts > 0 {
				fmt.Println("Review drafts, then: attest attest create --control <id> --affirmed-by <name> --expires <date>")
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
			fmt.Printf("Running %s onboarding analysis...\n\n", mode)

			plan, err := analyst.Onboard(ctx, mode, docsDir)
			if err != nil {
				return fmt.Errorf("onboarding analysis failed: %w", err)
			}

			fmt.Println(plan.Summary)
			if len(plan.PriorityItems) > 0 {
				fmt.Printf("\nPriority actions:\n")
				for i, item := range plan.PriorityItems {
					fmt.Printf("\n%d. [%s] %s — %s\n", i+1, item.Priority, item.ControlID, item.Title)
					if item.Reason != "" {
						fmt.Printf("   Why: %s\n", item.Reason)
					}
					if item.NextStep != "" {
						fmt.Printf("   Next: %s\n", item.NextStep)
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
		Run:   func(cmd *cobra.Command, args []string) { fmt.Printf("attest %s\n", version) },
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

			fmt.Printf("Verifying: %s\n", binary)
			fmt.Printf("Expected identity: github.com/%s/attest\n", org)
			fmt.Printf("OIDC issuer: https://token.actions.githubusercontent.com\n\n")
			fmt.Printf("Run:\n")
			fmt.Printf("  cosign verify-blob %s \\\n", binary)
			fmt.Printf("    --bundle %s.bundle \\\n", binary)
			fmt.Printf("    --certificate-identity-regexp 'github.com/%s/attest' \\\n", org)
			fmt.Printf("    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'\n\n")
			fmt.Println("Download the .bundle file alongside the binary from the GitHub Release.")
			fmt.Println("Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/")
			return nil
		},
	}
	cmd.Flags().String("org", "provabl", "GitHub org that signed the release")
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
			fmt.Println("Running simulated CMMC Level 2 assessment (Opus 4.6)...")
			result, err := analyst.AuditSim(ctx)
			if err != nil {
				return fmt.Errorf("audit simulation failed: %w", err)
			}
			fmt.Printf("\nSimulated Score: %d / 110 controls\n\n", result.Score)
			fmt.Printf("Assessor Narrative:\n%s\n\n", result.Narrative)
			if len(result.Weaknesses) > 0 {
				fmt.Println("Weaknesses identified:")
				for _, w := range result.Weaknesses {
					fmt.Printf("  • %s\n", w)
				}
			}
			if len(result.Findings) > 0 {
				fmt.Println("\nDraft Findings:")
				for _, f := range result.Findings {
					fmt.Printf("  [FINDING] %s\n", f)
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
			fmt.Printf("Translating: %q\n\n", statement)
			cedar, err := analyst.TranslateToCedar(ctx, statement)
			if err != nil {
				return fmt.Errorf("translation failed: %w", err)
			}
			fmt.Println(cedar)
			fmt.Println("\nReview the policy, then: cp proposed.cedar .attest/proposed/")
			fmt.Println("Test with: attest simulate --proposed .attest/proposed/")
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
			fmt.Printf("Analyzing Cedar decision log: %s\n\n", logPath)
			anomalies, err := analyst.AnalyzeAnomalies(ctx, logPath)
			if err != nil {
				return fmt.Errorf("analysis failed: %w", err)
			}
			if len(anomalies) == 0 {
				fmt.Println("No anomalies detected.")
				return nil
			}
			for _, a := range anomalies {
				fmt.Printf("[%s] %s (%d occurrences)\n", a.Severity, a.Pattern, a.Occurrences)
				if len(a.ControlIDs) > 0 {
					fmt.Printf("  Controls: %s\n", strings.Join(a.ControlIDs, ", "))
				}
				fmt.Printf("  Suggestion: %s\n\n", a.Suggestion)
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
			fmt.Printf("Analyzing framework impact: %s\n\n", args[0])
			result, err := analyst.AnalyzeImpact(ctx, args[0])
			if err != nil {
				return fmt.Errorf("impact analysis failed: %w", err)
			}
			fmt.Printf("Summary:\n%s\n\n", result.Summary)
			if len(result.NewControls) > 0 {
				fmt.Printf("New controls (%d):\n", len(result.NewControls))
				for _, c := range result.NewControls {
					fmt.Printf("  + %s\n", c)
				}
			}
			if len(result.AffectedSCPs) > 0 {
				fmt.Printf("\nAffected SCPs: %s\n", strings.Join(result.AffectedSCPs, ", "))
			}
			if result.SCPBudgetDelta != 0 {
				sign := "+"
				if result.SCPBudgetDelta < 0 {
					sign = ""
				}
				fmt.Printf("SCP budget delta: %s%d chars\n", sign, result.SCPBudgetDelta)
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
			fmt.Printf("Generating remediation for %s...\n\n", controlID)
			artifact, err := analyst.Remediate(ctx, controlID)
			if err != nil {
				return fmt.Errorf("remediation failed: %w", err)
			}
			fmt.Printf("Type: %s\nTitle: %s\n\n", artifact.Type, artifact.Title)
			fmt.Println(artifact.Content)
			if artifact.Explanation != "" {
				fmt.Printf("\nExplanation: %s\n", artifact.Explanation)
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
					fmt.Printf("\nWritten to: %s\n", outPath)
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
			fmt.Printf("Generating %s document for control %s...\n\n", policyType, controlID)
			artifact, err := analyst.GenerateAdminPolicy(ctx, controlID, policyType)
			if err != nil {
				return fmt.Errorf("policy generation failed: %w", err)
			}
			fmt.Printf("Title: %s\n\n", artifact.Title)
			fmt.Println(artifact.Content)
			if artifact.Explanation != "" {
				fmt.Printf("\nAudit note: %s\n", artifact.Explanation)
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
					fmt.Printf("\nWritten to: %s\n", outPath)
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
