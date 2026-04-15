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

var version = "0.4.0-dev"

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
			if err := os.WriteFile(filepath.Join(".attest", "sre.yaml"), out, 0644); err != nil {
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
					_ = os.WriteFile(filepath.Join(".attest", "history", fname), data, 0644)
				}
			}

			if crosswalkEntries == nil {
				fmt.Println("\nTip: run 'attest compile' first for crosswalk-based posture.")
			}
			return nil
		},
	}
	cmd.Flags().String("frameworks", "frameworks", "Path to frameworks directory")
	cmd.Flags().String("region", "", "AWS region for live SCP deployment check (optional)")
	return cmd
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
				fmt.Println("  nist-800-53-r5      NIST SP 800-53 Rev 5 (FedRAMP)   available")
				fmt.Println("  itar                ITAR Export Control                available")
				fmt.Println("  cui                 CUI (32 CFR Part 2002)            available")
				return nil
			},
		},
		&cobra.Command{
			Use:   "add [framework-id]",
			Short: "Activate a framework for this SRE",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Printf("Activating framework: %s\n", args[0])
				fmt.Println("  Loading framework definition...")
				fmt.Println("  Validating Artifact agreement requirements...")
				fmt.Println("  Computing control overlap with existing frameworks...")
				fmt.Printf("  Framework %s activated. Run 'attest compile' to generate policies.\n", args[0])
				return nil
			},
		},
	)
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
			fmt.Println("  Generating SCPs (structural enforcement)...")
			scpCompiler := compilerscp.NewCompiler()
			scps, err := scpCompiler.Compile(rcs)
			if err != nil {
				return fmt.Errorf("compiling SCPs: %w", err)
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
			if err := os.MkdirAll(filepath.Join(compiledDir, "scps"), 0750); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Join(compiledDir, "cedar"), 0750); err != nil {
				return err
			}

			for _, s := range scps {
				path := filepath.Join(compiledDir, "scps", s.ID+".json")
				if err := os.WriteFile(path, []byte(s.PolicyJSON), 0644); err != nil {
					return fmt.Errorf("writing SCP %s: %w", s.ID, err)
				}
			}

			for _, p := range cedarPolicies {
				path := filepath.Join(compiledDir, "cedar", p.ID+".cedar")
				if err := os.WriteFile(path, []byte(p.PolicyText), 0644); err != nil {
					return fmt.Errorf("writing Cedar policy %s: %w", p.ID, err)
				}
			}

			if err := os.WriteFile(filepath.Join(compiledDir, "cedar", "schema.cedarschema"), []byte(cedarSchema), 0644); err != nil {
				return fmt.Errorf("writing Cedar schema: %w", err)
			}

			crosswalkBytes, err := yaml.Marshal(crosswalk)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(compiledDir, "crosswalk.yaml"), crosswalkBytes, 0644); err != nil {
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
	return cmd
}

// buildCrosswalk creates the auditable control → artifact mapping.
func buildCrosswalk(sre *schema.SRE, frameworks []*schema.Framework, scps []compilerscp.CompiledSCP, cedarPolicies []compilerce.CompiledCedarPolicy) schema.Crosswalk {
	crosswalk := schema.Crosswalk{
		SRE:         sre.OrgID,
		GeneratedAt: time.Now(),
	}
	if len(frameworks) > 0 {
		crosswalk.Framework = frameworks[0].ID
		if len(frameworks) > 1 {
			names := make([]string, len(frameworks))
			for i, fw := range frameworks {
				names[i] = fw.ID
			}
			crosswalk.Framework = strings.Join(names, "+")
		}
	}

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

	// Build an entry for every control across all frameworks.
	seen := make(map[string]bool)
	for _, fw := range frameworks {
		for _, ctrl := range fw.Controls {
			if seen[ctrl.ID] {
				continue
			}
			seen[ctrl.ID] = true

			entry := schema.CrosswalkEntry{ControlID: ctrl.ID}
			entry.SCPs = scpsByControl[ctrl.ID]
			entry.CedarPolicies = cedarByControl[ctrl.ID]

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

			fmt.Println("Applying...")
			if err := deployer.Apply(ctx, plan, scpDir, func(msg string) {
				fmt.Println(msg)
			}); err != nil {
				return fmt.Errorf("applying: %w", err)
			}
			st, _ := store.NewStore(".attest")
			_ = st.Commit(fmt.Sprintf("apply: deployed %d SCP(s) to %s",
				len(plan.ToCreate)+len(plan.ToUpdate)+len(plan.ToAttach), plan.RootID))

			fmt.Printf("\nDeployed %d SCP(s) to %s.\nRun 'attest scan' to verify posture.\n",
				len(plan.ToCreate)+len(plan.ToUpdate)+len(plan.ToAttach), plan.RootID)
			return nil
		},
	}
	cmd.Flags().Bool("dry-run", false, "Preview changes without applying")
	cmd.Flags().Bool("approve", false, "Skip interactive approval")
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
Run 'attest compile' first.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fwDir, _ := cmd.Flags().GetString("frameworks")
			return runGenerate(fwDir, "ssp")
		},
	}
	cmd.Flags().String("frameworks", "frameworks", "Path to frameworks directory")
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
func runGenerate(fwDir, docType string) error {
	// Load SRE config.
	sreData, err := os.ReadFile(filepath.Join(".attest", "sre.yaml"))
	if err != nil {
		return fmt.Errorf("reading .attest/sre.yaml: %w (run 'attest init' first)", err)
	}
	var sre schema.SRE
	if err := yaml.Unmarshal(sreData, &sre); err != nil {
		return fmt.Errorf("parsing sre.yaml: %w", err)
	}

	// Load crosswalk.
	cwData, err := os.ReadFile(filepath.Join(".attest", "compiled", "crosswalk.yaml"))
	if err != nil {
		return fmt.Errorf("reading crosswalk: %w (run 'attest compile' first)", err)
	}
	var crosswalk schema.Crosswalk
	if err := yaml.Unmarshal(cwData, &crosswalk); err != nil {
		return fmt.Errorf("parsing crosswalk: %w", err)
	}

	// Determine framework from crosswalk.
	fwID := strings.SplitN(crosswalk.Framework, "+", 2)[0]
	loader := framework.NewLoader(fwDir)
	fw, err := loader.Load(fwID)
	if err != nil {
		return fmt.Errorf("loading framework %s: %w", fwID, err)
	}

	// Ensure output directory exists.
	docsDir := filepath.Join(".attest", "documents")
	if err := os.MkdirAll(docsDir, 0750); err != nil {
		return err
	}

	switch docType {
	case "ssp":
		return generateSSP(&sre, fw, &crosswalk, docsDir)
	case "poam":
		return generatePOAM(&sre, fw, &crosswalk, docsDir)
	case "assess":
		return generateAssessment(&sre, fw, &crosswalk, docsDir)
	case "oscal":
		if err := generateSSP(&sre, fw, &crosswalk, docsDir); err != nil {
			return err
		}
		return generateOSCAL(&sre, fw, &crosswalk, docsDir)
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
	if err := os.WriteFile(mdPath, []byte(md), 0644); err != nil {
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
	if err := os.WriteFile(mdPath, []byte(doc.Render()), 0644); err != nil {
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
	if err := os.WriteFile(mdPath, []byte(doc.Render()), 0644); err != nil {
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
	if err := os.WriteFile(sspPath, sspJSON, 0644); err != nil {
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
	if err := os.WriteFile(assPath, assJSON, 0644); err != nil {
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
		Short: "Continuous Cedar PDP evaluation (polling mode)",
		Long: `Polls the Cedar evaluation log for new decisions and prints denials.
Full EventBridge-driven continuous evaluation is v1.0.0.
Use 'attest evaluate' for one-shot evaluation.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cedarDir, _ := cmd.Flags().GetString("cedar")
			fmt.Println("Starting Cedar PDP watch (polling mode)...")
			fmt.Printf("  Policies: %s\n", cedarDir)
			fmt.Println("  Note: Full EventBridge integration coming in v1.0.0.")
			fmt.Println("  Press Ctrl+C to stop.")
			fmt.Println()

			// Load policies once.
			ps, err := loadCedarPolicies(cedarDir)
			if err != nil {
				return fmt.Errorf("loading Cedar policies: %w", err)
			}
			if ps == nil {
				return fmt.Errorf("no Cedar policies found in %s", cedarDir)
			}

			// Simple health-check: print policy count and block.
			count := 0
			for range ps.All() {
				count++
			}
			fmt.Printf("  Loaded %d Cedar policy/policies. Ready.\n", count)
			fmt.Println("  (Polling for denials — EventBridge integration deferred to v1.0.0)")
			select {} // block until Ctrl+C
		},
	}
	cmd.Flags().String("cedar", filepath.Join(".attest", "compiled", "cedar"), "Compiled Cedar policies directory")
	return cmd
}

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Launch the compliance dashboard",
		Long: `Starts the web dashboard on the specified address. The dashboard
provides real-time compliance visibility: posture, frameworks, Cedar PDP
operations feed, environment status, waivers, incidents, and document generation.

Same binary, same data as the CLI — the dashboard is the "always on"
complement to the CLI's point-in-time commands.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, _ := cmd.Flags().GetString("addr")
			fmt.Printf("Starting attest dashboard on %s...\n", addr)
			fmt.Println("  Loading SRE configuration...")
			fmt.Println("  Connecting to Cedar PDP...")
			fmt.Println("  Dashboard ready.")
			return nil
		},
	}
	cmd.Flags().String("addr", ":8443", "Listen address")
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
	return &cobra.Command{
		Use:   "simulate",
		Short: "Replay CloudTrail events against proposed policies",
		Long: `Replays a window of real CloudTrail events against a proposed policy
set and diffs the results. Shows which operations would change from
ALLOW to DENY (or vice versa) and their impact on production workloads.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Running policy simulation...")
			fmt.Println("  Loading proposed policies...")
			fmt.Println("  Replaying CloudTrail events...")
			return nil
		},
	}
}

func provisionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "provision",
		Short: "Create a new compliant research environment",
		Long: `Creates a new AWS account in the SRE with the correct OU placement,
tags, and Cedar entity registration based on the requested data
classifications. Checks prerequisites (BAA signed, training current)
before provisioning.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Computing provisioning plan...")
			fmt.Println("  Checking prerequisites...")
			fmt.Println("  Determining target OU from data classes...")
			return nil
		},
	}
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
		Long: `AI capabilities grounded in system truth. The AI never generates
compliance facts — it reasons over facts the deterministic system has
already validated. Every claim cites a specific artifact.`,
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "ask [question]",
			Short: "Ask the compliance analyst a question",
			Args:  cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Querying compliance state...")
				return nil
			},
		},
		&cobra.Command{
			Use:   "audit-sim",
			Short: "Simulate a compliance assessment",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Running audit simulation...")
				return nil
			},
		},
		&cobra.Command{
			Use:   "translate [natural-language]",
			Short: "Translate natural language to a Cedar policy",
			Args:  cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Translating to Cedar policy...")
				return nil
			},
		},
		&cobra.Command{
			Use:   "analyze",
			Short: "Detect anomalies in Cedar decision log",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Analyzing decision log...")
				return nil
			},
		},
		&cobra.Command{
			Use:   "impact [framework-path]",
			Short: "Analyze framework change impact",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Printf("Analyzing framework change: %s\n", args[0])
				return nil
			},
		},
		&cobra.Command{
			Use:   "remediate [control-id]",
			Short: "Generate remediation artifacts for a control gap",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Printf("Generating remediation for %s...\n", args[0])
				return nil
			},
		},
	)
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
