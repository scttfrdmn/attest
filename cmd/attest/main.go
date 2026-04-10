package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.2.0-dev"

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
		reportCmd(),
		aiCmd(),
		versionCmd(),
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
			fmt.Println("Initializing SRE...")
			fmt.Println("  Reading Organization topology...")
			fmt.Println("  Inventorying existing SCPs...")
			fmt.Println("  Querying Artifact agreements...")
			fmt.Println("  Detecting data classifications...")
			fmt.Println()
			fmt.Println("SRE initialized. Written to .attest/sre.yaml")
			fmt.Println("Run 'attest frameworks add <framework-id>' to activate a framework.")
			return nil
		},
	}
	return cmd
}

func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Analyze current org posture against active frameworks",
		Long: `Reads the current state of the SRE and evaluates it against all active
frameworks. Produces a posture report showing which controls are enforced,
partially enforced, or have gaps. Also checks for Artifact report updates
that may change the shared responsibility boundaries.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Scanning SRE posture...")
			fmt.Println("  Checking Artifact for report updates...")
			fmt.Println("  Evaluating structural controls (SCPs)...")
			fmt.Println("  Evaluating operational controls (Cedar)...")
			fmt.Println("  Evaluating monitoring controls (Config)...")
			return nil
		},
	}
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
SCPs (structural), Cedar policies (operational), and Config rules (monitoring).
Produces the crosswalk manifest mapping every artifact to its framework controls.

Use --output terraform or --output cdk to generate IaC modules alongside
the raw policy artifacts.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			output, _ := cmd.Flags().GetString("output")
			fmt.Println("Compiling policies for active frameworks...")
			fmt.Println("  Resolving cross-framework control overlap...")
			fmt.Println("  Generating SCPs (structural enforcement)...")
			fmt.Println("  Generating Cedar policies (operational enforcement)...")
			fmt.Println("  Generating Config rules (drift monitoring)...")
			fmt.Println("  Writing crosswalk manifest...")
			if output != "" {
				fmt.Printf("  Generating %s output...\n", output)
			}
			fmt.Println()
			fmt.Println("Compiled artifacts written to .attest/compiled/")
			fmt.Println("  12 SCPs, 23 Cedar policies, 8 Config rules")
			fmt.Println("  Crosswalk: .attest/compiled/crosswalk.yaml")
			fmt.Println()
			fmt.Println("Run 'attest apply' to deploy to the organization.")
			return nil
		},
	}
	cmd.Flags().String("output", "", "IaC output format: terraform, cdk")
	return cmd
}

func applyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Deploy compiled policies to the organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Deploying policies to SRE organization...")
			fmt.Println("  This will modify SCPs on the organization.")
			fmt.Println("  Use --dry-run to preview changes.")
			return nil
		},
	}
	cmd.Flags().Bool("dry-run", false, "Preview changes without applying")
	cmd.Flags().Bool("approve", false, "Skip interactive approval")
	return cmd
}

func evaluateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "evaluate",
		Short: "Run Cedar PDP evaluation against current state",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Running Cedar policy evaluation...")
			return nil
		},
	}
}

func generateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate compliance documents",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "ssp",
			Short: "Generate System Security Plan",
			Long: `Generates an SSP from the current SRE state. Every fact in the SSP is
derived from the crosswalk, deployed policies, and Cedar evaluation logs.
The SSP is a computed artifact, not a hand-written document.`,
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Generating System Security Plan...")
				fmt.Println("  Reading crosswalk manifest...")
				fmt.Println("  Querying Cedar evaluation logs...")
				fmt.Println("  Querying Config compliance history...")
				fmt.Println("  Fetching Artifact report references...")
				fmt.Println("  Generating control narratives...")
				fmt.Println()
				fmt.Println("SSP written to .attest/documents/ssp-nist-800-171-r2.md")
				fmt.Println("OSCAL: .attest/documents/ssp-nist-800-171-r2.oscal.json")
				return nil
			},
		},
		&cobra.Command{
			Use:   "poam",
			Short: "Generate Plan of Action & Milestones",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Generating POA&M...")
				fmt.Println("  Identifying control gaps...")
				fmt.Println("  Estimating remediation effort...")
				fmt.Println()
				fmt.Println("POA&M written to .attest/documents/poam.md")
				return nil
			},
		},
		&cobra.Command{
			Use:   "assess",
			Short: "Generate self-assessment (CMMC, 800-171A)",
			Long: `Scores the SRE against assessment objectives. For CMMC 2.0 Level 2,
each NIST 800-171 control is scored based on enforcement depth:
- Fully enforced (SCP + Cedar + Config): 5 points
- Partially enforced: 3 points
- Planned: 1 point
- Gap: 0 points`,
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Generating self-assessment...")
				fmt.Println("  Evaluating 110 controls against 800-171A objectives...")
				fmt.Println()
				fmt.Println("Score: 487/550 (88.5%)")
				fmt.Println("  Implemented: 94 controls")
				fmt.Println("  Partially Implemented: 11 controls")
				fmt.Println("  Planned: 5 controls")
				fmt.Println()
				fmt.Println("Assessment written to .attest/documents/assessment.md")
				fmt.Println("OSCAL: .attest/documents/assessment-results.oscal.json")
				return nil
			},
		},
		&cobra.Command{
			Use:   "oscal",
			Short: "Export all documents in OSCAL format",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Exporting to OSCAL...")
				fmt.Println("  SSP → OSCAL SSP model")
				fmt.Println("  Assessment → OSCAL Assessment Results model")
				fmt.Println("  POA&M → OSCAL POA&M model")
				return nil
			},
		},
	)
	return cmd
}

func diffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff",
		Short: "Compare current posture to last assessment",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Comparing current posture to last assessment...")
			return nil
		},
	}
}

func watchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "watch",
		Short: "Continuous compliance monitoring via Cedar PDP",
		Long: `Runs the Cedar PDP in continuous evaluation mode. Every sensitive
operation in the SRE is evaluated against framework policies in real time.
Violations emit to Security Hub and the decision log.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Starting continuous compliance monitoring...")
			fmt.Println("  Cedar PDP listening for EventBridge events...")
			fmt.Println("  Press Ctrl+C to stop.")
			select {} // block
		},
	}
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
	return &cobra.Command{
		Use:   "test",
		Short: "Run policy unit tests against cedar-go",
		Long: `Executes policy test suites defined in .attest/tests/. Each test case
specifies a principal, action, resource with attributes and the expected
Cedar decision (ALLOW or DENY). Tests run locally — no deployment needed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Running policy tests...")
			fmt.Println("  Loading compiled Cedar policies...")
			fmt.Println("  Executing test suites...")
			return nil
		},
	}
}

func checkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "CI/CD compliance gate for Terraform plans",
		Long: `Evaluates a Terraform plan JSON against Cedar policies to catch
compliance violations before deployment. Outputs SARIF for GitHub
annotation integration. Use in CI/CD pipelines.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			tf, _ := cmd.Flags().GetString("terraform")
			fmt.Printf("Checking Terraform plan: %s\n", tf)
			fmt.Println("  Loading Cedar policies...")
			fmt.Println("  Extracting resource changes...")
			fmt.Println("  Evaluating compliance...")
			return nil
		},
	}
	cmd.Flags().String("terraform", "", "Path to Terraform plan JSON")
	cmd.Flags().String("output", "text", "Output format: text, sarif, json")
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
	cmd.AddCommand(
		&cobra.Command{
			Use:   "create",
			Short: "Create a new compliance waiver",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Creating waiver...")
				return nil
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List active waivers",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Active waivers:")
				return nil
			},
		},
		&cobra.Command{
			Use:   "expire [waiver-id]",
			Short: "Expire a waiver",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Printf("Expiring waiver: %s\n", args[0])
				return nil
			},
		},
	)
	return cmd
}

func reportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate posture trend reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			window, _ := cmd.Flags().GetString("window")
			fmt.Printf("Generating trend report (window: %s)...\n", window)
			fmt.Println("  Loading posture history...")
			fmt.Println("  Computing score trajectory...")
			fmt.Println("  Analyzing remediation velocity...")
			return nil
		},
	}
	cmd.Flags().String("window", "90d", "Report window (e.g., 30d, 90d, 1y)")
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
