# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-04-15

### Added

- `attest frameworks add <id>` now actually writes to `.attest/sre.yaml`. Previously
  a stub — now loads the framework, checks for duplicates, appends, and persists.
- Multi-framework posture: `CrosswalkEntry.FrameworkID` field added to schema.
  `buildCrosswalk()` now produces one entry per control per framework (enables
  per-framework SSP generation). `Crosswalk.Frameworks []string` added alongside
  the legacy `Framework string` field.
- `attest generate ssp --framework <id>` generates an SSP for a specific active
  framework. Without `--framework`, generates one SSP per active framework.
  `filterCrosswalkByFramework()` helper for per-framework crosswalk filtering.
- `attest apply --approve` deployed 26 SCPs to live org `o-pygqyjjoym` (root r-fr7j).
  Discovered and fixed two real-world deployment issues:
  - SCP `Sid` field must be alphanumeric — compiler now generates PascalCase Sids
    (e.g., `scp-require-mfa` → `ScpRequireMfa`) and deduplicates them.
  - AWS default quota: 5 SCPs per target. Attest compiles 26+; quota increase required.
  `Apply()` now continues on individual SCP failures and reports all at end.
- `attest ai ask <question>` — live Bedrock ConverseStream via Claude Haiku 4.5.
  Grounded in compiled crosswalk and SRE state. Verified against real org.
- `attest ai ingest <file>` — Claude Sonnet 4.6 maps document content to framework
  controls with evidence citations. Creates draft attestation records for covered
  controls. Tested against Meridian Research University IS Policy (28 controls found).
- `attest ai onboard --mode greenfield|legacy|checkpoint` — Claude Sonnet 4.6
  produces prioritized action plan. Greenfield mode identifies admin control gaps
  blocking Cedar policy enforcement. Tested live.
- `internal/ai/analyst.go` — Bedrock client, `selectModel()` routing, `Ask()`,
  `IngestDocument()`, `Onboard()` with streaming via `ConverseStreamEventStream`.
  Model IDs: Opus (`us.anthropic.claude-opus-4-6-v1`), Sonnet
  (`us.anthropic.claude-sonnet-4-6`), Haiku (`us.anthropic.claude-haiku-4-5-20251001-v1:0`).
- `docs/quickstart.md` — getting-started guide with prerequisites, step-by-step
  pipeline, and quota notes.
- `frameworks/CONTRIBUTING.md` — framework authoring guide with full schema reference,
  condition string syntax table, and testing workflow.
- SCP compiler: `sanitizeSid()` converts hyphenated IDs to PascalCase alphanumeric
  (AWS SCP requirement). `mergeSpecs()` deduplicates Sids with index suffix.
- Deploy: `ApplyResult` type; `Apply()` returns `(*ApplyResult, error)` — continues
  on individual failures, reports all at end.

### Fixed

- `attest generate ssp` / `poam` / `assess` / `oscal` now use `loadGenerateContext()`
  shared helper instead of duplicating SRE + crosswalk loading.
- SCP compiler test `TestApplyError` updated for new `Apply()` signature.

### Issues filed

- #64 `attest preflight` — check AWS prerequisites and quotas before apply
- #65 SCP merging — compile to ≤5 composite SCPs to fit default quota
- #66 Step-by-step tutorials tied to Meridian Research University demo scenarios

## [0.5.0] - 2026-04-15

### Added

- `attest apply [--dry-run] [--approve]` — deploys compiled SCPs to the AWS Organization.
  Creates new SCPs, updates changed ones, attaches all to org root. Dry-run mode
  shows the full deployment plan without making changes. Against o-pygqyjjoym, correctly
  plans 26 SCPs to create and attach to root `r-fr7j`.
- `attest evaluate --principal --action --resource [--attr]` — one-shot Cedar PDP
  evaluation against compiled policies. Parses `entity.attribute=value` flags into
  Cedar entities, runs `ps.IsAuthorized()`, returns ALLOW/DENY with policy ID.
- `attest diff [ref1] [ref2]` — compares two posture history snapshots. Shows improved,
  regressed, and unchanged controls with score delta.
- `attest attest create|list|expire` — administrative control attestation management.
  Records who affirmed a control, when, what evidence, and expiry. Stored as YAML in
  `.attest/attestations/`. Same pattern as waivers.
- `attest calendar [--window 90d]` — lists controls with review schedules and their
  upcoming due dates. Flags unattestedcontrols and overdue reviews.
- `attest report [--window 90d]` — trend analysis from posture history snapshots.
- `attest watch` — Cedar PDP polling mode (EventBridge integration deferred to v1.0.0).
- `attest compile --output terraform` — generates Terraform HCL for all compiled SCPs
  with `aws_organizations_policy` + `aws_organizations_policy_attachment` resources.
- `internal/deploy/deployer.go` — SCP deployer: Plan (dry-run diff), Apply
  (create/update/attach), content-normalizing JSON comparison.
- `internal/evaluator/evaluator.go` — Cedar PDP evaluation via cedar-go: builds entities
  from attribute map, calls `ps.IsAuthorized()`, returns `schema.CedarDecision`.
- `internal/attestation/manager.go` — attestation CRUD: Create (validated), List,
  ListExpiring, IsAttested, Expire.
- `internal/iac/output.go` — Terraform HCL generation from compiled SCPs.
- `internal/reporting/reporting.go` — posture trend analysis from `.attest/history/`.
- `frameworks/ferpa/framework.yaml` — FERPA (20 U.S.C. § 1232g) framework: 13 controls
  across Student Rights, Amendment Rights, Disclosure Controls, and Enforcement families.
  Cedar policies for student record access and disclosure controls.
- `classification-schemes/uc-protection-levels.yaml` — UC P-level system (IS-3):
  P1–P4 mapped to attest data classes and frameworks. P4 → PHI/CUI, P3 → FERPA.
- `classification-schemes/fisma-impact-levels.yaml` — FISMA Low/Moderate/High mapped
  to NIST 800-171 (Moderate) and NIST 800-53 (High).
- `attest init --classification-scheme` — translates institutional classification tags
  to attest data classes and activates appropriate frameworks.
- Schema additions: `Attestation`, `ReviewSchedule`, `AdminDependency`,
  `ClassificationScheme`, `ClassificationMapping` types.
- `AdminDependencies` field on `OperationalEnforcement` — links Cedar policies to the
  administrative controls their correctness depends on.
- `ReviewSchedule` field on `Control` — specifies review frequency for administrative
  controls; feeds `attest calendar`.
- `review_schedule` added to 8 key NIST 800-171 controls (3.2.1, 3.2.2, 3.2.3, 3.6.3,
  3.9.1, 3.11.1, 3.12.1, 3.12.4).
- `admin_dependencies` added to `cedar-cui-data-movement` (3.1.3) — depends on 3.2.2
  training attestation.
- Demo scenario: Meridian Research University (greenfield + legacy walkthroughs).
- Tests: 10 deploy, 7 attestation — 89 total, all passing.

## [0.4.0] - 2026-04-15

### Added

- `attest generate ssp` — generates a human-readable System Security Plan
  in markdown from the compiled crosswalk. Every statement is derived from
  deployed artifacts; nothing is hand-written. Includes CMMC scoring and
  control narratives with evidence references.
- `attest generate poam` — generates a Plan of Action & Milestones listing
  all gap/partial controls with milestone IDs, scheduled completion dates,
  and remediation guidance.
- `attest generate assess` — CMMC 2.0 Level 2 self-assessment scoring
  (enforced=5pts, partial=3pts, planned=1pt, gap=0pts, max 550). Includes
  per-family breakdown and assessment readiness determination.
- `attest generate oscal` — exports SSP and Assessment Results in NIST
  OSCAL 1.1.2 JSON format for GRC tool interoperability.
- `attest waiver create|list|expire` — compliance exception management.
  Waivers are YAML files in `.attest/waivers/`, validated against required
  fields, and returned with computed status (active/expiring/expired).
- `attest test` — runs policy unit test suites from `.attest/tests/*.yaml`
  against compiled Cedar policies via cedar-go. No AWS access required.
- `attest check --terraform plan.json` — evaluates a Terraform plan for
  compliance violations; `--output sarif` for GitHub annotation integration.
- HIPAA Security Rule framework (`frameworks/hipaa/framework.yaml`) — 23
  controls across 5 families. Activated via BAA agreement detection.
  Shared SCPs (scp-require-mfa, scp-require-kms-encryption, etc.) are
  deduplicated automatically against NIST 800-171 via the crosswalk.
- Git-backed policy store (`internal/store/git.go`) — `.attest/` initialized
  as a git repository on first use. Commit, Tag, and Diff methods for
  policy-as-code lifecycle management.
- `internal/document/ssp/renderer.go` — markdown renderer for the SSP.
- `internal/document/poam/` — new package for POA&M generation.
- `internal/document/assessment/` — new package for self-assessment scoring.
- `internal/document/oscal/exporter.go` — OSCAL SSP and Assessment Results
  exporters implemented (previously stubbed).
- Tests: renderer (2), POA&M generator (4), assessment generator (4),
  waiver manager (5) — 15 new tests, 72 total.

## [0.3.0] - 2026-04-15

### Added

- NIST SP 800-171 Rev 2 framework definition — all 110 controls across all
  14 families. 6 controls retain full structural/operational/monitoring specs;
  remaining 104 are community-maintained skeletons with title, responsibility
  split, and assessment objectives.
- SCP condition parsing: framework YAML condition strings (`key != true`,
  `key not in [v1, v2]`, ARN patterns, `contains`, etc.) now compile into
  correct IAM Condition blocks (Bool, StringEquals, StringNotEquals, ArnLike,
  ArnNotLike, StringLike, StringNotLike operators).
- SCP size limit validation: policies exceeding the 5120-byte AWS limit are
  automatically split into multiple SCPs, each individually valid.
- Cedar schema generation: `Compiler.BuildSchema()` emits a `.cedarschema`
  file defining all entity types and their attributes, inferred from the
  framework's operational enforcement specs.
- Cedar temporal constraints: `generateFromSpec` respects `TemporalConstraint`
  — expiry constraints add `principal.training_expiry` checks, event constraints
  add `principal.irb_active`, schedule constraints add `context.hour` bounds.
- `attest compile` now calls real SCP and Cedar compilers, writes artifacts to
  `.attest/compiled/scps/`, `.attest/compiled/cedar/` (including schema), and
  `.attest/compiled/crosswalk.yaml`. Running against NIST 800-171 produces
  26 SCPs and 7 Cedar policies.
- `attest scan` now reads the compiled crosswalk for accurate posture. With
  `--region`, it compares compiled SCP IDs against deployed SCPs for live
  deployment status.
- Principal attribute resolver SAML source: reads `attest:*` IAM role tags
  (cui-training, cui-expiry, lab-id, admin-level) to hydrate Cedar principal
  entities. LDAP source interface defined; implementation deferred to community.
- `.goreleaser.yaml` for cross-platform binary releases (linux/darwin/windows,
  amd64/arm64) with framework definitions included in archives.
- SCP compiler tests: `TestParseCondition` (13 cases), `TestConditionInCompiledSCP`,
  `TestSCPSizeLimit`, `TestCompileNIST800171`.
- Cedar compiler tests: `TestCompile`, `TestCompileWithHandwrittenCedarPolicy`,
  `TestTemporalConstraints` (3 types), `TestBuildSchema`,
  `TestInferCedarType` (9 cases), `TestBuildSchemaWithTemporalContext`,
  `TestCompileFullFramework`.

## [0.2.0] - 2026-04-15

### Added

- `attest init` now reads a live AWS Organization via the Organizations API:
  builds SRE model, inventories existing SCPs, detects Artifact agreements,
  resolves data classifications from account tags, and writes `.attest/sre.yaml`.
- `attest scan` loads `.attest/sre.yaml` and active frameworks, resolves
  cross-framework controls, computes structural posture (SCP coverage), and
  saves a posture snapshot to `.attest/history/`.
- `internal/artifact/client.go` — full implementation of the Artifact API:
  `ListReports` (paginated), `GetReportMetadata`, `DownloadReport` (via
  GetTermForReport + GetReport presigned URL), `ListAgreements`
  (ListCustomerAgreements), `DetectFrameworkActivations`, `DetectReportChanges`.
- `internal/org/analyzer.go` — full implementation of the Organizations analyzer:
  `BuildOrgTree` (recursive OU walk), `BuildSRE`, `InventoryExistingSCPs`,
  `InventoryConfigRules` (management account; cross-account deferred to v0.3.0).
  Account tags `attest:data-class`, `attest:owner`, `attest:purpose` drive the
  environment model.
- `internal/artifact/client_test.go` — 16 table-driven tests with mock SDK.
- `internal/org/analyzer_test.go` — 13 table-driven tests with mock SDK.
- `internal/framework/loader_test.go` — 8 tests including live NIST 800-171 load.
- `.github/workflows/ci.yml` — CI pipeline: go vet, go test, go build on push/PR.
- AWS SDK v2 dependencies: `service/artifact`, `service/organizations`,
  `service/configservice`, `config`.
- Isolation VPC `vpc-096e8f408e16a2c22` (10.99.0.0/16) tagged `attest-dev`
  in us-west-2 for future test resources.

### Added (previous unreleased items)

- Makefile with build, test, vet, and security scanning targets.
- GitHub Actions security workflow: govulncheck, Trivy (filesystem + IaC),
  Semgrep SAST. Runs on push, PR, and weekly cron.
- Expanded v1 architecture with 13 new packages:
  - `internal/evaluator/` — continuous Cedar PDP runtime (EventBridge-driven).
  - `internal/integrations/` — 12 AWS security service integrations
    (Security Hub, Config, GuardDuty, CloudTrail, IAM Access Analyzer,
    Macie, Inspector, Firewall Manager, KMS, SSM, EventBridge, Organizations).
  - `internal/dashboard/` — web dashboard server (Go net/http + HTMX + SSE).
  - `internal/ai/` — 7 Bedrock+Claude capabilities: Artifact comprehension,
    natural language → Cedar, anomaly detection, compliance analyst agent,
    framework change impact, audit simulation, remediation synthesis.
  - `internal/principal/` — entity attribute resolver (SAML, LDAP, LMS, IRB)
    with plugin interface for institutional systems.
  - `internal/waiver/` — compliance exception management (time-bounded,
    scoped, auditable, Cedar-aware).
  - `internal/testing/` — policy unit tests, CloudTrail simulation,
    Terraform CI/CD compliance checks (SARIF output).
  - `internal/provision/` — automated environment provisioning with
    prerequisite checking.
  - `internal/store/` — git-backed policy store (.attest/ layout).
  - `internal/iac/` — IaC output (Terraform modules, CDK constructs).
  - `internal/reporting/` — trend analysis and incident lifecycle reports.
  - `internal/auth/` — Bouncing authn + Cedar authz for dashboard.
  - `internal/document/oscal/` — OSCAL export (SSP, Assessment Results, POA&M).
- New CLI commands: serve, test, check, simulate, provision, waiver
  (create/list/expire), report, ai (ask/audit-sim/translate/analyze/
  impact/remediate).
- `--output terraform|cdk` flag on `attest compile` for IaC generation.
- Extended schema types: Waiver, Incident, PrincipalAttributes,
  CedarDecision, PolicyTestSuite, IaCManifest, PostureSnapshot.
- React dashboard prototype (`web/dashboard/App.jsx`) with 9 views:
  Posture, Frameworks, Operations, Environments, Waivers, Incidents,
  Tests & Deploy, Generate, AI Analyst.

## [0.1.0] - 2026-04-09

### Added

- Project scaffold with CLI entry point and cobra command structure.
- Core data model (`pkg/schema`): SRE, Environment, Framework, Control,
  Crosswalk, Posture, and all enforcement/assessment types.
- CLI commands: init, scan, frameworks (list/add), compile, apply, evaluate,
  generate (ssp/poam/assess/oscal), diff, watch, version.
- AWS Artifact API client stub (`internal/artifact`): report listing, agreement
  detection, framework activation mapping, report change detection.
- AWS Organizations analyzer stub (`internal/org`): org topology, SCP inventory,
  Config rule inventory, data class resolution.
- Framework loader (`internal/framework`): YAML parsing, validation,
  cross-framework control resolution and deduplication.
- SCP compiler (`internal/compiler/scp`): generates IAM policy JSON from
  structural enforcement specs, merges cross-framework overlaps.
- Cedar policy compiler (`internal/compiler/cedar`): generates Cedar policy text
  from operational enforcement specs, builds entity schemas.
- SSP generator (`internal/document/ssp`): produces System Security Plans from
  crosswalk and Cedar evaluation data, with CMMC scoring.
- NIST SP 800-171 Rev 2 framework definition (partial: 6 controls across
  Access Control and System and Communications Protection families).
- CLAUDE.md project rules and conventions.

[Unreleased]: https://github.com/provabl/attest/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/provabl/attest/releases/tag/v0.1.0
