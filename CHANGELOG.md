# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/scttfrdmn/attest/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/scttfrdmn/attest/releases/tag/v0.1.0
