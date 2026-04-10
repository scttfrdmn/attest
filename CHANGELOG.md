# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
