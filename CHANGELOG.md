# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-04-17

### Added

- `attest provision [--name] [--email] [--owner] [--data-class] [--approve]` —
  full environment provisioning: computes target OU from data class (CUI→research-controlled,
  PHI→research-hipaa, FERPA→research-education), checks prerequisites, creates AWS account
  via Organizations API (async polling), moves to target OU, applies `attest:*` tags, and
  registers environment in `.attest/sre.yaml`. Uses existing `organizations` SDK dep (#38).
- `frameworks/fedramp-moderate/framework.yaml` — FedRAMP Moderate baseline: 23 controls
  across AC, AU, CM, IA, SC, SI families. All SCP conditions overlap with NIST 800-171 R2
  and HIPAA — adding FedRAMP to an org with NIST+HIPAA costs ~0 additional SCP chars
  (conditions already deduplicated by the intelligent compiler) (#55).
- `internal/principal/resolver.go` — `LDAPSource.Resolve()` implemented using
  `go-ldap/ldap/v3`. Maps `memberOf` groups (`lab-*`, `research-*` → LabMembership,
  `admin-*` → AdminLevel). `NewLDAPSource(url, baseDN)` constructor. Falls back
  gracefully if LDAP is unavailable.
- `attest evaluate [--ldap-url] [--ldap-base-dn] [--region]` — optional LDAP principal
  attribute resolution wired into one-shot Cedar evaluation.
- `attest serve [--oidc-issuer] [--oidc-client-id] [--oidc-client-secret]` — OIDC/OAuth2
  authentication for the dashboard via `internal/auth/OIDCHandler`. Supports Shibboleth,
  Okta, Azure AD, and any OIDC-compliant IdP. Routes: `GET /login`, `GET /callback`,
  `GET /logout`. Session cookies (8h TTL). Roles mapped from OIDC claims. Static token
  auth (`--auth`) unchanged for local/CI use (#42).
- `dashboard.NewServerWithOIDC()` — dashboard constructor that wraps all routes with
  OIDC middleware.
- `frameworks list` now shows `iso27001-2022` and `fedramp-moderate`.

### Changed

- `internal/auth/auth.go` — full OIDC implementation replacing the `TODO` stub.
  `Middleware()` stub replaced by `OIDCHandler.Middleware()`. `StaticTokenMiddleware()`
  extracted for local/CI use. `UserFromContext()` / `WithUser()` unchanged.
- Dependencies added: `go-ldap/ldap/v3`, `coreos/go-oidc/v3`, `golang.org/x/oauth2`.
- Version bumped to 0.9.0.

## [0.8.1] - 2026-04-17

### Security

- **CRITICAL fixed**: `store.Checkout()` and `store.Tag()` now validate the ref/tag
  name against a safe character allowlist (`[a-zA-Z0-9._/-]+`, no `..`). Prevents
  path traversal and git ref injection via the `attest rollback --to` flag.
- **HIGH fixed**: `aiRemediateCmd` sanitizes `controlID` (strips non-alphanumeric
  characters, uses `filepath.Abs` comparison to prevent path traversal in `--out`
  directory writes).
- **HIGH fixed**: `handleOperationsSSE` enforces a `maxSSEConnections=50` limit via
  atomic counter, preventing goroutine/file-descriptor exhaustion from connection floods.
- **HIGH fixed**: CloudTrail event fields (`EventName`, `Username`, `ResourceName`,
  extracted ARN) are now sanitized by `sanitizeEventField()` before use in Cedar
  evaluation or log writes. Prevents log injection and Cedar evaluation manipulation.
- **HIGH fixed**: `attest serve` binds to `127.0.0.1:8080` by default (localhost only).
  Prints prominent warnings when running without auth. Minimum token length enforced
  (16 chars) when `--auth` is used.
- **MEDIUM fixed**: All `.attest/` files now written with `0640` (was `0644`).
  Applies to: `cmd/attest`, `internal/waiver`, `internal/iac`, `internal/attestation`.
- **MEDIUM fixed**: Removed unused HTMX CDN script tag from dashboard HTML.
  Frontend uses vanilla JS only — no external CDN supply chain dependency.
- **MEDIUM fixed**: Framework YAML `validate()` now enforces size limits: ID ≤128 chars,
  title ≤512 chars, controls ≤10,000 per framework, control ID ≤64 chars.
- **MEDIUM fixed**: `http.Server` now sets `ReadHeaderTimeout` and `MaxHeaderBytes`
  to prevent slowloris and header-size attacks on the dashboard.
- **INFO fixed**: `handleGenerate` flusher type assertion is now checked; returns 500
  if SSE is not supported instead of silently failing.

### Added

- `internal/store/store_test.go` — 3 tests for `validateRef()`, `Tag()`, `Checkout()`
  covering CRITICAL security fix: injection via path traversal, shell metacharacters,
  empty refs, and oversized refs.
- `internal/evaluator/cloudtrail_test.go` — 10 tests for `sanitizeEventField()` and
  `translateEvent()` covering HIGH security fix: log injection, newlines, semicolons,
  pipes, backticks, long inputs, and nil EventName.
- `internal/framework/loader_test.go` — 8 boundary tests for the new MEDIUM security
  fix: framework ID, control ID, and control title length limits; control count limit.
- `internal/dashboard/server_test.go` — 7 tests for auth middleware (5 cases), SSE
  connection limit enforcement (concurrent safety), and API Content-Type headers.
- `docs/operations/rollback.md` — updated to reflect v0.8.0 delivery (auto-snapshot,
  `attest rollback` command); added "Snapshot naming rules" section documenting the
  v0.8.1 ref validation (allowed chars, `..` prohibition, 255-char limit, error message).

## [0.8.0] - 2026-04-17

### Added

- `attest apply` auto-tag: creates a `applied-YYYYMMDD-HHMMSS` git tag in the
  `.attest/` store before every deployment — pre-deploy snapshot for rollback (#69).
- `attest rollback [--list] [--to <tag>] [--approve]` — undo the last apply or
  restore to any named snapshot: detaches all attest-managed SCPs, checks out compiled
  artifacts from the target tag, and re-applies. Uses `store.ListTags()` and new
  `store.Checkout()` (#70).
- `deployer.DetachAll()` — detaches all `attest-*` SCPs from org root while leaving
  non-attest policies (e.g., FullAWSAccess) untouched.
- `attest watch [--region] [--interval]` — continuous Cedar PDP evaluation via
  CloudTrail polling. Polls CloudTrail management events every N seconds (default 30s),
  evaluates each against compiled Cedar policies, streams DENY decisions to terminal,
  writes all decisions to `.attest/history/cedar-decisions.jsonl`. EventBridge
  integration remains v1.0.0 (#32).
- `attest incident create/list/resolve` — lightweight incident lifecycle management
  stored in `.attest/history/incidents.yaml`. Mirrors `attest waiver` pattern (#41).
- `attest serve [--addr] [--auth]` — real web dashboard on Go `net/http` + HTMX + SSE.
  Posture ring, frameworks, live Cedar PDP feed (SSE), waivers, incidents, and
  document generation. Static bearer token auth via `ATTEST_DASHBOARD_TOKEN` (#39, #42).
- Security service integrations (`internal/integrations`): `CollectForControl()` and
  `CollectAll()` implemented with GuardDuty (active findings via threat→control mapping),
  IAM Access Analyzer (active overly-permissive-policy findings), and Organizations
  (deployed SCPs). All free-tier. AWS SDK deps: `guardduty`, `accessanalyzer` (#33).
- `store.ListTags()` and `store.Checkout()` methods for rollback support.
- `internal/reporting/incidents.go` — `Incident` type and `IncidentManager` CRUD.
- `internal/evaluator/cloudtrail.go` — CloudTrail event → `AuthzRequest` translation.
- `evaluator.DecisionEvent` type and `Subscribe()` channel for dashboard SSE feed.
- `docs/tutorials/greenfield.md` — step-by-step: blank org to CMMC Assessment Ready,
  including quota handling, rollback, and dashboard walkthrough (#66).
- `docs/tutorials/legacy.md` — step-by-step: existing docs to audit-ready SSP in
  30 minutes using `attest ai ingest` (#66).
- `docs/operations/rollback.md` — documents current rollback approach: manual
  checkpoint creation via `git -C .attest tag`, step-by-step SCP detach/delete
  via AWS CLI, re-applying a previous compiled state from a checkpoint, Terraform
  destroy path.

### Changed

- `docs/quickstart.md` — corrects SCP quota section (5-per-target is a hard limit,
  not a default; solution is `--scp-strategy merged`). Adds pre-apply checkpoint
  reminder, rollback caveat in Step 5, merged-strategy compile example with budget
  output, and link to `docs/operations/rollback.md`.
- Bumped version to `0.8.0-dev` → `0.8.0`.
- `attest simulate` now performs a real CloudTrail replay: polls the last N hours of
  events, evaluates each against both current and proposed Cedar policies, and reports
  ALLOW→DENY and DENY→ALLOW changes. Previously printed placeholder output.
- `attest provision` returns a clear actionable error with manual steps instead of
  printing fake progress output. Planned for v0.9.0 (#38).
- `auth.UserFromContext()` implemented via context value store (`WithUser()`/`UserFromContext()`).
- AI capabilities fully wired to Bedrock (5 previously stubbed commands):
  `attest ai audit-sim` (Opus 4.6 CMMC assessor simulation),
  `attest ai translate` (NL → Cedar policy, Opus 4.6),
  `attest ai analyze` (Cedar log anomaly detection, Sonnet 4.6),
  `attest ai impact` (framework change impact, Opus 4.6),
  `attest ai remediate` (remediation artifact generation, Sonnet 4.6).

## [0.7.0] - 2026-04-15

### Added

- `attest compile --scp-strategy merged` — intelligent SCP compilation:
  deduplicates structural enforcement specs by condition fingerprint across
  all active frameworks, unions action lists for specs sharing conditions, and
  bin-packs statements into ≤4 SCP documents using compact JSON (no whitespace,
  no Sids). NIST 800-171 R2 + HIPAA + ISO 27001 → 1 SCP, 2,780 chars, 13.6%
  of the 20,480-char budget. Adding ISO 27001 to an org with NIST+HIPAA cost
  zero additional chars — all conditions already deduplicated.
  Filters specs with non-`aws:` condition keys (not supported by AWS Organizations).
  Reports: "N specs → M unique conditions → K SCP documents, X% of budget used."
- `attest preflight [--region]` — validates prerequisites before `attest apply`:
  organization feature set (ALL), SCP policy type on root, SCP quota check
  (current attached vs. compiled count), IAM access. Shows solution when quota
  would be exceeded: "run 'attest compile --scp-strategy merged'."
- `attest apply` quota warning: `DeployPlan.QuotaWarning` field; when compiled
  SCP count would exceed the 5-per-target limit, a warning is printed before
  prompting for approval.
- `attest scan --verify [--region]` — direct AWS API spot-checks with $0 ongoing
  cost (no Config required): CloudTrail multi-region trail status,
  attest SCPs deployed to org, IAM password policy active.
- ISO 27001:2022 framework (`frameworks/iso27001-2022/framework.yaml`) — 30
  controls across Organizational (A.5), People (A.6), Physical (A.7), and
  Technological (A.8) themes. Validates SCP deduplication: A.5.15 shares
  scp-require-mfa with NIST 800-171 §3.1.1; A.8.24 shares encryption
  conditions with §3.13.11; A.8.20 shares TLS enforcement.
- `CompileStats` type in `internal/compiler/scp` with `InputSpecs`,
  `UniqueConditions`, `TotalChars`, `BudgetUsed`, `SCPCount` fields.
- `TotalBudget` exported constant (20,480 chars = 4 SCPs × 5,120 chars).
- `DeployPlan.CurrentCount` — number of SCPs currently attached to target.
- `deployer.countAttachedSCPs()` — queries total SCP count at a target.
- CloudTrail SDK dependency (`github.com/aws/aws-sdk-go-v2/service/cloudtrail`).

### Notes

- SCP per-target limit is a **hard limit of 5** (AWS Organizations). Not
  adjustable. `--scp-strategy merged` is the solution — produces ≤4 composite
  SCPs fitting within the limit alongside the FullAWSAccess default policy.
- The zero-cost architecture is now documented: attest scan uses direct API
  calls (free), SCPs are free, Cedar runs as Lambda (~$0). No Config or
  Security Hub required for compliance monitoring.

### In provabl/ark (companion release)

- `NewServiceWithIAM()` — training service with IAM client for attest tagging
- `writeAttestTags()` — writes `attest:*` tags to researcher IAM roles on
  training completion (cui-fundamentals → attest:cui-training=true, etc.)
- `moduleTagMap` — maps Ark module IDs to attest:* tag keys
- `extractRoleName()` — parses role name from IAM role ARN

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
