# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.2] - 2026-04-23

### Security

Second-pass board-wide audit — 4 findings.

- **HIGH fixed**: Prompt injection in `ai.IngestDocument()` — raw document content
  embedded directly in Bedrock user message; a crafted document could inject
  model instructions. Fixed by wrapping content in `<document_content>` XML
  delimiters and adding explicit anti-injection instruction to the system prompt.
- **HIGH fixed**: Path traversal in `--classification-scheme` CLI flag —
  `applyClassificationScheme()` used the flag value directly in `filepath.Join`
  without a confinement check; `../../../etc/passwd` would read arbitrary files.
  Added `filepath.Abs` confinement identical to `framework/loader.go`.
- **MEDIUM fixed**: Symlink TOCTOU in CMMC bundle — `generateAttestationsIndex()`
  and `generateWaiversRegister()` checked `e.Info()` for symlinks from `os.ReadDir`
  then called `os.ReadFile` separately, leaving a race window. Replaced with
  `os.Lstat()` immediately before each `os.ReadFile` call.
- **MEDIUM fixed**: Check-then-act race in `multisre.Add()` — `Load→check→Save`
  executed without a lock; concurrent calls could both pass the duplicate-ID check.
  Added `sync.Mutex` to `Manager`; `Add()` and `Remove()` hold the lock for their
  full critical section.

## [0.12.1] - 2026-04-23

### Security

Board-wide audit — 14 findings across all packages fixed.

- **CRITICAL fixed**: Framework loader path traversal — `Load(id)` used the
  caller-supplied `id` directly in `filepath.Join` before path confinement check;
  `validate()` only checked `fw.ID` from the YAML file, not the input param.
  Added `filepath.Abs` confinement to reject IDs that escape `frameworkDir`.
- **CRITICAL fixed**: Cedar policy code injection — `spec.Description` embedded
  raw in a `//` comment; a newline would close the comment and inject Cedar policy
  statements. New `sanitizeCedarComment()` strips `\n`/`\r` before embedding.
- **CRITICAL fixed**: Cedar entity/attribute name injection — entity and attribute
  names from framework YAML embedded directly in generated Cedar policy text.
  New `isValidCedarIdentifier()` rejects names containing non-identifier characters.
- **HIGH fixed**: Waiver ID path traversal — `w.ID` used as a filename stem without
  validation; IDs derived from `--control` CLI flag which could contain `/` or `..`.
  Added `safeIDRE` (`[a-zA-Z0-9_-]+`) validation in `Create()` and `Expire()`.
- **HIGH fixed**: Attestation ID path traversal — same issue and fix as waiver.
- **HIGH fixed**: Git ref injection in `store.Diff()` — `Tag()` and `Checkout()`
  validated refs via `validateRef()` but `Diff(from, to)` did not; added validation.
- **HIGH fixed**: Template parse error exposed to HTTP clients in dashboard
  `handleIndex` — `err.Error()` returned verbatim; now logs server-side and returns
  generic "Internal Server Error".
- **HIGH fixed**: Bearer token timing attack in dashboard `authMiddleware` — string
  equality replaced with `subtle.ConstantTimeCompare()`.
- **HIGH fixed**: YAML parse error details returned to authenticated dashboard clients
  (`handlePosture`, `handleWaivers`, `handleIncidents`) — now return generic messages.
- **HIGH fixed**: `fetchPresigned()` in artifact client had no response size limit;
  `io.ReadAll` replaced with `io.LimitReader` capped at 100 MB.
- **MEDIUM fixed**: Principal resolver silently discarded source errors
  (`_ = fmt.Sprintf(...)`) — now logs to stderr for operational visibility.
- **MEDIUM fixed**: `evaluator/sqs.go` used string concatenation for history log
  path — replaced with `filepath.Join()`.
- **MEDIUM fixed**: `GenerateTrend()` loaded all history snapshots without a count
  limit; added 1 000-snapshot cap to prevent memory exhaustion.
- **LOW fixed**: `strings.Title` (deprecated) in SSP renderer replaced with
  inline `titleCase()` helper.

## [0.12.0] - 2026-04-20

### Added

- `attest evaluate --output <file>` — appends the Cedar decision as a JSONL
  record to the specified file, enabling decision log collection across runs
  (closes #22 remaining acceptance criterion)
- 9 unit tests for the Cedar evaluator (`internal/evaluator/evaluator_test.go`):
  allow, deny, forbid-overrides-permit, attribute-gated evaluation, concurrent
  stats counting, and `buildAttributes` edge cases
- `golangci/golangci-lint-action@v6` step in CI workflow (closes #28)

### Fixed

- Go stdlib CVEs resolved by bumping to `go1.25.9`:
  - GO-2026-4947, GO-2026-4946: `crypto/x509` inefficient policy validation
  - GO-2026-4870: `crypto/tls` TLS 1.3 KeyUpdate DoS
  - GO-2026-4865: `html/template` XSS (JsBraceDepth context tracking)
  - GO-2026-4603: `html/template` URL escaping in meta content attribute
  - GO-2026-4602: `os` FileInfo escape from Root
  - GO-2026-4601: `net/url` parsing vulnerability
- Release pipeline: pin `cosign-installer@v3.9.1` (floating `@v3` tag broken
  on current ubuntu-24.04 runners); remove deprecated `COSIGN_EXPERIMENTAL`

## [0.11.3] - 2026-04-18

### Security

This release fixes findings from the first **board-wide** (full codebase) security audit
— not limited to new code — covering packages that had not been reviewed in previous cycles.

- **CRITICAL fixed**: Prompt injection via framework control titles — `loadFrameworkContext()`
  embedded raw YAML `ctrl.Title` values in Bedrock system prompts. A malicious framework YAML
  with a title containing `\n` could inject arbitrary instructions. New `sanitizePromptField()`
  strips newlines, control characters, and truncates to 512 chars before embedding any
  user-controlled value (framework IDs, control titles, SRE name, OrgID) in prompts.
- **CRITICAL fixed**: Prompt injection via SRE metadata — `buildSystemPrompt()` embedded
  `sre.OrgID` and `sre.Name` from `.attest/sre.yaml` without sanitization. Applied
  `sanitizePromptField()` to all embedded values.
- **HIGH fixed**: OOM via unbounded file reads in `AnalyzeImpact()` and `IngestDocument()` —
  both now check file size via `os.Stat()` before `os.ReadFile()`; reject files larger than
  `maxDocumentSize` (10 MB) with a clear error message.
- **MEDIUM fixed**: LDAP group names validated by `isValidGroupName()` before being stored
  in `PrincipalAttributes.LabMembership` — rejects names containing newlines, quotes, ANSI
  escape sequences, or other special characters that could propagate into Cedar evaluation
  or log output.

## [0.11.2] - 2026-04-18

### Security

- **CRITICAL fixed**: SQS message/handle mismatch — `Poll()` now returns `[]messageRecord`
  (pairing each message's `[]*AuthzRequest` with its receipt handle) instead of separate
  parallel slices. The old design deleted the wrong SQS message when `translateSQSMessage`
  returned 0 requests for a non-CloudTrail message, causing infinite redelivery of some
  messages and silent deletion of others. `StartWithSQS` updated to iterate records.
- **CRITICAL fixed**: SQS queue URL subdomain confusion — `newSQSPoller()` now uses
  `net/url.Parse()` and `strings.Count(host, ".")` to verify the hostname is exactly
  `sqs.<region>.amazonaws.com`. The previous `HasPrefix` + `Contains` check allowed
  `https://sqs.us-east-1.amazonaws.com.evil.com/...` to pass validation.
- **HIGH fixed**: SQS queue IAM policy constructed with `json.Marshal()` instead of
  `fmt.Sprintf()` — prevents JSON injection if ARNs ever contain `"` or `\`.
- **HIGH fixed**: OSCAL payload no longer printed in dry-run mode — compliance documents
  contain sensitive control implementation details; removed truncated payload print.
- **HIGH fixed**: Cost Explorer service names sanitized via `sanitizeServiceName()` —
  strips ANSI escape sequences and control characters before display.
- **MEDIUM fixed**: `ParseFloat` errors and non-finite values (NaN/Inf/negative) are now
  skipped in cost aggregation instead of silently producing `0` or invalid totals.

## [0.11.1] - 2026-04-18

### Security

- **CRITICAL fixed**: SSRF in `attest integrate grc push --endpoint` — endpoint URL now
  validated by `validateEndpoint()`: must use http(s), must not target localhost/loopback,
  must not target private/link-local IP ranges (prevents targeting AWS metadata endpoint
  169.254.169.254, internal Redis, etc.). `newClientDirect()` constructor added for test
  use with localhost servers.
- **CRITICAL fixed**: Path traversal in `attest sre report --output` — output path
  validated (must be relative, must not start with `..`), matching the pattern used by
  `attest generate cmmc-bundle --output`.
- **HIGH fixed**: UTF-8 truncation in `truncate()` — now uses `[]rune` slicing instead of
  byte slicing; prevents invalid UTF-8 output when payload contains multi-byte characters.
- **HIGH fixed**: Missing SQS queue URL validation in `newSQSPoller()` — queue URL from
  `.attest/evaluator.yaml` now validated to match `https://sqs.*.amazonaws.com/` format,
  preventing SSRF via hand-edited config file.
- **HIGH fixed**: Filesystem path disclosure in assessor portal — `store_dir` field
  removed from `GET /api/assessor/me` response; was exposing internal filesystem paths
  to external C3PAO assessors.
- **HIGH fixed**: Platform string validation in `integrateGRCPushCmd()` — `--platform`
  flag now validated against explicit allowlist via `ValidatePlatform()` before being
  cast to `grc.Platform` type.
- **MEDIUM fixed**: Assessor portal now requires `--auth` — `--assessor-mode` without
  `--auth` returns an error instead of printing a warning; C3PAO assessors must authenticate.
- **MEDIUM fixed**: Timezone-safe assessor session expiry — expiry parsed with
  `time.ParseInLocation(..., time.UTC)` and comparison uses `time.Now().UTC()`; prevents
  timezone-dependent access control issues.
- **MEDIUM fixed**: XSS in assessor org JSON response — `s.assessorOrg` now HTML-escaped
  via `sanitizeForJSON()` before inclusion in `/api/assessor/me` response.
- **LOW fixed**: `maxRetries` bounded to `maxRetryLimit` (10) in `PushWithRetry()`.

### Added

- `grc.ValidatePlatform()` — exported function validating platform strings against allowlist
- `grc.ValidPlatforms` — exported map of valid platform identifiers
- `grc.newClientDirect()` — package-internal constructor for tests (bypasses SSRF validation)
- `dashboard.sanitizeForJSON()` — HTML-entity escaper for JSON response values
- `evaluator.newSQSPoller()` — now returns error on invalid queue URL
- Tests: SSRF prevention (8 rejected URLs + 4 safe URLs), `ValidatePlatform` (7 cases)

## [0.11.0] - 2026-04-17

### Added

- **`attest integrate grc push`** — GRC platform integration (#71). Generates OSCAL
  Assessment Results from the current crosswalk and POSTs to any OSCAL-compatible HTTP
  endpoint. Supports ServiceNow GRC, RSA Archer, and generic receivers. Auth via
  `ATTEST_GRC_TOKEN` env var (never CLI). Retry with exponential backoff on 5xx;
  fail-fast on 4xx. `--dry-run` prints payload without sending. `--on-change` watches
  for posture changes and pushes at a configurable interval.
- **`attest enforce setup`** — EventBridge + SQS infrastructure setup (#72). Creates
  an EventBridge rule matching CloudTrail events, an SQS queue (`attest-cedar-events`)
  as the target, sets the queue policy, and saves the queue URL to `.attest/evaluator.yaml`.
  After setup, `attest watch` automatically uses SQS for sub-second Cedar evaluation
  latency (vs. 30s CloudTrail polling).
- **`evaluator.StartWithSQS()`** — SQS-based Cedar PDP continuous evaluation. Long-polls
  SQS (20s wait, batch 10), parses EventBridge-wrapped CloudTrail events, evaluates via
  Cedar, writes to decision log, and deletes only successfully-processed messages
  (at-least-once semantics). `internal/evaluator/sqs.go`.
- **`attest serve --assessor-mode`** — CMMC C3PAO assessor portal (#73). Read-only
  dashboard mode with `--assessor-org` and `--assessor-expires` flags. All POST/PUT/DELETE
  endpoints return 403. Session expiry enforced. New `GET /api/assessor/me` endpoint
  returns assessor info. `dashboard.NewAssessorServer()` constructor.
- **`attest sre report [--cost] [--output csv]`** — Multi-SRE aggregate compliance and
  cost report (#74). Shows per-SRE posture score and (with `--cost`) monthly AWS spend
  via Cost Explorer. Exports to CSV. Uses existing `ScanAll()` infrastructure.
- **`internal/integrations/grc/`** — New package: `GRCClient` with `Push()`,
  `PushWithRetry()`, `WatchAndPush()`. Platform-specific headers for ServiceNow and Archer.
- **`internal/multisre/cost.go`** — `CostCollector` and `CostSummary` types. Queries
  AWS Cost Explorer for 30-day spend, aggregates by service, returns top-5.
- **`internal/document/oscal/oscal_test.go`** — First test coverage for the OSCAL package:
  UUID format, uniqueness, status mapping, SSP structure, Assessment Results structure,
  empty controls edge case (9 tests).
- **`internal/integrations/grc/client_test.go`** — 9 tests: push success, auth header,
  no-token, 4xx fail-fast, 5xx error, dry-run, platform headers, truncate, document type.
- **`internal/multisre/cost_test.go`** — 3 tests: cost aggregation across time buckets,
  empty result, top-5 limit enforcement.
- Dependencies added: `service/sqs`, `service/eventbridge`, `service/costexplorer`.

## [0.10.3] - 2026-04-17

### Security

- **CRITICAL fixed**: Assessor organization markdown injection — `--assessor` flag value
  embedded in CMMC bundle `readiness.md` without sanitization. `[Evil Corp](https://phishing.com)`
  would render as an active link when the report is viewed as HTML. New `sanitizeMarkdown()`
  helper escapes `[`, `]`, `(`, `)`, `*`, `_`, `` ` ``, `<`, `>`, `&`, and collapses
  newlines. Applied to all user-supplied fields in generated reports (`AssessorOrg`, `OrgID`).
- **CRITICAL fixed**: Registry TOCTOU path traversal — `Manager.Load()` now re-validates
  all SRE IDs parsed from `.attest/sres.yaml` with `isValidSREID()`. A manually-edited
  registry file with `id: "../../etc"` would previously bypass the validation enforced by
  `Add()` and reach `StoreDir()`. `Load()` now returns an error on any invalid ID.
- **HIGH fixed**: `attest sre scan --id` missing validation — the `--id` flag value was not
  validated with `IsValidSREID()`, unlike the `--from`/`--to` flags in `sre diff`. Now
  validated before use. Consistent validation across all `sre` subcommands.

### Added

- `internal/document/cmmc/bundle_test.go` — 7 test cases for `sanitizeMarkdown()`: link
  injection, script tags, newlines, backtick code spans, markdown emphasis. `internal/document/cmmc`
  now has test coverage for the first time.
- `internal/multisre/toctou_test.go` — 3 tests for TOCTOU fix: manually-injected unsafe ID
  in registry YAML is rejected on `Load()`, normal valid registry still loads.

## [0.10.2] - 2026-04-17

### Security

- **CRITICAL fixed**: Path traversal in `attest compile --output` — the `--output`
  flag now validates against an explicit allowlist `{"terraform", "cdk"}`. Previously
  any string was accepted and used directly in `filepath.Join(compiledDir, iacOutput)`,
  allowing `--output ../../tmp` to write compiled artifacts outside `.attest/compiled/`.
- **HIGH fixed**: Missing ID validation in `attest sre diff --from/--to` — both flag
  values are now validated with `IsValidSREID()` (exported from `multisre` package)
  before being used in `StoreDir()`. Prevents path traversal via the diff subcommand
  that bypassed the validation enforced by `Add()`.
- **HIGH fixed**: OrgID markdown injection in CMMC bundle — `Manager.Add()` now
  validates `OrgID` against `isValidOrgID()`: must match `o-[a-z0-9]+` pattern,
  rejecting `]`, `[`, `<`, `>`, quotes, and other HTML/markdown metacharacters that
  would be injected into generated compliance reports.
- **HIGH fixed**: Missing runtime path validation in `iac.Generator.Generate()` — now
  rejects relative `outputDir` values that start with `..` (path traversal). Absolute
  paths remain valid for programmatic use; CLI callers already validate via allowlist.

### Added

- `multisre.IsValidSREID()` — exported wrapper for the internal ID validator, allowing
  CLI diff/scan subcommands to validate `--from`/`--to` flags before reaching `StoreDir`.
- `multisre.isValidOrgID()` — validates AWS Org IDs (`o-[a-z0-9]+`), rejecting
  markdown metacharacters.
- 2 new test files covering the new fixes (15+ test cases):
  - `internal/multisre/orgid_test.go`: OrgID validation and injection rejection
  - `internal/iac/generator_security_test.go`: outputDir path traversal prevention

## [0.10.1] - 2026-04-17

### Security

- **CRITICAL fixed**: Path traversal in multi-SRE registry — `SREEntry.ID` now validated
  by `isValidSREID()` (alphanumeric, hyphen, underscore only; max 64 chars; rejects `..`,
  `/`, `\`, shell metacharacters). `Manager.Add()` enforces this before `StoreDir()` is
  ever called. Prevents `attest sre add --id ../../etc` from escaping `.attest/`.
- **CRITICAL fixed**: Code injection in CDK TypeScript generation — all SCP filenames are
  validated by `isValidSCPID()` (lowercase alphanumeric, hyphen, underscore only) before
  being embedded into `stack.ts`. Rejects backticks, template literals, quotes, and other
  TypeScript metacharacters that could inject arbitrary code into the generated CDK stack.
- **CRITICAL fixed**: Zip slip in CMMC bundle generator — `createZip()` now resolves
  absolute paths and verifies every archived file path stays within `srcDir` using
  `filepath.Abs()` + `strings.HasPrefix()`. Symlinks in the source directory are silently
  skipped. Zip file created with `0640` (was `os.Create` default, often `0644`).
- **HIGH fixed**: Symlink traversal in CMMC document generation — `generateSCPManifest()`,
  `generateAttestationsIndex()`, `generateWaiversRegister()` now check
  `info.Mode()&os.ModeSymlink != 0` and skip symlinks before calling `os.ReadFile()`.
- **MEDIUM fixed**: Output directory path traversal in `attest generate cmmc-bundle` —
  `--output` flag value is now validated: must be relative, must not start with `..`.
- **MEDIUM fixed**: Framework ID Unicode/homoglyph validation — `validate()` in
  `internal/framework/loader.go` now enforces `[a-z0-9_-]` character set on IDs, rejecting
  Unicode lookalikes (Cyrillic "ітар", en-dash, em-dash) that could bypass conflict detection.

### Added

- 3 new security test files (30+ test cases):
  - `internal/multisre/security_test.go`: `isValidSREID` (17 cases), `Add` rejection,
    `StoreDir` containment
  - `internal/iac/security_test.go`: `isValidSCPID` (11 cases), CDK injection rejection
  - `internal/framework/security_test.go`: Unicode/homoglyph ID validation (10 cases)

## [0.10.0] - 2026-04-17

### Added

- **NIST SP 800-53 Rev 5 framework** (`frameworks/nist-800-53-r5/framework.yaml`) — 31 controls
  across AC, AU, CM, IA, RA, SC, SI, SA families. Fixes framework defect: CLI listed this
  framework as available but no YAML existed. Unlocks FedRAMP High and federal agency
  customers. ~75% of SCP conditions shared with NIST 800-171 R2; marginal budget cost ~400 chars.
- **UK Cyber Essentials framework** (`frameworks/uk-cyber-essentials/framework.yaml`) — 11 controls
  across 5 themes (Firewalls, Secure Configuration, Access Control, Malware Protection,
  Patch Management). For UK research networks and Horizon/UKRI collaborations. Near-zero
  SCP budget cost when combined with NIST 800-171 R2. Closes #58.
- **ASD Essential Eight framework** (`frameworks/asd-essential-eight/framework.yaml`) — 8 controls
  at Maturity Level 1. For ARC/NHMRC-funded labs and Aus-UK research partnerships. Closes #57.
- **Multi-framework conflict detection** (`internal/framework/conflicts.go`) — `DetectConflicts()`
  analyses active frameworks and surfaces contradictions, supersessions, and coverage notes.
  Detected patterns: ITAR vs NIST region conflict (blocking), HIPAA emergency access vs NIST MFA
  (info), UK CE vs NIST region supersession, NIST vs FERPA encryption supersession, ASD coverage
  warning. Wired into `attest scan` and `attest compile` (blocks compile on blocking conflicts).
  Closes #61.
- **CDK IaC output** (`internal/iac/output.go` — `generateCDK()`) — `attest compile --output cdk`
  produces `stack.ts` (AWS CDK v2 TypeScript), `cdk.json`, `package.json`, `tsconfig.json` in
  `.attest/compiled/cdk/`. Replaces the hard error that blocked CDK users. Closes #37.
- **CMMC Level 2 assessment bundle** (`internal/document/cmmc/bundle.go`) —
  `attest generate cmmc-bundle [--output <dir>] [--assessor <org>]` produces the complete C3PAO
  assessment package: `readiness.md` (traffic-light report), `cmmc-score.md` (per-control scoring
  out of 550), `evidence/` directory (SCP manifest, attestations index, waivers register),
  `crosswalk-cmmc.yaml`, and a `cmmc-bundle-DATE.zip` archive.
- **Multi-SRE management** (`internal/multisre/manager.go`) — `attest sre add/list/remove/scan/diff`
  manages compliance across multiple AWS Organizations from one registry (`.attest/sres.yaml`).
  `scan --all` runs concurrently. `diff --from <id> --to <id>` compares posture between SREs.
  Designed for multi-campus research networks and partner institution SREs.
- `frameworks list` now includes `nist-800-53-r5`, `uk-cyber-essentials`, `asd-essential-eight`.

### Fixed

- Framework defect: `nist-800-53-r5` was listed in CLI as available but no YAML existed.
  YAML now added; the framework loads correctly via `attest frameworks add nist-800-53-r5`.

### Tests added

- `internal/framework/conflicts_test.go` — 11 tests for `DetectConflicts()`, `HasBlockingConflicts()`,
  `FormatConflicts()` covering all 6 conflict patterns.
- `internal/multisre/manager_test.go` — 9 tests for add, list, get, remove, validation,
  persistence, default region, and aggregate posture.
- `internal/reporting/incidents_test.go` — 7 tests for create, list, resolve, uniqueness,
  timing, and persistence.
- `internal/principal/resolver_test.go` — 5 tests for `roleNameFromARN()`, `extractCN()`,
  resolver chain, graceful failure, and PrincipalARN propagation.
- `internal/iac/output_test.go` — 5 tests for Terraform generation, CDK generation,
  `toCDKResourceID()`, unsupported format, and missing SCP dir.

## [0.9.1] - 2026-04-17

### Security

- **CRITICAL fixed**: Open redirect in OIDC callback — `redirect` query param now
  validated to be a relative path only (must start with `/`, must not contain `://`
  or `//`). Prevents post-authentication redirect to attacker-controlled sites.
- **CRITICAL fixed**: `attest provision --email` now validated with `net/mail.ParseAddress()`
  before being sent to the AWS Organizations API. Also enforces AWS 64-char limit.
- **HIGH fixed**: OIDC session store race condition — `OIDCHandler.sessions` map now
  protected by `sync.RWMutex`; all reads, writes, and deletes are lock-guarded.
- **HIGH fixed**: Session cookie now sets `Secure: true` when the redirect URL is not
  localhost/127.x, preventing transmission over plain HTTP in production.
- **HIGH fixed**: OIDC state comparison now uses `crypto/subtle.ConstantTimeCompare`
  instead of string `!=`, eliminating the timing oracle.
- **HIGH fixed**: OIDC redirect URI defaults to `https://` for non-localhost addresses;
  previously hardcoded `http://` was rejected by institutional OIDC providers.
- **HIGH fixed**: Path traversal in `attest ai ingest` and `attest ai analyze` — file
  paths are now resolved with `filepath.Abs`, `os.Stat`, and `IsRegular()` before
  being passed to the AI analyst. Non-regular files (directories, symlinks) rejected.
- **MEDIUM fixed**: HTTP security headers added to all dashboard responses via new
  `securityHeaders` middleware: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Content-Security-Policy: default-src 'self'`, `Referrer-Policy: strict-origin-when-cross-origin`.
- **MEDIUM fixed**: OIDC state token entropy increased from 128-bit (16 bytes) to
  256-bit (32 bytes), matching NIST recommendations for cryptographic nonces.
- **MEDIUM fixed**: `attest provision --name` now validated: max 50 chars (AWS limit),
  alphanumeric/spaces/hyphens/periods only.
- **MEDIUM fixed**: LDAP `LDAPSource` prints a warning to stderr when using anonymous
  bind (`BindDN == ""`), making the security risk visible to operators.
- **LOW fixed**: `provisioner.Execute()` sanitizes account-creation errors that mention
  "email" to prevent information leakage about existing account email addresses.
- **LOW fixed**: `provisioner.findOU()` now detects and errors on duplicate OU names
  under the same parent, preventing ambiguous account placement.
- **MEDIUM fixed**: Session cookie TTL reduced from 8h to 4h (appropriate for an
  administrative security interface).

### Added

- `attest ai generate-policy <control-id>` — generates institutional policy and procedure
  documents (training plans, IR procedures, risk assessment templates) for administrative
  control gaps. Uses Claude Sonnet 4.6 with a policy-drafting system prompt. Distinct from
  `attest ai remediate` which targets technical artifacts.
- `internal/auth/auth_test.go` — 8 tests covering open redirect, session concurrency
  (race detector), entropy, uniqueness, localhost detection, and static token middleware.
- `internal/dashboard/server_test.go` — `TestSecurityHeaders` verifying all 4 new
  security headers are present on every response.
- `.github/workflows/ci.yml` — `go test -race` step added to catch concurrency bugs in CI.

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
