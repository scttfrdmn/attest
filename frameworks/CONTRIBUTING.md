# Framework Authoring Guide

Attest frameworks are community-maintained YAML files that map compliance controls to
deployable AWS policy artifacts. This guide explains how to write one.

## Structure

```
frameworks/
└── <framework-id>/
    └── framework.yaml
```

Framework ID should be lowercase, hyphenated: `nist-800-171-r2`, `hipaa`, `ferpa`.

---

## Framework YAML schema

```yaml
id: "my-framework"           # Unique ID (used in CLI: attest frameworks add my-framework)
name: "My Framework"         # Human-readable name
version: "1.0"               # Framework version
source: "https://..."        # Authoritative source URL

artifact_reports:            # AWS Artifact reports that evidence AWS-side coverage
  - series: "SOC 2 Type II"
    category: "SOC"

controls:
  - id: "1.1"                # Control ID (string, any format)
    family: "Access Control" # Control family for grouping in SSP
    title: "Limit access..."
    responsibility:
      aws: "What AWS covers"
      customer: "What the customer must do"
    structural: [...]        # Optional: SCPs (preventive enforcement)
    operational: [...]       # Optional: Cedar policies (operational enforcement)
    monitoring: [...]        # Optional: Config rules (drift detection)
    assessment:              # Optional: assessment objectives
      objectives: [...]
    review_schedule:         # Optional: for administrative controls
      frequency: "annual"    # annual, semiannual, quarterly, event_driven
      trigger: "calendar"    # calendar | event
```

---

## Structural enforcement (SCPs)

SCPs are Deny-type policies applied at the org root. Conditions use a custom syntax
that the compiler translates to IAM Condition blocks.

```yaml
structural:
  - id: "scp-require-mfa"             # Alphanumeric ID (no hyphens in final Sid)
    description: "Deny without MFA"
    actions:
      - "*"
    conditions:
      - "aws:MultiFactorAuthPresent != true"   # Bool: false
      - "aws:PrincipalType == IAMUser"          # StringEquals
    effect: "Deny"
```

### Condition string syntax

| Pattern | Example | IAM operator |
|---|---|---|
| `key != true` | `aws:MultiFactorAuthPresent != true` | `Bool: "false"` |
| `key == true` | `aws:MultiFactorAuthPresent == true` | `Bool: "true"` |
| `key == false` | `aws:SecureTransport == false` | `Bool: "false"` |
| `key != false` | `aws:SecureTransport != false` | `Bool: "true"` |
| `key == value` | `aws:RequestedRegion == us-east-1` | `StringEquals` |
| `key != value` | `aws:RequestedRegion != us-east-1` | `StringNotEquals` |
| `key in [v1, v2, ...]` | `aws:PrincipalType in [IAMUser, IAMRole]` | `StringEquals` (multi-value) |
| `key not in [v1, v2, ...]` | `aws:RequestedRegion not in [us-east-1, us-west-2]` | `StringNotEquals` (multi-value) |
| `key contains str` | `aws:username contains Admin` | `StringLike` (`*str*`) |
| `key does not contain str` | `aws:username does not contain Admin` | `StringNotLike` (`*str*`) |
| `arn-key == arn:...*...` (wildcard) | `aws:PrincipalArn == arn:aws:iam::*:role/*` | `ArnLike` |
| `arn-key != arn:...*...` (wildcard) | `aws:PrincipalArn != arn:aws:iam::*:root` | `ArnNotLike` |
| `arn-key == arn:...` (exact) | `aws:PrincipalArn == arn:aws:iam::123456789012:role/Admin` | `ArnEquals` |
| `arn-key != arn:...` (exact) | `aws:PrincipalArn != arn:aws:iam::123456789012:root` | `ArnNotEquals` |

**Detection rule**: keys containing `arn` (case-insensitive) or values starting with `arn:`
use ARN operators. Values containing `*` or `?` use wildcard variants (ArnLike/ArnNotLike).

**Important**: Only `aws:*` condition keys are reliably supported in SCPs. Service-specific
keys (`ec2:*`, `lambda:*`) may be rejected by AWS Organizations. Test with
`attest apply --dry-run` before committing.

---

## Operational enforcement (Cedar policies)

Cedar policies evaluate context-dependent attributes at runtime. The compiler generates
a `forbid-unless` policy from the entities and attributes spec.

```yaml
operational:
  - id: "cedar-cui-data-movement"
    description: "CUI data only moves to authorized destinations"
    entities: ["data_object", "destination_bucket", "principal"]
    attributes:
      data_object: ["classification", "source_account"]
      destination_bucket: ["encryption_type", "enclave_membership"]
      principal: ["cui_training_current", "lab_authorization"]
    temporal:                          # Optional: time-bounded constraints
      condition_type: "expiry"         # expiry | event | schedule
      description: "Training expires annually"
    admin_dependencies:                # Optional: links to admin controls
      - control_id: "3.2.2"
        attribute: "principal.cui_training_current"
        consequence: "Policy evaluates attribute as false if training unattested"
```

For complex policies, include the raw Cedar DSL:

```yaml
    cedar_policy: |
      forbid (
        principal,
        action == Action::"S3:PutObject",
        resource
      )
      unless {
        resource.enclave_membership == true &&
        principal.cui_training_current == true
      };
```

---

## Monitoring (Config rules)

Config rules detect configuration drift:

```yaml
monitoring:
  - id: "config-mfa-enabled"
    resource_type: "AWS::IAM::User"    # AWS CloudFormation resource type
    check: "MFA device attached and active"
    remediation: "Enable MFA via IAM console"
```

---

## Assessment objectives

For controls with NIST 800-171A or similar assessment objectives:

```yaml
assessment:
  objectives:
    - id: "3.1.1[a]"
      description: "Authorized users are identified"
      auto_assessable: true       # Can attest score this from system state?
      evidence_source: "cedar"    # cedar | scp | config | manual
```

`auto_assessable: true` means attest can score the objective from compiled artifacts.
`evidence_source: manual` means human attestation is required.

---

## Review schedules

For administrative controls that require periodic renewal:

```yaml
review_schedule:
  frequency: "annual"      # annual | semiannual | quarterly | event_driven
  trigger: "calendar"      # calendar | event
```

Controls with `review_schedule` appear in `attest calendar` output.

---

## Minimal working example

```yaml
id: my-framework
name: "My Compliance Framework"
version: "1.0"
source: "https://example.com/my-framework"

controls:
  - id: "MF-1.1"
    family: "Access Control"
    title: "Require MFA for all users"
    responsibility:
      aws: "IAM supports MFA"
      customer: "Enforce MFA via SCP"
    structural:
      - id: "scp-my-require-mfa"
        description: "Deny all actions without MFA"
        actions: ["*"]
        conditions:
          - "aws:MultiFactorAuthPresent != true"
          - "aws:PrincipalType == IAMUser"
        effect: "Deny"
    assessment:
      objectives:
        - id: "MF-1.1[a]"
          description: "MFA is enforced for all users"
          auto_assessable: true
          evidence_source: "scp"
```

---

## Delta frameworks

Some compliance baselines are strict supersets of others. Rather than duplicating
controls across files, write a *delta* framework that contains only the additions
and activate both together:

```bash
attest frameworks add fedramp-moderate   # base (23+ controls)
attest frameworks add fedramp-high       # delta — High-specific controls only
```

The merged SCP compiler deduplicates conditions across all active frameworks
automatically. A delta framework costs zero additional SCP budget for conditions
already covered by its base.

`frameworks/fedramp-high/framework.yaml` is a reference implementation. Key conventions:

1. Name the framework to make the dependency clear:
   ```yaml
   name: "My Framework (delta — activate with base-framework)"
   ```

2. Include only controls that are genuinely new — not present in the base.

3. Add a conflict check in `internal/framework/conflicts.go` so users get a warning
   if they activate the delta without the base.

---

## Testing your framework

```bash
# Validate it loads and parses
attest frameworks list    # should appear

# Activate and compile
attest frameworks add my-framework
attest compile
# → check .attest/compiled/scps/ for generated SCPs

# Check the crosswalk
cat .attest/compiled/crosswalk.yaml | grep "my-framework"

# Generate SSP
attest generate ssp --framework my-framework
```

---

## Submitting

1. Fork `github.com/provabl/attest`
2. Create `frameworks/<your-id>/framework.yaml`
3. Run `go test ./internal/framework/... -run TestLoadAll` to verify it parses
4. Open a PR — include the framework's authoritative source URL and your rationale
   for the enforcement mappings

Community contributions are the backbone of attest's compliance coverage.
The framework schema is open; the quality validated content packs are commercial
(see [provabl.dev](https://provabl.dev)).
