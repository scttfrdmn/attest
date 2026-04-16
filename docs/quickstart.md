# Quick Start

Get from a blank AWS Organization to a CMMC 2.0 Level 2 self-assessment in one session.

## Prerequisites

Before you start, you need:

- **Management account access** — attest must run from the management account of your
  AWS Organization (or an account with delegated Organizations read access)
- **AWS credentials** configured (`AWS_PROFILE` or `aws configure`)
- **IAM permissions**: `organizations:Describe*`, `organizations:List*`,
  `organizations:CreatePolicy`, `organizations:AttachPolicy`,
  `organizations:EnablePolicyType`, `artifact:ListReports`,
  `artifact:ListCustomerAgreements`, `config:DescribeConfigRules`
- **Organizations All Features** enabled (not Consolidated Billing only)
- **Go 1.25+** (to build from source) or download a release binary
- **For AI capabilities**: AWS Bedrock access enabled in your region

### What attest does NOT require

- Existing SCPs or compliance controls — attest inventories what's there and identifies gaps
- Pre-existing Cedar policies — compiled from the framework definitions
- Existing framework activations — `attest frameworks add` handles this
- A pre-configured compliance program — that's the point

### AWS quota note

AWS limits SCPs to **5 per target** (root, OU, or account) by default. Attest compiles
26 SCPs for NIST 800-171 alone. Before running `attest apply` in production, request a
quota increase via AWS Support (target: 20-50 per target). Run `attest preflight` to
check your quota before applying.

---

## Installation

```bash
# Build from source (requires Go 1.25+)
git clone https://github.com/provabl/attest
cd attest
go build -o /usr/local/bin/attest ./cmd/attest

# Verify
attest version
```

---

## Step 1 — Initialize

Point attest at your AWS Organization:

```bash
AWS_PROFILE=your-profile attest init --region us-east-1
```

Output:
```
Initializing SRE...
  Reading Organization topology (region: us-east-1)...
  Organization: o-abc123xyz (3 environments)
  Inventorying existing SCPs...
  Found 1 existing SCP (FullAWSAccess — AWS default)
  Querying Artifact for active agreements...
  Detecting data classifications from account tags...

SRE initialized. Written to .attest/sre.yaml
  Org: o-abc123xyz
  Environments: 3
  Active frameworks: 0
```

**Tag your accounts** so attest knows what data they handle:

```bash
aws organizations tag-resource \
  --resource-id 123456789012 \
  --tags Key=attest:data-class,Value=CUI \
         Key=attest:owner,Value="Dr. Smith" \
         Key=attest:purpose,Value="DoD research"
```

---

## Step 2 — Activate frameworks

```bash
attest frameworks add nist-800-171-r2

# If you have a signed HIPAA BAA with AWS:
attest frameworks add hipaa

# List available frameworks
attest frameworks list
```

For UC campuses or institutions using P-levels:
```bash
attest init --classification-scheme uc-protection-levels
# Automatically maps P4 accounts → CUI/PHI + activates NIST 800-171 / HIPAA
```

---

## Step 3 — Compile

Generate the SCP JSON, Cedar policies, and crosswalk manifest:

```bash
attest compile
```

Output:
```
Compiled artifacts written to .attest/compiled
  26 SCP(s)
  7 Cedar policy/policies + schema
  Crosswalk: .attest/compiled/crosswalk.yaml
```

Inspect what was generated:
```bash
ls .attest/compiled/scps/       # 26 SCP JSON files
cat .attest/compiled/crosswalk.yaml | head -20
```

---

## Step 4 — Check prerequisites

Before deploying, verify your org is ready:

```bash
AWS_PROFILE=your-profile attest preflight --region us-east-1
```

This checks:
- SCP policy type enabled on org root
- IAM permissions for deployment
- SCP quota vs. compiled count
- If quota would be exceeded: outputs the Service Quotas console link

---

## Step 5 — Apply (deploy SCPs)

Preview what will happen:

```bash
AWS_PROFILE=your-profile attest apply --dry-run --region us-east-1
```

Deploy to your organization:

```bash
AWS_PROFILE=your-profile attest apply --approve --region us-east-1
```

This creates and attaches SCPs to the org root. Every account inherits them immediately.

---

## Step 6 — Scan posture

```bash
attest scan
```

Output:
```
Posture summary:
  Total controls:  110
  Enforced:         9
  Partial:         21
  Gaps:             0   (remaining are AWS-covered)

  NIST SP 800-171 Rev 2:
    Enforced: 9  Partial: 21  Gaps: 0
```

---

## Step 7 — Generate documents

```bash
# System Security Plan (markdown + OSCAL)
attest generate ssp --framework nist-800-171-r2

# CMMC self-assessment score
attest generate assess

# Plan of Action & Milestones
attest generate poam

# Full OSCAL bundle
attest generate oscal
```

Output from `generate assess`:
```
Score: 487/550 (88.5%) — Assessment Ready
  Implemented: 94  Partial: 16  Planned: 0  Gap: 0
```

Documents written to `.attest/documents/`.

---

## Step 8 — Administrative controls

Technical controls are now deployed. Administrative controls (training, risk assessments,
IR testing) need human action. See where to focus:

```bash
# See what's missing and what comes due
attest calendar --window 90d

# Get AI-guided onboarding (requires Bedrock access)
AWS_PROFILE=your-profile attest ai onboard --mode greenfield --region us-east-1
```

Record attestations as you complete each obligation:

```bash
attest attest create \
  --control 3.2.2 \
  --affirmed-by "CISO Jane Smith" \
  --evidence "CITI completion records, exported 2026-04-01" \
  --expires 2027-04-01
```

---

## Demo scenario

The `demo/` directory contains a realistic walkthrough for Meridian Research University:

- **`demo/greenfield/`** — DoD-funded quantum lab, starting from zero, reaching 88.5%
- **`demo/legacy/`** — Genomics lab with 4 years of existing docs, mapped in 30 minutes

---

## Next steps

- [Framework authoring guide](../frameworks/CONTRIBUTING.md) — contribute a new framework
- [Architecture docs](../docs/architecture/) — multi-framework, principal attributes, ITAR
- [GitHub Issues](https://github.com/provabl/attest/issues) — report bugs, request features
