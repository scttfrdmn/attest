# Tutorial: Greenfield — From Zero to CMMC Assessment

This tutorial follows **Dr. Sarah Chen's DoD-funded quantum computing lab** at Meridian Research
University. The lab handles CUI (Controlled Unclassified Information) and needs to reach
CMMC Level 2 Assessment Ready status before receiving DoD funding. They start with a blank
AWS Organization and no compliance program.

See also: [`demo/greenfield/`](../../demo/greenfield/) for full scenario context.

---

## Prerequisites

- AWS management account access (`AWS_PROFILE=sre`)
- IAM permissions: `organizations:*`, `sts:GetCallerIdentity`, `cloudtrail:DescribeTrails`
- Go 1.25+ (or download release binary)

```bash
# Build from source
git clone https://github.com/provabl/attest
cd attest
go build -o /usr/local/bin/attest ./cmd/attest
attest version
# → attest v0.8.0-dev
```

---

## Step 1 — Initialize

```bash
AWS_PROFILE=sre attest init --region us-east-1
```

**What you should see:**
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

Tag your research accounts so attest knows what data they handle:

```bash
aws organizations tag-resource \
  --resource-id 123456789012 \
  --tags Key=attest:data-class,Value=CUI \
         Key=attest:owner,Value="Dr. Chen" \
         Key=attest:purpose,Value="DoD quantum computing research"
```

---

## Step 2 — Activate NIST 800-171

```bash
attest frameworks add nist-800-171-r2
```

**What you should see:**
```
Added framework: nist-800-171-r2
  110 controls across 14 families
  Requires: DoD contract or CUI data handling
Updated .attest/sre.yaml
```

---

## Step 3 — Compile (inspection mode)

```bash
attest compile
```

**What you should see:**
```
Compiled artifacts written to .attest/compiled
  26 SCP(s)
  7 Cedar policy/policies + schema
  Crosswalk: .attest/compiled/crosswalk.yaml
```

Inspect what was generated:
```bash
ls .attest/compiled/scps/
# attest-scp-deny-admin-star.json  attest-scp-deny-root-usage.json  ...

cat .attest/compiled/scps/attest-scp-require-mfa.json
# {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}
```

For production deployment, use the merged strategy to fit within the 5-SCP-per-target limit:

```bash
attest compile --scp-strategy merged
```

**What you should see:**
```
  26 structural specs → 15 unique condition groups → 1 SCP document
  SCP budget: 2,780 / 20,480 chars used (13.6%)
Compiled artifacts written to .attest/compiled
  1 SCP(s) (merged)
  7 Cedar policy/policies + schema
  Crosswalk: .attest/compiled/crosswalk.yaml
```

---

## Step 4 — Preflight check

Before deploying, verify your org is ready:

```bash
AWS_PROFILE=sre attest preflight --region us-east-1
```

**What you should see (ready):**
```
Checking prerequisites for attest apply...

  ✓ Organization: ALL features enabled
  ✓ Management account: 123456789012
  ✓ SCP policy type: enabled on root r-xxxx
  ✓ SCP quota: 1/5 used (fits within limit with merged strategy)
  ✓ Compiled SCPs: 1 (merged) — fits within quota
  ✓ IAM permissions: organizations:CreatePolicy ✓

  Result: READY — run 'attest apply --dry-run' to preview
```

**If you see a quota error (individual strategy):**
```
  ✗ SCP quota: 1/5 used at root
      Compiled SCPs: 26 (would need 26 slots, limit is 5)
      Solution: run 'attest compile --scp-strategy merged'
                produces ≤4 composite SCPs, fits the limit
```

→ Run `attest compile --scp-strategy merged` and re-run preflight.

---

## Step 5 — Preview and apply

```bash
AWS_PROFILE=sre attest apply --dry-run --region us-east-1
```

```
Deployment plan (root: r-xxxx):
  Create and attach: 1 SCP(s)
  Update:            0 SCP(s)
  Attach:            0 SCP(s)
  No change:         0 SCP(s)

Dry run — no changes made.
```

Deploy:

```bash
AWS_PROFILE=sre attest apply --approve --region us-east-1
```

```
Computing deployment plan...
Deployment plan (root: r-xxxx):
  Create and attach: 1 SCP(s)

  Snapshot: applied-20260416-143022
  Applying...
  Creating SCP: attest-scp-01
  Attaching SCP: attest-scp-01 → r-xxxx
  
Deployed 1 SCP(s) to r-xxxx.
Run 'attest scan' to verify posture.
```

Note the **Snapshot** line — attest automatically created a rollback point. To undo:

```bash
AWS_PROFILE=sre attest rollback --list
# → applied-20260416-143022

AWS_PROFILE=sre attest rollback --approve --region us-east-1
```

---

## Step 6 — Scan posture (first look)

```bash
attest scan
```

```
Posture summary:
  Total controls:  110
  Enforced:          9   (SCPs deployed)
  Partial:          21   (Cedar policies compiled but PDP not running)
  Gaps:             80   (administrative controls not yet attested)

  NIST SP 800-171 Rev 2:
    Enforced: 9  Partial: 21  Gaps: 80

Score: 111 / 550 (20.2%) — Work in progress
```

Low score is expected — 80 administrative controls need human attestation.

Verify live infrastructure:

```bash
AWS_PROFILE=sre attest scan --verify --region us-east-1
```

```
Live verification:
  ✓ CloudTrail: multi-region trail active (last event: 2 minutes ago)
  ✓ SCPs deployed: attest-scp-01 attached to root r-xxxx
  ✓ IAM password policy: active
```

---

## Step 7 — First SSP (low score)

```bash
attest generate ssp --framework nist-800-171-r2
```

```
Generating SSP for nist-800-171-r2...
  110 controls processed
  9 enforced, 21 partial, 80 gaps
Written to .attest/documents/ssp-nist-800-171-r2.md
```

Open `.attest/documents/ssp-nist-800-171-r2.md` — it will show mostly gaps in the
administrative sections (3.2 Training, 3.6 Incident Response, 3.11 Risk Assessment).

---

## Step 8 — AI-guided onboarding for administrative controls

```bash
AWS_PROFILE=sre attest ai onboard --mode greenfield --region us-east-1
```

The AI will identify which administrative controls are blocking Cedar policy
enforcement and guide you through the priority order.

---

## Step 9 — Record training completion

```bash
attest attest create \
  --control 3.2.2 \
  --affirmed-by "CISO Dr. Smith" \
  --title "CUI handling training cycle complete — CITI Program, Apr 2026" \
  --evidence "CITI completion records, 47 researchers, exported 2026-04-15" \
  --evidence-type training_record \
  --expires 2027-04-15
```

```
Created attestation ATT-001 for control 3.2.2
  Expires: 2027-04-15
```

Repeat for other administrative controls (risk assessment, IR capability, etc.).

---

## Step 10 — Rescan (after admin work)

```bash
attest scan
```

```
Posture summary:
  Enforced:         9   (SCPs)
  Partial:         21   (Cedar partially covered)
  AWS Covered:     80   (administrative controls attested)

Score: 487 / 550 (88.5%) — Assessment Ready ✓
```

Generate the final SSP:

```bash
attest generate ssp --framework nist-800-171-r2
attest generate assess
```

---

## Step 11 — Dashboard

```bash
AWS_PROFILE=sre attest serve
# → http://localhost:8080
```

Open `http://localhost:8080` to see the live posture ring, framework table, and
Cedar PDP operations feed.

---

## Next steps

- [Legacy ingest tutorial](legacy.md) — mapping existing docs in 30 minutes
- [Rollback guide](../operations/rollback.md) — how to undo a deployment
- [Framework authoring](../../frameworks/CONTRIBUTING.md) — add HIPAA or ISO 27001
