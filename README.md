# attest

**Open-source compliance compiler for AWS Secure Research Environments.**

Universities, health systems, and national labs running research on AWS face a compliance problem that consultants charge $300/hour to solve: translating framework requirements (NIST 800-171, HIPAA, FERPA, CMMC) into deployed AWS controls — and then proving they're working.

Attest automates the full lifecycle: read your org, compile your policies, deploy them, enforce them continuously, and generate the documents your auditor actually needs.

---

## The problem attest solves

A compliance program has two layers that most tools treat independently. Attest connects them.

**Technical controls** — what AWS enforces:
- SCPs that prevent non-compliant actions at the organization level
- Cedar policies that evaluate every sensitive operation against data classification, principal attributes, and temporal constraints
- Config rules that detect configuration drift

**Administrative controls** — what humans operate:
- Training programs (and the records proving they happened)
- Risk assessments, incident response plans, contingency tests
- Personnel screening, policy reviews, waiver approvals

The connection matters. Control 3.2.2 (CUI handling training) isn't just a paperwork requirement — it feeds `principal.cui_training_current` in the Cedar policy that gates every CUI data movement operation. When training expires, the technical enforcement degrades. When the training records exist but aren't in the system, attest thinks the control is a gap when it isn't.

Attest tracks both layers and tells you when they drift apart.

---

## Two starting points

### Starting from scratch

```
$ attest ai onboard --mode greenfield

Attest AI: You have 26 technical controls enforced. You need to build
           34 administrative processes. Here's where to start:

           CRITICAL (blocks Cedar attributes):
           · 3.2.2 — CUI handling training
             Blocks: principal.cui_training_current in 3 Cedar policies.
             Without this: CUI data movement denies everyone.

           Start here? [y]

$ attest ai generate-policy --control 3.2.2
  → Generates: .attest/drafts/policy-3.2.2-cui-training.md
    (tailored to your org, your data classes, your environments)

$ attest attest create --control 3.2.2 \
    --evidence "training-records.csv" --expires 2027-04-15
  → Control 3.2.2 now shows Implemented. Cedar attributes resolve correctly.
```

### You have existing documentation

```
$ attest ai ingest ./policies/information-security-policy.pdf

  3.11.1[a]  ✓ Covered   "Section 4.2: Annual risk assessment required"
  3.11.1[b]  ✓ Covered   "Section 4.3: Risk management measures defined"
  3.6.1[a]   ✓ Covered   "Appendix C: Incident Response Procedures"
  3.6.3[a]   ✗ Missing   No IR testing schedule found
  3.11.2[a]  ✗ Missing   No vulnerability scanning schedule found

  Create attestation records for covered controls? [y]
```

---

## The technical pipeline

```
AWS Artifact API ──► Framework definitions (YAML)
AWS Org API      ──► Org topology, existing SCPs
                              │
                    Control gap analysis
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         SCP compiler    Cedar compiler   Config compiler
         (structural)    (operational)    (monitoring)
              │               │               │
              └───────────────┼───────────────┘
                              ▼
                    Crosswalk manifest
                  (control → artifact, auditable)
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
           Deploy          Evaluate       Generate docs
         (attest apply)  (Cedar PDP)   (SSP/POA&M/OSCAL)
```

**The crosswalk is the core artifact.** It maps every framework control to the deployed artifacts that enforce it — SCPs, Cedar policies, Config rules, attestation records, Artifact report references. An auditor can walk the crosswalk from control to evidence end-to-end.

---

## Quick start

```bash
# Initialize from your existing AWS Organization
AWS_PROFILE=your-profile attest init --region us-west-2

# Activate NIST 800-171 (CMMC 2.0 Level 2)
attest frameworks add nist-800-171-r2

# Compile policy artifacts
attest compile
# → 26 SCPs, 7 Cedar policies, crosswalk.yaml

# Generate your System Security Plan
attest generate ssp
# → .attest/documents/ssp-nist-800-171-r2.md
#   Score: 508/550 (92.4%) — Assessment Ready

# Full assessment package
attest generate assess   # CMMC self-assessment score
attest generate poam     # Plan of Action & Milestones
attest generate oscal    # OSCAL 1.1.2 for GRC tools
```

→ Full step-by-step walkthrough: [docs/quickstart.md](docs/quickstart.md)

---

## What you get from `attest generate ssp`

A real System Security Plan — not a template someone filled in, but a document computed from your live compliance state:

```markdown
### 3.1.3 — Control the flow of CUI in accordance with approved authorizations

| Status | Implemented | Score | 5/5 |
|--------|-------------|-------|-----|
| AWS Coverage | VPC flow control, S3 bucket policies, KMS encryption |
| Enforcement | SCP scp-cui-region-restrict (restricts to approved regions),
|             | SCP scp-cui-s3-encryption (requires KMS),
|             | Cedar policy cedar-cui-data-movement (evaluates classification,
|             | destination encryption, principal training at operation time) |
| Evidence | Training attestation: ATT-2026-003, affirmed 2026-04-01,
|          | expires 2027-04-01 |
```

Every sentence traces to a deployed artifact, an attestation record, or an Artifact report reference. Nothing is hand-written.

---

## Full CLI surface

```
# Initialization and scanning
attest init [--region]             Initialize SRE from existing org
attest scan [--region]             Compute posture against active frameworks
attest diff                        Compare posture between assessment periods

# Framework management
attest frameworks list             Available and active frameworks
attest frameworks add <id>         Activate a framework

# Policy lifecycle
attest compile [--output tf|cdk]   Generate SCPs, Cedar policies, crosswalk
attest apply [--dry-run]           Deploy compiled policies to the org
attest test                        Unit test policies against cedar-go (no AWS)
attest check --terraform plan.json CI/CD compliance gate (SARIF output)

# Document generation
attest generate ssp                System Security Plan (markdown + OSCAL)
attest generate poam               Plan of Action & Milestones
attest generate assess             CMMC 2.0 Level 2 self-assessment
attest generate oscal              Full OSCAL 1.1.2 export bundle

# Governance
attest waiver create|list|expire   Manage compliance exceptions
attest attest create|list|expire   Record administrative control attestations
attest calendar [--window 90d]     Upcoming review and renewal obligations

# Continuous monitoring
attest evaluate                    One-shot Cedar PDP evaluation
attest watch                       Continuous Cedar PDP (EventBridge-driven)
attest serve                       Launch compliance dashboard

# AI capabilities (Bedrock + Claude)
attest ai onboard                  Guided onboarding for greenfield/legacy orgs
attest ai ingest <file>            Map existing documents to framework controls
attest ai generate-policy <ctrl>   Draft administrative policies and procedures
attest ai ask <question>           Query compliance state in plain language
attest ai audit-sim                Simulate an assessor evaluation
attest ai remediate <control>      Generate remediation artifacts for gaps
attest ai translate <description>  Natural language → Cedar policy
attest ai analyze [--window 30d]   Detect anomalies in Cedar decision log
```

---

## Frameworks

Community-maintained YAML definitions in `frameworks/`. Each control carries the full vertical: shared responsibility split, SCP specs, Cedar policy specs, Config rules, assessment objectives, and administrative review schedules.

| Framework | Controls | Notes |
|-----------|---------|--------|
| `nist-800-171-r2` | 110 | CMMC Level 2 basis |
| `hipaa` | 23 | Activated via AWS Artifact BAA |
| `fedramp-moderate` | 36 | FedRAMP Moderate baseline |
| `fedramp-high` | 15 | Delta — activate with `fedramp-moderate` |
| `nist-800-53-r5` | 32 | FedRAMP/High base controls |
| `ferpa` | 13 | — |
| `iso27001-2022` | 36 | — |
| `uk-cyber-essentials` | 11 | — |
| `asd-essential-eight` | 8 | — |

Framework contributions welcome — see [`frameworks/CONTRIBUTING.md`](frameworks/CONTRIBUTING.md).

---

## Open core

| Open source | Commercial (Playground Logic) |
|-------------|-------------------------------|
| Framework definitions and schema | Cedar PDP continuous enforcement |
| SCP, Cedar, Config compilers | Compliance dashboard |
| Crosswalk manifest generator | AI capabilities (Bedrock + Claude) |
| CLI: init, scan, compile, generate | Multi-SRE management |
| Policy unit testing | GRC integrations (OSCAL continuous) |
| IaC output (Terraform, CDK) | Bouncing auth for dashboard |
| Attestation and waiver management | Operational alerting |

---

## License

Apache 2.0. The compliance compiler, framework definitions, CLI, and governance tools are open source. The continuous enforcement dashboard and AI capabilities are commercial.
