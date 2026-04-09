# attest

Open-source compliance compiler for AWS Secure Research Environments.

**Attest** reads compliance frameworks from AWS Artifact, maps customer-responsible
controls to deployable policy artifacts (SCPs, Cedar policies, Config rules), and
generates audit documents (SSP, POA&M, self-assessments) from the live state of
your AWS Organization.

## Architecture

An AWS Secure Research Environment (SRE) is an **Organization** with compliance
controls applied at the org level. Accounts within the org are research
**environments** — they inherit the compliance posture by construction, not by
individual configuration.

```
┌─────────────────────────────────────────────────┐
│  attest                                         │
│                                                 │
│  Artifact API ──► Framework Parser              │
│  Org API      ──► Org Analyzer                  │
│                      │                          │
│                      ▼                          │
│              Control Gap Analysis                │
│                      │                          │
│          ┌───────────┼───────────┐              │
│          ▼           ▼           ▼              │
│     SCP Compiler  Cedar Comp  Config Comp       │
│          │           │           │              │
│          ▼           ▼           ▼              │
│     Crosswalk Manifest (control → artifact)     │
│                      │                          │
│          ┌───────────┼───────────┐              │
│          ▼           ▼           ▼              │
│      Deploy      Evaluate    Generate Docs      │
│     (org apply)  (Cedar PDP) (SSP/POA&M/OSCAL)  │
└─────────────────────────────────────────────────┘
```

## Core Concepts

- **SRE (Secure Research Environment)**: An AWS Organization configured as a
  compliance enclave. The org *is* the boundary.
- **Environment**: An AWS account within the SRE. Inherits org-level controls.
  Researchers get accounts, not infrastructure.
- **Framework**: A compliance standard (NIST 800-171, HIPAA, FERPA, etc.)
  expressed as machine-readable control definitions.
- **Crosswalk**: The mapping from framework controls → deployed policy artifacts.
  The auditable proof that a control is enforced.
- **Posture**: The computed compliance state of an SRE — which controls are
  enforced structurally (SCPs), operationally (Cedar), and monitored (Config).

## CLI

```
attest init              # Initialize an SRE from an existing AWS Org
attest scan              # Analyze current org posture against active frameworks
attest frameworks list   # List available compliance frameworks
attest frameworks add    # Activate a framework for this SRE
attest compile           # Generate policy artifacts for active frameworks
attest apply             # Deploy compiled policies to the org (with approval)
attest evaluate          # Run Cedar PDP evaluation against current state
attest generate ssp      # Generate System Security Plan
attest generate poam     # Generate Plan of Action & Milestones
attest generate assess   # Generate self-assessment (CMMC, 800-171A)
attest generate oscal    # Export all documents in OSCAL format
attest diff              # Compare current posture to last assessment
attest watch             # Continuous compliance monitoring (Cedar PDP)
```

## Frameworks

Frameworks are defined in YAML and live in `frameworks/`. The open-source
distribution includes:

- `nist-800-171-r2` — NIST SP 800-171 Rev 2 (maps to CMMC 2.0 Level 2)
- `hipaa` — HIPAA Security Rule
- `ferpa` — FERPA (educational records)
- `nist-800-53-r5` — NIST SP 800-53 Rev 5 (FedRAMP baseline)
- `itar` — ITAR (defense articles, export control)
- `cui` — CUI (Controlled Unclassified Information)

Community contributions welcome. See `frameworks/CONTRIBUTING.md`.

## License

Apache 2.0 — open core. The compliance compiler, framework definitions, and
CLI are open source. The continuous evaluation dashboard and GRC integrations
are commercial (Playground Logic).
