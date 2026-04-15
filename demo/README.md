# Attest Demo Scenarios

Two realistic demo scenarios based on **Meridian Research University** (MRU), a fictional
R1 university running research workloads on AWS. MRU handles three data classes across
different research groups: CUI (DoD-funded research), PHI (clinical genomics), and FERPA
(student data in educational computing labs).

---

## Scenario 1 — Greenfield: Quantum Computing Lab

**Situation**: Dr. Sarah Chen's Quantum Computing Lab just received a DoD subcontract
through MRU's Office of Sponsored Programs. The subcontract involves controlled
unclassified information (CUI) and requires CMMC 2.0 Level 2 compliance within 90 days.
The university has never done CMMC. There is no compliance program, no policies, no
training records. IT Security knows they need to comply but doesn't know where to start.

**Demo flow**: `demo/greenfield/` — shows attest building a compliance program from nothing.

**Key moments**:
- `attest init` reveals the bare org state
- `attest ai onboard` prioritizes what to build first
- `attest ai generate-policy` produces draft documentation
- `attest compile` + `attest generate ssp` shows the score improving as controls are addressed

→ [Greenfield walkthrough](greenfield/WALKTHROUGH.md)

---

## Scenario 2 — Legacy: Biomedical Research Center

**Situation**: Dr. Marcus Rodriguez's Biomedical Research Center has been running on AWS
for 4 years handling genomics data (PHI + CUI). The university has an information security
policy, a signed BAA with AWS, CITI training records in the LMS, and an incident response
plan — but none of it has ever been mapped to NIST 800-171 or HIPAA controls. An NIH audit
is coming in 60 days. The compliance officer says the lab is "probably fine" but can't prove it.

**Demo flow**: `demo/legacy/` — shows attest mapping existing documentation to controls.

**Key moments**:
- `attest ai ingest` maps 4 years of policy documents in minutes
- Before ingestion: 34% posture (everything manual shows as "gap")
- After ingestion + attestations: 71% posture
- `attest generate ssp` produces an audit-ready SSP citing actual evidence

→ [Legacy walkthrough](legacy/WALKTHROUGH.md)

---

## Meridian Research University — Environment Map

```
AWS Organization: o-mru2026
Management Account: MRU IT Security (100000000001)

├── Enclave OU (CUI + PHI)
│   ├── quantum-cui-lab        Dr. Sarah Chen, Physics Dept
│   │   Data: CUI              100000000002
│   │
│   ├── genomics-hipaa-lab     Dr. Marcus Rodriguez, Biomedical
│   │   Data: PHI, CUI         100000000003
│   │
│   └── clinical-trials-02    Dr. Elena Vasquez, Medicine
│       Data: PHI              100000000004
│
├── Research OU (General)
│   └── climate-modeling       Dr. Yuki Tanaka, Earth Sciences
│       Data: (none tagged)    100000000005
│
└── Teaching OU (FERPA)
    └── cs-teaching-lab        CS Department
        Data: FERPA             100000000006
```
