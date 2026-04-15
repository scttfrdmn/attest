# Multi-Framework Compliance

Attest is designed from the ground up for organizations operating under multiple
compliance frameworks simultaneously. This is the normal state for research institutions:
a university hospital might run HIPAA, NIST 800-171/CMMC, and FERPA in the same
AWS Organization. A defense contractor lab adds ITAR.

---

## How it works today

When multiple frameworks are active in `.attest/sre.yaml`, `attest compile`:

1. Loads all framework definitions
2. Calls `framework.Resolve([]*schema.Framework{hipaa, nist800171, ...})`
3. Deduplicates by structural enforcement ID — controls from different frameworks
   that require the same SCP produce **one SCP**, not two
4. Generates Cedar policies and Config rules (same deduplication logic)
5. Writes a unified crosswalk with 133 entries (110 NIST + 23 HIPAA = 133,
   minus nothing — they don't overlap at the control level, only at the SCP level)

### What deduplication looks like

HIPAA §164.312(a)(2)(iv) and NIST 800-171 §3.13.11 both require KMS encryption:

```
compile with [hipaa, nist-800-171-r2]
  → deduplication key: "scp-require-kms-encryption"
  → one SCP compiled: attest-scp-require-kms-encryption.json
  → crosswalk entry for 164.312(a)(2)(iv): scps: [attest-scp-require-kms-encryption]
  → crosswalk entry for 3.13.11: scps: [attest-scp-require-kms-encryption]
  → one SCP applied to org satisfies both controls
```

### Confirmed overlap (HIPAA + NIST 800-171 R2)

7 of HIPAA's 8 structural controls share enforcement with NIST 800-171:

| Shared SCP | NIST 800-171 control | HIPAA control |
|---|---|---|
| scp-require-mfa | 3.1.1, 3.5.3 | §164.312(a)(1) |
| scp-deny-admin-star | 3.1.2 | §164.308(a)(3) |
| scp-require-kms-encryption | 3.13.11 | §164.312(a)(2)(iv) |
| scp-require-fips-endpoints | 3.13.11 | §164.312(e)(1) |
| scp-protect-cloudtrail | 3.3.1 | §164.312(b) |
| scp-protect-audit-logs | 3.3.8 | §164.312(b) |
| scp-mfa-privileged | 3.5.3 | §164.312(d) |

Only **1 new SCP** is needed for HIPAA when NIST 800-171 is already active.

---

## The HIPAA + CMMC + ITAR scenario

For a defense-contracted genomics lab with clinical data and export-controlled
research (a real scenario at several national labs and R1s):

```
Active frameworks: [nist-800-171-r2, hipaa, itar]
```

**What attest compiles:**
- 27 SCPs (26 from NIST + 1 new for HIPAA + 1 new for ITAR region restriction)
  minus: ITAR's region SCP replaces NIST's region SCP (conflict resolution)
  actual result: ~27 SCPs, of which ~24 are shared across all three frameworks
- Framework-specific Cedar policies:
  - NIST: cedar-cui-data-movement (evaluates cui_training_current)
  - HIPAA: cedar-hipaa-authorized-principals (evaluates hipaa_training_current)
  - ITAR: cedar-itar-us-person (evaluates us_person)
- 156 crosswalk entries (110 NIST + 23 HIPAA + 2 ITAR = fewer due to aws_covered overlap)

**What the researcher experiences:**
- Cannot create resources in commercial regions (ITAR SCP — most restrictive)
- Cannot access CUI data without current CUI training (Cedar)
- Cannot access PHI without current HIPAA training (Cedar)
- Cannot access ITAR technical data if not a US person (Cedar)
- All access logged (shared CloudTrail Config rules)

---

## Region restriction conflicts

This is the most common cross-framework conflict. ITAR overrides NIST 800-171:

| Framework | Allowed regions |
|---|---|
| NIST 800-171 | us-east-1, us-west-2, us-gov-west-1 |
| HIPAA | No restriction (runs in commercial) |
| ITAR | us-gov-west-1, us-gov-east-1 **only** |

**Resolution**: When ITAR is active, the ITAR region SCP (`GovCloud only`) is compiled
and the NIST region SCP is suppressed. An org with ITAR active is GovCloud-only for
all workloads — there's no way to have some accounts ITAR-restricted and others not
in the same organization.

**Practical implication**: ITAR research environments are typically separate
AWS Organizations in GovCloud. The HIPAA/CUI commercial org and the ITAR GovCloud
org are managed separately. Attest handles both; run `attest init` once per org.

---

## Per-framework posture

When multiple frameworks are active, `attest scan` shows per-framework scores:

```
$ attest scan

Scanning SRE posture: o-mru2026
  Environments: 5
  Frameworks: NIST SP 800-171 R2, HIPAA Security Rule

NIST SP 800-171 R2:  487/550 (88.5%) — Assessment Ready
  Enforced: 94  Partial: 12  Gaps: 4

HIPAA Security Rule:  92.1% — Compliant
  Enforced: 18  Partial: 4  Not applicable: 1

Combined: 133 controls across 2 frameworks
  Shared SCPs: 7 (enforced once, satisfy both frameworks)
```

Per-framework SSP generation:

```bash
attest generate ssp --framework nist-800-171-r2
# → .attest/documents/ssp-nist-800-171-r2.md
#   Cites shared SCPs as "also satisfying HIPAA §164.312(a)(2)(iv)"

attest generate ssp --framework hipaa
# → .attest/documents/ssp-hipaa.md
#   Cites shared SCPs as "also satisfying NIST 800-171 §3.13.11"

attest generate ssp --all
# → One SSP per active framework
```

---

## Cross-framework control mapping

For organizations pursuing multiple certifications (ISO 27001 + CMMC, or
FedRAMP + HIPAA), a crosswalk mapping file allows inherited enforcement:

```yaml
# crosswalk-mappings/iso27001-to-nist800171.yaml
source_framework: iso27001-2022
target_framework: nist-800-171-r2

mappings:
  - source_id: "A.8.24"     # ISO 27001: Use of cryptography
    target_ids: ["3.13.11"] # NIST: FIPS-validated cryptography
    relationship: "equivalent"
    note: "scp-require-kms-encryption satisfies both"
```

When ISO 27001 is active alongside NIST 800-171, the ISO controls inherit the
enforcement artifacts from mapped NIST controls. The marginal cost of ISO 27001
certification drops substantially when CMMC work is already done.

See: [Cross-framework mapping issue #54](https://github.com/provabl/attest/issues/54)

---

## Known gaps

1. **CrosswalkEntry missing framework_id** (issue #60): Can't split posture by framework
   without it. Fix: add `framework_id` field to `CrosswalkEntry` schema.

2. **SSP generator is single-framework** (issue #60): `attest generate ssp` uses the
   first active framework. Fix: `--framework` flag and per-framework SSP generation.

3. **Shared artifact attribution** (issue #60): The SSP for NIST 800-171 §3.13.11
   should note that the same SCP satisfies HIPAA §164.312(a)(2)(iv). Fix: crosswalk
   entries reference sibling entries from other frameworks.

4. **Conflict detection** (issue #62): Region restriction conflicts and access control
   contradictions should be detected at compile time and surfaced explicitly, not
   silently resolved.

All tracked in v1.0.0 milestone.

---

## See also

- [Principal attribute resolution](./principal-attributes.md)
- [ITAR framework](../frameworks/itar.md)
- [Ark integration](../integrations/ark.md)
- [Issue #60: Multi-framework posture gaps](https://github.com/provabl/attest/issues/60)
- [Issue #61: ITAR framework](https://github.com/provabl/attest/issues/61)
- [Issue #62: Conflict detection](https://github.com/provabl/attest/issues/62) (note: renumbered from earlier)
