# The Admin-to-Technical Bridge

## The problem nobody has solved

Most institutions doing compliance work today have two completely separate tracks:

**Track 1: Technical controls.** SCPs, Config rules, security groups. The cloud team
deploys them. The CISO signs off. They work until someone misconfigures something
or a rule lapses.

**Track 2: Administrative controls.** Training programs, risk assessments, incident
response plans, personnel screening. The compliance office manages them. They're
documented in SharePoint. They get renewed annually in paper form. Nobody checks
whether the training that's "complete on paper" actually matches who has access to
what system.

The **admin-to-technical bridge** is the missing connection: the administrative
work you've done should directly influence what the technical controls permit.

---

## The honest state of compliance today

Most R1 universities and research institutions doing CUI, HIPAA, or ITAR compliance
are operating on the honor system:

- The PI signs a form saying their lab members completed CUI training
- The assessor says "okay" and marks the control as satisfied
- Meanwhile, researchers are using AWS accounts with full S3 access to move data
  in ways that would violate NIST 800-171 §3.1.3 if anyone checked

Nobody is checking at the API level. Nobody connects "this person's CUI training
expired in March" to "this person's S3 PutObject call should be denied in April."
The technical controls don't know about the administrative state.

This is not a judgment — it's a structural problem. The systems that track training
(an LMS) and the systems that enforce access (IAM, SCPs) have never been connected.
Attest builds that connection.

---

## How attest closes the gap

Cedar policies in attest evaluate principal attributes that come from institutional
systems — not just IAM. When a researcher attempts to copy CUI data:

```
Request: s3:PutObject, arn:aws:s3:::cui-enclave/data.tar.gz
  
Cedar evaluation:
  principal.cui_training_current = ?
    ← reads from IAM role tag attest:cui-training
    ← tag set by Ark when CITI certificate was issued
    ← CITI certificate issued when LMS confirmed completion
    ← LMS updated by CITI Program on course completion
  
  If tag missing or expired: DENY
  If present and not expired: continue evaluation
  → also check resource.enclave_membership, resource.encryption_type, etc.
  → all conditions met: ALLOW
```

The chain from LMS → CITI → Ark → IAM tag → Cedar evaluation is the bridge.
When it's built, "training expired" automatically degrades access. Not in the next
audit. Not when the compliance officer notices. At the next API call.

---

## Why this matters for assessors

When a CMMC C3PAO, a HIPAA auditor, or an IRB reviewing your data governance asks
"how do you ensure that only trained personnel access CUI data?" — the current answer
is usually "we have a policy and a training program." The assessor circles "Implemented"
and moves on.

The attest answer is: "Here is the Cedar policy text. Here is the CloudTrail log of
every S3 operation in the past 90 days. Every ALLOW decision required
`principal.cui_training_current = true`, which is sourced from the CITI training
completion record in our LMS via IAM role tag. Here is the training completion
certificate for each authorized user."

That's an audit artifact, not a promise. It's the difference between "we attest that
we comply" and "here is the cryptographically-verifiable evidence that compliance is
enforced at runtime."

---

## The administrative controls and their technical dependencies

| Administrative control | Framework | What happens technically when it lapses |
|---|---|---|
| CUI handling training (3.2.2) | NIST 800-171 | `principal.cui_training_current = false` → Cedar denies all CUI data movement |
| HIPAA training | HIPAA §164.308(a)(5) | `principal.hipaa_training_current = false` → Cedar denies PHI access |
| Security awareness training (3.2.1) | NIST 800-171 | `principal.awareness_training_current = false` → Can be used as additional Cedar gate |
| Active IRB protocol | (institutional) | `principal.irb_active = false` → Cedar denies dataset access during inactive protocol |
| US person status | ITAR | `principal.us_person = false` → Cedar denies ITAR technical data access |
| Personnel screening (3.9.1) | NIST 800-171 | Feeds `principal.screened` — can gate SRE environment access entirely |
| IR capability test (3.6.3) | NIST 800-171 | Attestation expiry → posture degrades, noted in SSP, calendar alerts CISO |

The first four columns are **automated** via Ark + the principal resolver chain.
The last two (IR testing, personnel screening) still require human attestation — but
attest tracks their status and surfaces expiry in `attest calendar`, so the CISO
gets alerted 30 days before the obligation is due rather than discovering it during
an audit.

---

## The framework YAML captures the dependency

When writing or reviewing framework YAML, the `admin_dependencies` field on an
operational control makes the dependency explicit:

```yaml
operational:
  - id: "cedar-cui-data-movement"
    description: "CUI data movement control"
    entities: ["principal", "destination_bucket"]
    attributes:
      principal: ["cui_training_current", "lab_authorization"]
    admin_dependencies:
      - control_id: "3.2.2"
        attribute: "principal.cui_training_current"
        consequence: |
          Policy evaluates cui_training_current = false if 3.2.2 is unattested.
          All CUI data movement operations are denied until training is renewed.
```

When `attest scan` sees that `3.2.2` has no current attestation, it degrades
`cedar-cui-data-movement` from `enforced` to `partial` — even if the Cedar policy
is compiled and active. The technical control is deployed but its precondition is
not met.

---

## Implementation status

| Component | Status |
|---|---|
| `admin_dependencies` in `OperationalEnforcement` schema | ✓ Implemented (v0.5.0) |
| `review_schedule` in `Control` schema | ✓ Implemented (v0.5.0) |
| `attest attest create/list/expire` | ✓ Implemented (v0.5.0) |
| `attest calendar` | ✓ Implemented (v0.5.0) |
| Attestation status → posture degradation in `attest scan` | ✗ Planned (v1.0.0) |
| Ark tag writing on training completion | ✗ Planned (Ark v0.3.0) |
| Denial reasons link to Ark remediation | ✗ Planned (v1.0.0) |
| SSP narratives cite admin dependencies | ✗ Planned (v1.0.0) |

---

## See also

- [Principal attribute resolution](./principal-attributes.md)
- [Ark integration](../integrations/ark.md)
- [ITAR framework](../frameworks/itar.md) — us_person as an admin-sourced attribute
- [Issue #48: Admin-to-technical bridge](https://github.com/provabl/attest/issues/48)
