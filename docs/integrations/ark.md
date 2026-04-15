# Ark Integration

[Ark (AWS Research Kit)](https://github.com/scttfrdmn/ark) is a sister project that
provides progressive security training and per-researcher guardrails for institutions
running research on AWS. Attest and Ark address complementary halves of the same
compliance problem.

```
RESEARCHER LAYER          INSTITUTIONAL LAYER
     │                          │
  ARK                        ATTEST
  Per-researcher             Org-wide compliance
  Training + guardrails      Posture + documentation

  "You can't create a        "principal.cui_training_current
   CUI bucket until you       == true is required to move
   complete CUI training"     CUI data at evaluation time"
     │                          │
     └──────────┬───────────────┘
                │
        INTEGRATION POINT:
        Ark writes attest:* IAM tags
        Attest reads them via Cedar
```

---

## Why they need each other

**Without Ark**, attest's Cedar policies evaluate `principal.cui_training_current`
but that attribute is never set. Every operation is denied because the system
doesn't know training is complete. The admin-to-technical bridge is broken.

**Without attest**, Ark enforces training gates at the CLI/UI layer but those gates
can be bypassed with direct AWS API calls. No org-wide structural enforcement, no
SSP, no audit-ready compliance posture.

**Together**: Ark ensures every researcher completes training before accessing
sensitive data. Attest enforces the same requirement at the AWS API level via Cedar
policies — independently of which tool the researcher uses.

---

## How the integration works

### 1. Training completion → IAM role tags (the critical link)

When a researcher completes a compliance-relevant training module in Ark, Ark calls
the AWS IAM API to tag their assumed role with attest-readable attributes:

```
Ark: Researcher completes "CUI Fundamentals" module → certificate issued
  → aws iam tag-role \
       --role-name arn:aws:iam::123456789012:role/researcher-genomics \
       --tags Key=attest:cui-training,Value=true \
              Key=attest:cui-expiry,Value=2027-04-01
```

Attest's `SAMLSource` principal resolver (`internal/principal/resolver.go`) reads
these tags at Cedar evaluation time. The policy `cedar-cui-data-movement` immediately
starts returning ALLOW for this researcher — without any CISO action.

**Ark module → attest tag mapping:**

| Ark training module | Tag written | Attest control satisfied |
|---|---|---|
| CUI Fundamentals (CITI) | `attest:cui-training=true`, `attest:cui-expiry=YYYY-MM-DD` | NIST 800-171 §3.2.2 |
| HIPAA Privacy & Security | `attest:hipaa-training=true`, `attest:hipaa-expiry=YYYY-MM-DD` | HIPAA §164.308(a)(5) |
| Security Awareness | `attest:awareness-training=true` | NIST 800-171 §3.2.1 |
| Data Classification | `attest:data-class-training=true` | NIST 800-171 §3.2.1[a] |
| Export Control (ITAR) | `attest:us-person=true` | ITAR (set from institutional identity, not training) |

### 2. Ark certificates → attest attestation records

Ark generates cryptographically signed training certificates. These should
simultaneously create attest attestation records — eliminating the manual
`attest attest create` step for training controls:

```
Ark certificate ARK-CERT-12345 issued for researcher@mru.edu
  → Creates: .attest/attestations/ATT-2026-3.2.2-001.yaml
    id: ATT-2026-3.2.2-001
    control_id: "3.2.2"
    title: "CUI handling training — Ark certificate ARK-CERT-12345"
    affirmed_by: "Ark Training System (automated)"
    evidence_ref: "ARK-CERT-12345"
    evidence_type: "training_record"
    expires_at: "2027-04-01"
```

Result: `attest attest list` shows the control as attested. `attest generate ssp`
cites the Ark certificate as evidence for §3.2.2. No human in the loop for routine
renewals.

### 3. attest denial → Ark remediation

When Cedar denies an operation because `principal.cui_training_current = false`,
the denial message should include the Ark remediation path:

```
$ attest evaluate --principal ... --action s3:PutObject --attr "principal.cui_training_current=false"

Decision:  DENY
Policy:    cedar-cui-data-movement (NIST 800-171 §3.1.3)
Reason:    principal.cui_training_current is false
Remediate: ark learn start cui-fundamentals
           (or visit https://ark.institution.edu/training/cui-fundamentals)
```

### 4. attest calendar shows Ark training obligations

`attest calendar` lists administrative controls with review schedules. Controls
backed by Ark training display the module name and direct link:

```
$ attest calendar --window 90d

✗ 3.2.2   CUI training    NOT ATTESTED   → ark learn start cui-fundamentals
✗ 3.2.1   Security awareness NOT ATTESTED → ark learn start security-awareness
⚠ 3.2.2   hipaa-training  expiring 15d   → ark learn start hipaa-privacy-security
```

### 5. attest ai ingest --type ark

Bulk-import Ark training records as attest attestations:

```bash
attest ai ingest --type ark --endpoint https://ark.institution.edu/api \
  --token $ARK_API_TOKEN
```

Queries Ark's compliance reporting API for all completed training certificates,
maps them to framework controls, and creates attestation records for any that
don't already exist. Useful for initial setup when Ark has months of training
history that predates attest deployment.

---

## Institutional identity and the ITAR case

For ITAR-controlled research, the `us_person` attribute is sourced from
institutional identity (HR/directory system), not from training completion. Ark
reads this during researcher onboarding:

```
HR System / LDAP
  └── us_person: true (citizenship/visa status determination)
         │
         ▼
      ARK onboarding
      Reads institutional identity attribute
      Sets: attest:us-person=true on IAM role
         │
         ▼
      ATTEST SAMLSource resolver
      Reads: attest:us-person from IAM tags
      Populates: principal.us_person = true
         │
         ▼
      Cedar PDP (cedar-itar-us-person)
      ALLOW or DENY ITAR data access
```

**Critical design constraint**: The `us_person` attribute is a **boolean only** —
attest never stores the underlying immigration or citizenship status. The HR system
is authoritative. Attest evaluates the derived boolean; it never reasons about
visa types, citizenship categories, or immigration status.

For most R1 universities using Shibboleth/InCommon federation, `us_person` is already
a managed attribute in the SAML assertion release policy — maintained by HR for
existing (paper-based) ITAR compliance programs. Adding it to the IdP's attribute
release for the AWS federation requires only a configuration change, not new infrastructure.

---

## Setup guide

### Step 1: Configure Ark to write attest tags

In Ark's institutional configuration (`ark.yaml`), enable attest tag writing:

```yaml
integrations:
  attest:
    enabled: true
    tag_prefix: "attest:"
    modules:
      cui-fundamentals:
        tags:
          - key: "attest:cui-training"
            value: "true"
          - key: "attest:cui-expiry"
            value: "{{expires_at}}"
        attest_control: "3.2.2"
      hipaa-basics:
        tags:
          - key: "attest:hipaa-training"
            value: "true"
          - key: "attest:hipaa-expiry"
            value: "{{expires_at}}"
        attest_control: "164.308(a)(5)"
```

### Step 2: Configure attest SAMLSource

In `.attest/sre.yaml`, enable Ark as a principal attribute source:

```yaml
principal_sources:
  - type: saml
    tag_mappings:
      "attest:cui-training":     cui_training_current
      "attest:cui-expiry":       cui_training_expiry
      "attest:hipaa-training":   hipaa_training_current
      "attest:awareness-training": authorization_current
      "attest:us-person":        us_person
```

### Step 3: Verify the integration

```bash
# After a researcher completes CUI training in Ark:
AWS_PROFILE=aws attest evaluate \
  --principal arn:aws:iam::123456789012:role/researcher-genomics \
  --action s3:PutObject \
  --resource arn:aws:s3:::cui-data/experiment.tar.gz \
  --attr "resource.enclave_membership=true" \
  --attr "resource.encryption_type=aws:kms" \
  --attr "principal.lab_authorization=true"

# Expected: ALLOW (principal.cui_training_current resolved true from Ark tag)
```

---

## What each project owns

| Concern | Ark | Attest |
|---|---|---|
| Training content and delivery | ✓ | |
| Training gate enforcement (UI/CLI layer) | ✓ | |
| Training completion records | ✓ | |
| Certificate issuance | ✓ | |
| IAM tag writing on completion | ✓ | |
| Principal attribute resolution | | ✓ |
| Cedar policy compilation and evaluation | | ✓ |
| Org-wide SCP deployment | | ✓ |
| Compliance posture tracking | | ✓ |
| SSP / POA&M / assessment generation | | ✓ |
| Attestation records (training evidence) | shared | ✓ |

---

## See also

- [Principal attribute resolver](../architecture/principal-attributes.md)
- [ITAR framework](../frameworks/itar.md)
- [Admin-to-technical bridge](../architecture/admin-tech-bridge.md)
- [Ark repository](https://github.com/scttfrdmn/ark)
