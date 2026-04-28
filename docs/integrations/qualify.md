# qualify ↔ attest Integration Contract

**qualify** (github.com/provabl/qualify) is the researcher training and access-gating
tool in the Provabl suite. When a researcher completes a training module in qualify,
it writes `attest:*` IAM role tags to their assumed role. attest's principal attribute
resolver reads those tags and makes them available as Cedar policy attributes.

This document is the formal contract between the two systems. Both sides must adhere
to it. Changes to the tag schema require coordination and a version bump.

---

## The Interface: IAM Role Tags

qualify writes tags. attest reads them. The interface is the AWS IAM tag API — neither
system needs to know how the other works internally.

**Direction**: qualify → IAM role tags → attest principal resolver → Cedar attributes

---

## Tag Schema

All tags use the `attest:` namespace. Tags are written to the IAM role the researcher
assumes when accessing the SRE.

### Training completion tags

| Tag key | Values | Cedar attribute | Notes |
|---|---|---|---|
| `attest:cui-training` | `"true"` / `"false"` | `principal.cui_training_current` | CUI handling (cui-fundamentals module) |
| `attest:cui-training-expiry` | RFC3339 timestamp | `principal.training_expiry` | Unix timestamp in Cedar |
| `attest:hipaa-training` | `"true"` / `"false"` | `principal.hipaa_training_current` | HIPAA privacy & security |
| `attest:hipaa-training-expiry` | RFC3339 timestamp | `principal.hipaa_training_expiry` | |
| `attest:awareness-training` | `"true"` / `"false"` | `principal.awareness_training_current` | General security awareness |
| `attest:awareness-training-expiry` | RFC3339 timestamp | `principal.awareness_training_expiry` | |
| `attest:ferpa-training` | `"true"` / `"false"` | `principal.ferpa_training_current` | FERPA basics |
| `attest:itar-training` | `"true"` / `"false"` | `principal.itar_training_current` | ITAR/EAR export controls |
| `attest:data-class-training` | `"true"` / `"false"` | `principal.data_class_training_current` | Data classification |
| `attest:research-security-training` | `"true"` / `"false"` | `principal.research_security_training_current` | NIH NOT-OD-26-017 |
| `attest:research-security-training-expiry` | RFC3339 timestamp | `principal.research_security_training_expiry` | |

### Identity tags

| Tag key | Values | Cedar attribute | Notes |
|---|---|---|---|
| `attest:lab-id` | lab identifier string | `principal.lab_membership` | Appended to LabMembership array |
| `attest:admin-level` | `"none"` / `"env"` / `"sre"` | `principal.admin_level` | Admin privilege scope |

### Value semantics

- Boolean tags: case-insensitive; `"true"` / `"True"` / `"TRUE"` all evaluate true
- Expiry timestamps: RFC3339 format (`2027-01-01T00:00:00Z`)
- Missing tags: Cedar policy attributes default to `false` for booleans, zero time for expiry
- qualify must write expiry as a separate tag when the training has a defined lifetime

### Default training lifetime

qualify uses 365 days (one year) as the default training certification period.
The expiry tag should be written at `completion_time + training_lifetime` in RFC3339 UTC.

---

## qualify Module → Tag Mapping

| qualify module ID | Tag written | Tag value |
|---|---|---|
| `cui-fundamentals` | `attest:cui-training` | `"true"` |
| `hipaa-privacy-security` | `attest:hipaa-training` | `"true"` |
| `security-awareness` | `attest:awareness-training` | `"true"` |
| `ferpa-basics` | `attest:ferpa-training` | `"true"` |
| `itar-export-control` | `attest:itar-training` | `"true"` |
| `data-classification` | `attest:data-class-training` | `"true"` |
| `nih-research-security` | `attest:research-security-training` | `"true"` |

All modules with a defined lifetime also write the corresponding `-expiry` tag.

---

## How attest Uses These Attributes

The principal resolver (`internal/principal/resolver.go`) reads these tags and
populates `schema.PrincipalAttributes`. Cedar policies in the framework YAML files
reference them as `principal.*` attributes:

```cedar
// Example: require CUI training before allowing S3 access to CUI data
forbid(principal, action, resource)
when {
  resource.data_classification == "CUI" &&
  !principal.cui_training_current
};
```

```cedar
// Example: require ITAR training for ITAR-controlled environments
permit(principal, action, resource)
when {
  principal.itar_training_current == true &&
  principal.us_person_verified == true
};
```

Cedar temporal constraints use the expiry timestamp:
```cedar
// Example: enforce training recertification (expiry)
forbid(principal, action, resource)
unless {
  context.current_time < principal.training_expiry
};
```

---

## Backward Compatibility

The legacy tag key `attest:cui-expiry` (used in early qualify versions before this
contract was formalized) is still read by attest's resolver for backward compatibility.
New deployments should use `attest:cui-training-expiry`. The legacy key will be
removed in a future major version.

---

## Decoupled Design

Neither system requires the other. attest functions without qualify — the training
attributes simply evaluate as `false` in Cedar policies, and access is controlled
by whatever other attributes are available. qualify functions without attest — training
completions are still recorded and the IAM tags are still written, they're just not
evaluated for access control until attest is deployed.

Institutions may also populate `attest:*` tags from systems other than qualify (their
own LMS, HR system, or manual tagging for pilots) and attest will read them the same way.

---

## Testing

See `internal/principal/resolver_test.go::TestSAMLSourceTagMapping` for the canonical
test that verifies the complete tag schema contract.
