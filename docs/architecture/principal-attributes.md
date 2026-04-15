# Principal Attribute Resolution

Cedar policies in attest evaluate contextual attributes about the requesting principal —
`principal.cui_training_current`, `principal.us_person`, `principal.irb_active`, etc.
These attributes don't come from IAM alone. They come from the institutional systems
that actually know whether a researcher is trained, screened, and authorized.

This document describes how those attributes flow from institutional systems into
Cedar policy evaluation at runtime.

---

## The chain

```
Institutional systems (authoritative sources)
  ├── HR system        → employment status, US person determination
  ├── LMS (Canvas)     → training completion, expiry dates
  ├── IRB system       → active protocols, PI authorization
  ├── LDAP/AD          → group membership, department, lab affiliation
  └── Sponsored Programs → grant status, contract requirements

         │ Read by
         ▼

Institutional IdP (Shibboleth, Okta, Azure AD)
  Aggregates attributes into SAML assertions or OIDC tokens
  Released to AWS federation endpoint when researcher assumes IAM role

         │ Translated to IAM session tags or role tags by
         ▼

Ark (AWS Research Kit) — recommended integration
  Reads IdP attributes during researcher onboarding
  Writes attest:* tags to the researcher's IAM role
  Updates tags when training is renewed or expires

         │ Read at evaluation time by
         ▼

Attest principal resolver (internal/principal/resolver.go)
  SAMLSource: reads attest:* IAM role tags
  LDAPSource: queries group membership directly (optional)
  Returns: schema.PrincipalAttributes

         │ Passed into
         ▼

Cedar PDP (ps.IsAuthorized)
  Builds cedar.EntityMap with resolved attributes
  Evaluates: principal.cui_training_current, principal.us_person, etc.
  Returns: ALLOW or DENY with policy ID
```

---

## Standard attributes

These are the attributes attest's Cedar policies evaluate. All are sourced from
institutional identity systems, not from IAM.

| Attribute | Type | Source | Set by | Controls that use it |
|---|---|---|---|---|
| `cui_training_current` | Bool | LMS (CITI) | Ark on cert issuance | 3.1.3, 3.2.2 |
| `cui_training_expiry` | Long (timestamp) | LMS | Ark on cert issuance | 3.1.3 temporal |
| `hipaa_training_current` | Bool | LMS (CITI) | Ark on cert issuance | HIPAA §164.308(a)(5) |
| `awareness_training_current` | Bool | LMS | Ark on cert issuance | 3.2.1 |
| `irb_active` | Bool | IRB system | Ark/manual | 3.1.3 temporal (event) |
| `irb_protocols` | Set\<String\> | IRB system (Cayuse/iRIS) | Resolver | 3.1.3 event constraint |
| `lab_membership` | Set\<String\> | LDAP/HR | Resolver | 3.1.2, 3.1.5 |
| `lab_authorization` | Bool | Sponsored Programs | Manual/Ark | 3.1.3, 3.1.5 |
| `us_person` | Bool | HR system | Ark on onboarding | ITAR cedar-itar-us-person |
| `admin_level` | String | LDAP group | Resolver | 3.1.5, 3.1.7 |
| `mfa_enabled` | Bool | IAM | SAMLSource from tag | 3.1.1, 3.5.3 |
| `authorization_current` | Bool | Multiple | Ark/SAMLSource | 3.1.1 |

---

## How IAM tags are used

The `SAMLSource` principal resolver reads `attest:*` tags from the researcher's
assumed IAM role. This is the recommended mechanism because:

1. IAM role tags are set once (at training completion) and persist until expired
2. They're evaluated at STS AssumeRole time — no external API call at Cedar eval time
3. They survive session expiry — the next session still has the training status

**Tag naming convention:**

| Tag key | Value | Maps to |
|---|---|---|
| `attest:cui-training` | `"true"` | `principal.cui_training_current` |
| `attest:cui-expiry` | RFC3339 date | `principal.cui_training_expiry` |
| `attest:hipaa-training` | `"true"` | `principal.hipaa_training_current` |
| `attest:hipaa-expiry` | RFC3339 date | `principal.hipaa_training_expiry` |
| `attest:awareness-training` | `"true"` | `principal.awareness_training_current` |
| `attest:us-person` | `"true"` | `principal.us_person` |
| `attest:lab-id` | lab identifier | `principal.lab_membership[0]` |
| `attest:admin-level` | `"none"` / `"env"` / `"sre"` | `principal.admin_level` |

Tags are written by Ark on training completion. They can also be set manually via
`aws iam tag-role` for institutions not yet running Ark.

---

## The us_person attribute in detail

For ITAR-controlled research, `us_person` is sourced from HR rather than training:

```
HR determination: Is this person a US person under 22 CFR §120.62?
  → yes → LDAP attribute: us_person=true
          SAML attribute: us_person=true (released by IdP)
          Ark reads at onboarding, writes: attest:us-person=true to IAM role
          Attest SAMLSource reads → principal.us_person = true
          Cedar: ALLOW ITAR data access

  → no  → No tag set
          SAMLSource returns us_person absent (defaults to false in Cedar)
          Cedar: DENY ITAR data access
```

**What attest never stores:**
- Citizenship status or country of citizenship
- Visa type, category, or expiration
- Immigration status
- Country of birth

The HR system owns the determination. Attest evaluates only the boolean. This boundary
is enforced by the `USPersonSource` implementation — it reads `attest:us-person` from
the IAM role tag (written by Ark based on the HR system's determination) and returns
`schema.PrincipalAttributes{UsPersonStatus: boolValue}`. The underlying status is
never in attest's data path.

---

## Fail-safe defaults

Cedar's `forbid-unless` pattern means **missing attributes default to deny**:

```cedar
forbid (principal, action, resource)
unless {
  principal.cui_training_current == true
};
```

If `cui_training_current` is absent (resolver couldn't read the tag, training not
completed, tag not set), the expression evaluates to false and the operation is
denied. This is the correct security posture — unknown state = deny, not allow.

The only exception is controls marked `aws_covered` in the crosswalk — those don't
require principal attribute evaluation because AWS handles them at the infrastructure
level.

---

## Adding a new attribute source

To add a new institutional system as an attribute source:

1. Implement `principal.AttributeSource` in `internal/principal/resolver.go`:

```go
type IRBSource struct {
    endpoint string // IRB system API endpoint
    apiKey   string
}

func (s *IRBSource) Name() string { return "irb" }

func (s *IRBSource) Resolve(ctx context.Context, arn string, attrs *schema.PrincipalAttributes) error {
    // Query IRB system for active protocols for this principal
    // Set attrs.IRBProtocols = []string{...}
    // Never return error for "not found" — return empty slice (→ deny in Cedar)
    return nil
}
```

2. Register the source when creating the resolver:

```go
resolver := principal.NewResolver(
    principal.NewSAMLSource(ctx, region),
    &IRBSource{endpoint: "https://irb.institution.edu/api"},
)
```

3. Update the framework YAML for controls that depend on the new attribute:

```yaml
operational:
  - id: "cedar-irb-data-access"
    entities: ["principal", "dataset"]
    attributes:
      principal: ["irb_active", "irb_protocols"]
    admin_dependencies:
      - control_id: "3.1.3"
        attribute: "principal.irb_active"
        consequence: "IRB protocol must be active for data access"
```

---

## See also

- [Ark integration](../integrations/ark.md) — recommended system for writing training
  attributes to IAM roles
- [ITAR framework](../frameworks/itar.md) — us_person attribute and GovCloud
- [Multi-framework overlap](../architecture/multi-framework.md)
- `internal/principal/resolver.go` — implementation
- `pkg/schema/types.go` — `PrincipalAttributes` struct definition
