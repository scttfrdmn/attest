# Rollback and State Management

## Current behavior (v0.7.x)

`attest apply` deploys SCPs to your AWS Organization and records the deployment in the
local `.attest/` git store. It does **not** automatically create a tagged checkpoint
before deploying.

This means there is no single `attest rollback` command today. Rollback is a manual
operation (described below). Both automatic checkpointing (#69) and a `attest rollback`
command (#70) are planned for v0.8.0.

---

## State storage

After each `attest apply`, the tool commits the compiled artifact state to a bare git
repository at `.attest/.git`. This gives you a history of what was compiled and when,
but it tracks artifact *content* only — not what is currently deployed in AWS.

```bash
# View apply history
git -C .attest log --oneline

# See what changed in the last apply
git -C .attest show HEAD
```

---

## Creating a manual checkpoint

Before any `attest apply` you want to be able to undo, tag the current state:

```bash
# Tag the current compiled state with a human-readable name
git -C .attest tag -a "before-iso27001" -m "Before adding ISO 27001 framework"

# Or with a timestamp
git -C .attest tag -a "checkpoint-$(date +%Y%m%d-%H%M)" -m "Pre-apply checkpoint"
```

List existing checkpoints:

```bash
git -C .attest tag -l
```

> **Note**: Creating a checkpoint before every apply will be automatic in v0.8.0 (#69).

---

## Rolling back manually

Rollback means: detach the SCPs attest deployed, then optionally delete them.

### Step 1 — Identify deployed attest SCPs

```bash
# Find the org root ID
aws organizations list-roots --query 'Roots[0].Id' --output text

# List SCPs attached to the root
aws organizations list-policies-for-target \
  --target-id r-xxxx \
  --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[?starts_with(Name, `attest-`)].[Id,Name]' \
  --output table
```

### Step 2 — Detach each attest SCP

```bash
# For each attest-* policy ID from step 1:
aws organizations detach-policy \
  --policy-id p-xxxxxxxxxx \
  --target-id r-xxxx
```

### Step 3 — Delete the SCP documents (optional)

Detaching removes enforcement; the policy document still exists in the org. To clean up
entirely:

```bash
aws organizations delete-policy --policy-id p-xxxxxxxxxx
```

> **Caution**: Deleting a policy is irreversible. If you may re-apply the same SCPs,
> detach without deleting — re-attaching an existing policy is faster than re-creating it.

---

## Re-applying a previous state

If you want to restore a specific earlier deployment rather than removing controls
entirely:

```bash
# Check out the compiled state from a tagged checkpoint
git -C .attest checkout before-iso27001

# Re-apply — this will update AWS to match the checked-out artifacts
AWS_PROFILE=your-profile attest apply --approve --region us-east-1

# Return .attest to HEAD
git -C .attest checkout main
```

---

## Terraform output as an alternative

If you compiled with `--output terraform`, Terraform state gives you a clean
plan/apply/destroy cycle:

```bash
attest compile --output terraform
cd .attest/terraform

# Preview removal
terraform plan -destroy

# Remove all attest-managed SCPs
terraform destroy
```

This is the most auditable rollback path when Terraform state is maintained.

---

## What's coming in v0.8.0

| Feature | Issue | Description |
|---|---|---|
| Auto-tag before apply | [#69](https://github.com/provabl/attest/issues/69) | Every `attest apply` creates a git tag before deploying |
| `attest rollback` command | [#70](https://github.com/provabl/attest/issues/70) | One-command rollback to any tagged checkpoint |

Once #69 lands, every apply will produce a tag like `applied-20260415-143200`, and
`attest rollback applied-20260415-143200` will detach the current SCPs and re-apply
the state from that checkpoint — no AWS CLI required.
