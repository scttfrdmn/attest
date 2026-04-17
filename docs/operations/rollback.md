# Rollback and State Management

## Current behavior (v0.8.x)

`attest apply` automatically creates a snapshot tag (`applied-YYYYMMDD-HHMMSS`) in the
`.attest/` git store before every deployment. `attest rollback` undoes the last apply
or restores to any named snapshot. Both features are available since v0.8.0.

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

## Automatic snapshots

Every `attest apply` creates a snapshot automatically before deploying:

```
  Snapshot: applied-20260416-143022
  Applying...
```

To list all snapshots:

```bash
attest rollback --list
# → applied-20260416-143022
#   applied-20260415-091533
#   before-iso27001
```

## Creating a manual checkpoint

You can also create named checkpoints at any time:

```bash
# Tag the current compiled state with a human-readable name
git -C .attest tag -a "before-iso27001" -m "Before adding ISO 27001 framework"

# Or with a timestamp
git -C .attest tag -a "checkpoint-$(date +%Y%m%d-%H%M)" -m "Pre-apply checkpoint"
```

### Snapshot naming rules

Tag names must match `[a-zA-Z0-9._/-]+`:
- Allowed: letters, digits, `.` `-` `_` `/`
- Not allowed: spaces, `..`, `;`, `&`, `|`, `$`, backticks, newlines, or any shell metacharacters
- Max length: 255 characters

attest auto-generates `applied-YYYYMMDD-HHMMSS` which is always valid.

If you pass an invalid name to `attest rollback --to`, you will see:
```
Error: invalid ref: ref "my tag;evil" contains unsafe characters
```

---

## Rolling back with `attest rollback`

Roll back to the most recent snapshot:

```bash
AWS_PROFILE=sre attest rollback --approve --region us-east-1
```

Roll back to a specific snapshot:

```bash
AWS_PROFILE=sre attest rollback --to before-iso27001 --approve --region us-east-1
```

This:
1. Detaches all `attest-*` SCPs from the org root
2. Checks out compiled artifacts from the target snapshot
3. Re-applies the checkpoint state

## Rolling back manually

If `attest rollback` is unavailable, rollback means: detach the SCPs attest deployed,
then optionally delete them.

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

## Changelog

| Version | Change |
|---|---|
| v0.8.0 | `attest apply` auto-creates snapshot; `attest rollback` command added (#69, #70) |
| v0.8.1 | Snapshot name validation: rejects unsafe characters to prevent git ref injection |
