# Attest — Project Rules

## Overview

Attest is a compliance compiler for AWS Secure Research Environments (SREs).
It reads compliance frameworks, maps controls to deployable policy artifacts
(SCPs, Cedar policies, Config rules), and generates audit documents from the
live state of an AWS Organization.

## Versioning

- Follow [Semantic Versioning 2.0.0](https://semver.org/).
- Tag releases as `vMAJOR.MINOR.PATCH` (e.g., `v0.2.0`).
- Pre-1.0: MINOR increments may include breaking changes; PATCH is bug fixes only.
- The canonical version lives in `cmd/attest/main.go` (`var version`).
- Every tagged release must have a corresponding CHANGELOG.md entry.

## Changelog

- Follow [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
- All notable changes go under `## [Unreleased]` during development.
- On release, move Unreleased items to a dated `## [x.y.z] - YYYY-MM-DD` section.
- Use the categories: Added, Changed, Deprecated, Removed, Fixed, Security.
- Every PR must update CHANGELOG.md if it changes user-facing behavior.

## Project Tracking

- **All tracking is in GitHub**: milestones, issues, labels, and projects.
- Do NOT create local TODO files, task lists, or tracking documents.
- Reference issues in commit messages (e.g., `Fixes #12`, `Relates to #5`).
- Every PR should reference at least one issue.

## Go Conventions

- Go 1.24+.
- Module path: `github.com/scttfrdmn/attest`.
- Follow standard Go project layout: `cmd/`, `internal/`, `pkg/`.
- `internal/` is for packages not intended for external consumption.
- `pkg/` is for packages safe for external import (currently `schema`).
- Run `go vet ./...` and `go test ./...` before committing.
- No `init()` functions. No global mutable state.
- Errors are returned, not logged-and-continued. Use `fmt.Errorf("context: %w", err)`.
- Prefer table-driven tests.

## Architecture

```
Artifact API --> Framework Parser
Org API      --> Org Analyzer
                    |
              Control Gap Analysis
                    |
         +----------+----------+
         v          v          v
    SCP Compiler Cedar Comp  Config Comp
         |          |          |
         v          v          v
    Crosswalk Manifest (control -> artifact)
                    |
         +----------+----------+
         v          v          v
     Deploy     Evaluate    Generate Docs
```

### Key packages

- `cmd/attest/` — CLI entry point (cobra).
- `internal/artifact/` — AWS Artifact API client (reports, agreements).
- `internal/org/` — AWS Organizations analyzer (topology, existing SCPs).
- `internal/framework/` — Framework loader, validator, cross-framework resolver.
- `internal/compiler/scp/` — SCP compiler (structural enforcement).
- `internal/compiler/cedar/` — Cedar policy compiler (operational enforcement).
- `internal/document/ssp/` — SSP generator (and future POA&M, OSCAL).
- `pkg/schema/` — Core data model (SRE, Framework, Control, Crosswalk, Posture).

## Domain Concepts

- **SRE**: An AWS Organization configured as a compliance enclave.
- **Environment**: An AWS account within the SRE. Inherits org-level controls.
- **Framework**: A compliance standard (NIST 800-171, HIPAA, etc.) as YAML.
- **Crosswalk**: The mapping from framework controls to deployed artifacts.
- **Posture**: Computed compliance state — enforced, partial, gap, aws_covered.

## Frameworks

- Defined as YAML in `frameworks/<id>/framework.yaml`.
- Each control specifies: responsibility split, structural/operational/monitoring
  enforcement, and assessment objectives.
- The resolver deduplicates across frameworks (one SCP can satisfy multiple controls).

## Commit Messages

- Use imperative mood: "Add feature" not "Added feature".
- First line under 72 characters.
- Reference GitHub issues: `Fixes #N` or `Relates to #N`.
- Scope prefix encouraged: `artifact: add ListReports pagination`.

## Branch Strategy

- `main` is the release branch. Always in a releasable state.
- Feature branches: `feat/<short-description>` or `issue-N/<short-description>`.
- Bug fix branches: `fix/<short-description>`.
- Delete branches after merge.

## Dependencies

- AWS SDK v2 (`github.com/aws/aws-sdk-go-v2`).
- Cedar Go (`github.com/cedar-policy/cedar-go`).
- Cobra for CLI (`github.com/spf13/cobra`).
- YAML v3 (`gopkg.in/yaml.v3`).
- Lipgloss for terminal UI (`github.com/charmbracelet/lipgloss`).
- Keep dependencies minimal. Justify new additions.
