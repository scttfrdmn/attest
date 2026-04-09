# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-09

### Added

- Project scaffold with CLI entry point and cobra command structure.
- Core data model (`pkg/schema`): SRE, Environment, Framework, Control,
  Crosswalk, Posture, and all enforcement/assessment types.
- CLI commands: init, scan, frameworks (list/add), compile, apply, evaluate,
  generate (ssp/poam/assess/oscal), diff, watch, version.
- AWS Artifact API client stub (`internal/artifact`): report listing, agreement
  detection, framework activation mapping, report change detection.
- AWS Organizations analyzer stub (`internal/org`): org topology, SCP inventory,
  Config rule inventory, data class resolution.
- Framework loader (`internal/framework`): YAML parsing, validation,
  cross-framework control resolution and deduplication.
- SCP compiler (`internal/compiler/scp`): generates IAM policy JSON from
  structural enforcement specs, merges cross-framework overlaps.
- Cedar policy compiler (`internal/compiler/cedar`): generates Cedar policy text
  from operational enforcement specs, builds entity schemas.
- SSP generator (`internal/document/ssp`): produces System Security Plans from
  crosswalk and Cedar evaluation data, with CMMC scoring.
- NIST SP 800-171 Rev 2 framework definition (partial: 6 controls across
  Access Control and System and Communications Protection families).
- CLAUDE.md project rules and conventions.

[Unreleased]: https://github.com/scttfrdmn/attest/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/scttfrdmn/attest/releases/tag/v0.1.0
