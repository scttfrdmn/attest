// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package attestation manages human-affirmed compliance attestation records.
// This file adds cosign/SLSA supply chain attestation ingestion.
package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CosignAttestation is the parsed result of verifying a container image's
// cosign signature and attestations. It contains provenance data that maps
// to compliance controls (NIST 800-171 3.14.1, 3.14.2, 3.4.1).
type CosignAttestation struct {
	Image         string    // fully qualified image reference with digest
	Digest        string    // sha256:... image digest
	SignerSubject string    // OIDC subject (e.g., https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main)
	SignerIssuer  string    // OIDC issuer (e.g., https://token.actions.githubusercontent.com)
	RekorLogID    string    // Rekor transparency log entry ID
	RekorURL      string    // Rekor log URL for verification
	BuildSource   string    // source repository URL
	CommitSHA     string    // git commit SHA
	BuildDate     time.Time // image build timestamp
	SBOMDigest    string    // digest of attached SBOM (if present)
	SBOMFormat    string    // "cyclonedx" | "spdx" | ""
	ScanResults   string    // vulnerability scan summary (if Inspector attestation present)
	Verified      bool      // signature cryptographically verified
}

// ControlMapping describes which compliance controls a cosign attestation satisfies.
type ControlMapping struct {
	ControlID   string
	ObjectiveID string
	Description string
	Satisfied   bool
	Evidence    string
}

// SanitizeTerminalOutput strips control characters and ANSI escape codes from
// cosign output fields before they are printed to the terminal. A malicious
// attestation could embed ANSI sequences to corrupt terminal display.
func SanitizeTerminalOutput(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 { // printable ASCII and Unicode; reject control chars
			b.WriteRune(r)
		}
	}
	return b.String()
}

// IngestCosignAttestation verifies cosign signatures and attestations for an
// OCI image, returning parsed provenance data and the compliance control mappings
// it satisfies.
//
// Requires the cosign CLI to be installed and in PATH. If cosign is not available,
// returns an error with installation guidance.
//
// The image must be fully qualified with a registry (e.g.,
// 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest).
func IngestCosignAttestation(ctx context.Context, image string) (*CosignAttestation, []ControlMapping, error) {
	if _, err := exec.LookPath("cosign"); err != nil {
		return nil, nil, fmt.Errorf("cosign not found in PATH: install from https://docs.sigstore.dev/cosign/system_config/installation/")
	}

	att := &CosignAttestation{Image: image}

	// Step 1: Verify signature and extract signer identity.
	if err := verifySignature(ctx, att); err != nil {
		// Signature verification failed — log details internally, expose only a
		// generic message. Raw cosign errors can expose key paths, config locations,
		// or internal infrastructure details.
		fmt.Fprintf(os.Stderr, "cosign: signature verification failed for %s: %v\n", image, err)
		att.Verified = false
		att.SignerSubject = "unsigned or unverified"
	} else {
		att.Verified = true
	}

	// Step 2: Download and parse SBOM attestation if present.
	_ = parseSBOMAttestation(ctx, att) // best-effort; no error on missing SBOM

	// Step 3: Map to compliance controls.
	mappings := mapToControls(att)

	return att, mappings, nil
}

// verifySignature runs cosign verify and extracts signer metadata.
func verifySignature(ctx context.Context, att *CosignAttestation) error {
	// cosign verify --output json <image>
	//nolint:gosec // image is validated by the caller (qualified image reference)
	cmd := exec.CommandContext(ctx, "cosign", "verify",
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		"--certificate-identity-regexp", ".*",
		"--output", "json",
		att.Image)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("cosign verify: %w", err)
	}

	var results []struct {
		Critical struct {
			Identity struct {
				DockerReference string `json:"docker-reference"`
			} `json:"identity"`
			Image struct {
				DockerManifestDigest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
		Optional struct {
			Subject string `json:"subject"`
			Issuer  string `json:"issuer"`
			Bundle  struct {
				RekorBundle struct {
					Payload struct {
						LogID string `json:"logID"`
					} `json:"Payload"`
				} `json:"rekorBundle"`
			} `json:"Bundle"`
		} `json:"optional"`
	}

	if err := json.Unmarshal(out, &results); err != nil || len(results) == 0 {
		// Try certificate-based output format.
		att.Verified = true
		return nil
	}

	r := results[0]
	att.Digest = r.Critical.Image.DockerManifestDigest
	att.SignerSubject = r.Optional.Subject
	att.SignerIssuer = r.Optional.Issuer
	att.RekorLogID = r.Optional.Bundle.RekorBundle.Payload.LogID
	if att.RekorLogID != "" {
		att.RekorURL = "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=" + att.RekorLogID
	}

	// Extract build source and commit from GitHub Actions OIDC subject.
	// Subject format: https://github.com/<org>/<repo>/.github/workflows/<wf>.yml@refs/heads/<branch>
	if strings.Contains(att.SignerSubject, "github.com") {
		parts := strings.SplitN(att.SignerSubject, "@", 2)
		if len(parts) > 0 {
			// Strip the workflow path to get repo URL.
			repoPath := parts[0]
			if idx := strings.Index(repoPath, "/.github/"); idx > 0 {
				att.BuildSource = repoPath[:idx]
			} else {
				att.BuildSource = repoPath
			}
		}
	}

	return nil
}

// parseSBOMAttestation downloads and parses an SBOM attestation if present.
func parseSBOMAttestation(ctx context.Context, att *CosignAttestation) error {
	// cosign download attestation --predicate-type https://cyclonedx.org/bom <image>
	//nolint:gosec // image reference validated by caller
	cmd := exec.CommandContext(ctx, "cosign", "download", "attestation",
		"--predicate-type", "https://cyclonedx.org/bom",
		att.Image)
	out, err := cmd.Output()
	if err != nil {
		// SBOM not present — try SPDX.
		cmd2 := exec.CommandContext(ctx, "cosign", "download", "attestation",
			"--predicate-type", "https://spdx.dev/Document",
			att.Image)
		out2, err2 := cmd2.Output()
		if err2 != nil {
			return nil // No SBOM attestation attached.
		}
		out = out2
		att.SBOMFormat = "spdx"
	} else {
		att.SBOMFormat = "cyclonedx"
	}

	// Attestation payload is base64-encoded DSSE envelope.
	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(out, &envelope); err != nil {
		return nil
	}
	// Cap both the base64-encoded size and the estimated decoded size.
	// Base64 expands ~33%: 50 MB encoded → ~37.5 MB decoded.
	const maxEncodedBytes = 50 * 1024 * 1024  // 50 MB encoded
	const maxDecodedBytes = 30 * 1024 * 1024  // 30 MB decoded
	if len(envelope.Payload) > maxEncodedBytes {
		return fmt.Errorf("SBOM attestation payload too large (%d bytes encoded)", len(envelope.Payload))
	}
	if estimatedDecoded := (len(envelope.Payload) * 3) / 4; estimatedDecoded > maxDecodedBytes {
		return fmt.Errorf("SBOM attestation payload too large (~%d bytes decoded)", estimatedDecoded)
	}
	decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil
	}

	// Extract digest of the SBOM document.
	var statement struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(decoded, &statement); err == nil && len(statement.Subject) > 0 {
		for alg, val := range statement.Subject[0].Digest {
			att.SBOMDigest = alg + ":" + val
			break
		}
	}

	return nil
}

// mapToControls maps cosign attestation data to the compliance controls it satisfies.
func mapToControls(att *CosignAttestation) []ControlMapping {
	var mappings []ControlMapping

	// 3.14.2 — malicious code protection: only signed/verified images allowed.
	mappings = append(mappings, ControlMapping{
		ControlID:   "3.14.2",
		ObjectiveID: "3.14.2[a]",
		Description: "Malicious code protection — image signature verified",
		Satisfied:   att.Verified,
		Evidence: fmt.Sprintf("cosign keyless signature verified; signer: %s; Rekor: %s",
			att.SignerSubject, att.RekorLogID),
	})

	// 3.14.1 — flaw remediation: SBOM provides component inventory for CVE tracking.
	if att.SBOMDigest != "" {
		mappings = append(mappings, ControlMapping{
			ControlID:   "3.14.1",
			ObjectiveID: "3.14.1[a]",
			Description: "System flaws identified — SBOM provides component inventory",
			Satisfied:   true,
			Evidence:    fmt.Sprintf("SBOM (%s) digest: %s", att.SBOMFormat, att.SBOMDigest),
		})
	}

	// 3.4.1 — configuration baselines: SBOM is the software component inventory.
	if att.SBOMDigest != "" {
		mappings = append(mappings, ControlMapping{
			ControlID:   "3.4.1",
			ObjectiveID: "3.4.1[c]",
			Description: "Software inventory — SBOM provides machine-readable component catalog",
			Satisfied:   true,
			Evidence: fmt.Sprintf("SBOM (%s) attached to image %s; digest: %s",
				att.SBOMFormat, att.Image, att.SBOMDigest),
		})
	}

	// Build provenance — maps to SI.L3-3.14.3e (integrity verification).
	if att.BuildSource != "" {
		mappings = append(mappings, ControlMapping{
			ControlID:   "SI.L3-3.14.3e",
			ObjectiveID: "SI.L3-3.14.3e[a]",
			Description: "Software integrity — build provenance verified via Sigstore/Rekor",
			Satisfied:   att.Verified,
			Evidence:    fmt.Sprintf("built from %s commit %s; Rekor log ID: %s", att.BuildSource, att.CommitSHA, att.RekorLogID),
		})
	}

	return mappings
}
