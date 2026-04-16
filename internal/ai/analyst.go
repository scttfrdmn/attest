// Package ai implements AI-powered compliance capabilities using
// AWS Bedrock with Claude. The AI never generates compliance facts —
// it reasons over facts the deterministic system has already validated.
//
// Model routing (selectModel):
//   - Opus 4.6:   analyst agent, audit simulation, NL→Cedar, framework impact
//   - Sonnet 4.6: remediation synthesis, artifact extraction, anomaly detection
//   - Haiku 4.5:  simple queries, dashboard summaries, status checks
//
// Trust model: Bedrock Guardrail requires grounding score ≥ 0.8 (when ARN is set).
// Guardrail note: Guardrails cannot be combined with Tool Use in the same API call
// (AWS limitation). Apply Guardrail on non-tool calls; tool calls use no Guardrail.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"gopkg.in/yaml.v3"

	"github.com/provabl/attest/pkg/schema"
)

// Capability identifies which AI feature is being invoked (drives model selection).
type Capability string

const (
	CapabilityAnalystAgent    Capability = "analyst_agent"
	CapabilityAuditSim        Capability = "audit_sim"
	CapabilityNLToCedar       Capability = "nl_to_cedar"
	CapabilityFrameworkImpact Capability = "framework_impact"
	CapabilityRemediation     Capability = "remediation"
	CapabilityArtifact        Capability = "artifact_extraction"
	CapabilityAnomaly         Capability = "anomaly_detection"
	CapabilitySimpleQuery     Capability = "simple_query"
)

// selectModel maps capabilities to the appropriate Claude model via Bedrock.
func selectModel(cap Capability) string {
	switch cap {
	case CapabilityAnalystAgent, CapabilityAuditSim, CapabilityNLToCedar, CapabilityFrameworkImpact:
		return "us.anthropic.claude-opus-4-6-v1"
	case CapabilityRemediation, CapabilityArtifact, CapabilityAnomaly:
		return "us.anthropic.claude-sonnet-4-6"
	default: // simple_query, status, dashboard
		return "us.anthropic.claude-haiku-4-5-20251001-v1:0"
	}
}

// Analyst is the AI compliance analyst backed by AWS Bedrock.
type Analyst struct {
	bedrock      *bedrockruntime.Client
	guardrailARN string // from env ATTEST_GUARDRAIL_ARN (optional)
	guardrailVer string
	region       string
}

// NewAnalyst creates an AI analyst backed by real AWS Bedrock clients.
func NewAnalyst(ctx context.Context, region string) (*Analyst, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &Analyst{
		bedrock:      bedrockruntime.NewFromConfig(cfg),
		guardrailARN: os.Getenv("ATTEST_GUARDRAIL_ARN"),
		guardrailVer: "DRAFT",
		region:       region,
	}, nil
}

// --- Ask ---

// Ask answers a compliance question grounded in the current SRE state.
// Uses Haiku for simple lookups, Opus for complex reasoning.
// Every claim should trace to a specific artifact (crosswalk entry, posture data).
func (a *Analyst) Ask(ctx context.Context, question string) (string, error) {
	// Build system prompt with compliance context from .attest/.
	systemPrompt := a.buildSystemPrompt()

	input := &bedrockruntime.ConverseStreamInput{
		ModelId: aws.String(selectModel(CapabilitySimpleQuery)),
		Messages: []types.Message{
			{
				Role: types.ConversationRoleUser,
				Content: []types.ContentBlock{
					&types.ContentBlockMemberText{Value: question},
				},
			},
		},
		System: []types.SystemContentBlock{
			&types.SystemContentBlockMemberText{Value: systemPrompt},
		},
	}
	if a.guardrailARN != "" {
		input.GuardrailConfig = &types.GuardrailStreamConfiguration{
			GuardrailIdentifier: aws.String(a.guardrailARN),
			GuardrailVersion:    aws.String(a.guardrailVer),
		}
	}

	return a.streamConverse(ctx, input)
}

// --- IngestDocument ---

// IngestFinding is a control coverage finding from a document.
type IngestFinding struct {
	ControlID   string              // e.g., "3.2.1"
	FrameworkID string              // e.g., "nist-800-171-r2"
	Status      string              // "covered", "partial", "not_found"
	Evidence    string              // exact quote or section reference
	DraftAtt    *schema.Attestation // nil if confidence too low to draft
}

// IngestDocument reads a compliance document and maps its content to framework controls.
// Uses Sonnet for structured extraction. Returns findings with evidence citations.
func (a *Analyst) IngestDocument(ctx context.Context, docPath string, activeFrameworks []string) ([]IngestFinding, error) {
	content, err := os.ReadFile(docPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", docPath, err)
	}

	// Load framework controls for context.
	frameworkContext := a.loadFrameworkContext(activeFrameworks)

	systemPrompt := fmt.Sprintf(`You are a compliance analyst mapping institutional documents to compliance framework controls.

Active frameworks: %s

Your task: Read the provided document and identify which compliance controls it satisfies.

Rules:
- Only report controls where the document contains EXPLICIT evidence (direct quotes or clear references)
- For each finding, cite the exact section/quote as evidence
- Do not infer or assume — only report what is explicitly stated
- Return a JSON array of findings

JSON format:
[
  {
    "control_id": "3.2.1",
    "framework_id": "nist-800-171-r2",
    "status": "covered",
    "evidence": "Section 8.1: 'All MRU faculty, staff, and graduate students must complete the annual Security Awareness Training'"
  }
]

Status values: "covered" (explicit), "partial" (mentioned but incomplete), "not_found" (not in document)
Only include controls where you found evidence. Do not list controls with no evidence.

%s`, strings.Join(activeFrameworks, ", "), frameworkContext)

	userMsg := fmt.Sprintf("Document: %s\n\nContent:\n%s", filepath.Base(docPath), string(content))

	input := &bedrockruntime.ConverseStreamInput{
		ModelId: aws.String(selectModel(CapabilityArtifact)),
		Messages: []types.Message{
			{
				Role:    types.ConversationRoleUser,
				Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: userMsg}},
			},
		},
		System: []types.SystemContentBlock{
			&types.SystemContentBlockMemberText{Value: systemPrompt},
		},
	}
	if a.guardrailARN != "" {
		input.GuardrailConfig = &types.GuardrailStreamConfiguration{
			GuardrailIdentifier: aws.String(a.guardrailARN),
			GuardrailVersion:    aws.String(a.guardrailVer),
		}
	}

	rawJSON, err := a.streamConverse(ctx, input)
	if err != nil {
		return nil, err
	}

	// Parse JSON array from response (may have surrounding text).
	jsonStr := extractJSON(rawJSON)
	var raw []struct {
		ControlID   string `json:"control_id"`
		FrameworkID string `json:"framework_id"`
		Status      string `json:"status"`
		Evidence    string `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("parsing findings JSON: %w\nRaw: %s", err, rawJSON)
	}

	var findings []IngestFinding
	for _, r := range raw {
		finding := IngestFinding{
			ControlID:   r.ControlID,
			FrameworkID: r.FrameworkID,
			Status:      r.Status,
			Evidence:    r.Evidence,
		}

		// Create draft attestation for "covered" findings.
		if r.Status == "covered" && r.ControlID != "" {
			finding.DraftAtt = &schema.Attestation{
				ID:           fmt.Sprintf("ATT-DRAFT-%s-%s", r.ControlID, time.Now().Format("20060102")),
				ControlID:    r.ControlID,
				Title:        fmt.Sprintf("%s — from %s", r.ControlID, filepath.Base(docPath)),
				EvidenceRef:  fmt.Sprintf("%s: %s", filepath.Base(docPath), r.Evidence),
				EvidenceType: "policy_doc",
				Status:       "draft",
			}
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// --- Onboard ---

// OnboardMode controls the onboarding flow type.
type OnboardMode string

const (
	OnboardGreenfield  OnboardMode = "greenfield"
	OnboardLegacy      OnboardMode = "legacy"
	OnboardCheckpoint  OnboardMode = "checkpoint"
)

// OnboardPlan is the output of the onboarding analysis.
type OnboardPlan struct {
	Mode          OnboardMode
	Summary       string
	PriorityItems []OnboardItem
	GeneratedAt   time.Time
}

// OnboardItem is a single action in the onboarding plan.
type OnboardItem struct {
	ControlID   string
	Priority    string // "critical", "high", "moderate"
	Title       string
	Reason      string
	NextStep    string
}

// Onboard produces a prioritized action plan for onboarding.
// Greenfield: reads current posture gaps and prioritizes admin control work.
// Legacy: accepts a docs directory and maps existing documents to controls.
func (a *Analyst) Onboard(ctx context.Context, mode OnboardMode, docsDir string) (*OnboardPlan, error) {
	var systemPrompt, userMsg string

	switch mode {
	case OnboardGreenfield:
		postureSummary := a.loadPostureSummary()
		systemPrompt = `You are helping an organization get compliant from scratch.
Read the current posture and identify the highest-priority administrative controls to implement.
Focus on controls whose Cedar policies have admin_dependencies (training, screening) that block technical enforcement.
Return a JSON object with: summary (string), priority_items (array of {control_id, priority, title, reason, next_step}).
Be specific and actionable. Cite actual posture data.`
		userMsg = fmt.Sprintf("Current posture:\n%s\n\nWhat should this organization prioritize to get compliance-ready?", postureSummary)

	case OnboardLegacy:
		systemPrompt = `You are helping an organization discover what compliance coverage they already have.
They have existing policies and procedures that predate their compliance program.
Analyze the provided document list and help them understand:
1. Which controls are likely covered by existing docs
2. Which controls have no documentation
3. Priority order for filling gaps
Return a JSON object with: summary, priority_items.`
		var docList string
		if docsDir != "" {
			docList = a.listDocuments(docsDir)
		}
		userMsg = fmt.Sprintf("Available documents in %s:\n%s\n\nWhat should this organization focus on?", docsDir, docList)

	default:
		postureSummary := a.loadPostureSummary()
		systemPrompt = `You are a compliance advisor doing a checkpoint review.
Review the current posture and identify what needs attention in the next 90 days.
Focus on: expiring attestations, gaps, and upcoming review schedule obligations.
Return JSON: {summary, priority_items}.`
		userMsg = fmt.Sprintf("Current posture:\n%s\n\nWhat needs attention?", postureSummary)
	}

	input := &bedrockruntime.ConverseStreamInput{
		ModelId: aws.String(selectModel(CapabilityRemediation)),
		Messages: []types.Message{
			{
				Role:    types.ConversationRoleUser,
				Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: userMsg}},
			},
		},
		System: []types.SystemContentBlock{
			&types.SystemContentBlockMemberText{Value: systemPrompt},
		},
	}
	if a.guardrailARN != "" {
		input.GuardrailConfig = &types.GuardrailStreamConfiguration{
			GuardrailIdentifier: aws.String(a.guardrailARN),
			GuardrailVersion:    aws.String(a.guardrailVer),
		}
	}

	rawJSON, err := a.streamConverse(ctx, input)
	if err != nil {
		return nil, err
	}

	jsonStr := extractJSON(rawJSON)
	var raw struct {
		Summary       string `json:"summary"`
		PriorityItems []struct {
			ControlID string `json:"control_id"`
			Priority  string `json:"priority"`
			Title     string `json:"title"`
			Reason    string `json:"reason"`
			NextStep  string `json:"next_step"`
		} `json:"priority_items"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		// If JSON parsing fails, return raw text as summary.
		return &OnboardPlan{
			Mode:        mode,
			Summary:     rawJSON,
			GeneratedAt: time.Now(),
		}, nil
	}

	plan := &OnboardPlan{
		Mode:        mode,
		Summary:     raw.Summary,
		GeneratedAt: time.Now(),
	}
	for _, item := range raw.PriorityItems {
		plan.PriorityItems = append(plan.PriorityItems, OnboardItem{
			ControlID: item.ControlID,
			Priority:  item.Priority,
			Title:     item.Title,
			Reason:    item.Reason,
			NextStep:  item.NextStep,
		})
	}
	return plan, nil
}

// --- Streaming helper ---

// streamConverse calls ConverseStream and collects the full text response.
func (a *Analyst) streamConverse(ctx context.Context, input *bedrockruntime.ConverseStreamInput) (string, error) {
	resp, err := a.bedrock.ConverseStream(ctx, input)
	if err != nil {
		return "", fmt.Errorf("Bedrock ConverseStream: %w", err)
	}
	stream := resp.GetStream()
	defer stream.Close()

	var b strings.Builder
	for event := range stream.Reader.Events() {
		switch v := event.(type) {
		case *types.ConverseStreamOutputMemberContentBlockDelta:
			if delta, ok := v.Value.Delta.(*types.ContentBlockDeltaMemberText); ok {
				b.WriteString(delta.Value)
			}
		}
	}
	if err := stream.Reader.Err(); err != nil {
		return "", fmt.Errorf("stream error: %w", err)
	}
	return b.String(), nil
}

// --- Context builders ---

// buildSystemPrompt creates a system prompt injected with current SRE/posture context.
func (a *Analyst) buildSystemPrompt() string {
	var b strings.Builder
	b.WriteString("You are an expert compliance analyst for AWS Secure Research Environments.\n")
	b.WriteString("You have access to the organization's compliance state. Every answer must cite\n")
	b.WriteString("specific artifacts (control IDs, SCP names, attestation IDs) from the provided context.\n\n")

	// Inject SRE context if available.
	if sreData, err := os.ReadFile(filepath.Join(".attest", "sre.yaml")); err == nil {
		var sre schema.SRE
		if yaml.Unmarshal(sreData, &sre) == nil {
			b.WriteString(fmt.Sprintf("Organization: %s (%s)\n", sre.OrgID, sre.Name))
			b.WriteString(fmt.Sprintf("Environments: %d\n", len(sre.Environments)))
			if len(sre.Frameworks) > 0 {
				fwIDs := make([]string, len(sre.Frameworks))
				for i, f := range sre.Frameworks {
					fwIDs[i] = f.ID
				}
				b.WriteString(fmt.Sprintf("Active frameworks: %s\n", strings.Join(fwIDs, ", ")))
			}
		}
	}

	// Inject posture summary if available.
	b.WriteString("\n")
	b.WriteString(a.loadPostureSummary())
	return b.String()
}

// loadPostureSummary reads the most recent posture snapshot.
func (a *Analyst) loadPostureSummary() string {
	cwData, err := os.ReadFile(filepath.Join(".attest", "compiled", "crosswalk.yaml"))
	if err != nil {
		return "(no compiled crosswalk found — run 'attest compile' first)"
	}
	var cw schema.Crosswalk
	if err := yaml.Unmarshal(cwData, &cw); err != nil {
		return "(could not parse crosswalk)"
	}

	statusCounts := make(map[string]int)
	for _, e := range cw.Entries {
		statusCounts[e.Status]++
	}

	return fmt.Sprintf("Crosswalk: %d controls — enforced:%d partial:%d gap:%d aws_covered:%d (generated %s)",
		len(cw.Entries),
		statusCounts["enforced"],
		statusCounts["partial"],
		statusCounts["gap"],
		statusCounts["aws_covered"],
		cw.GeneratedAt.Format("2006-01-02"),
	)
}

// loadFrameworkContext loads framework control titles for context injection.
func (a *Analyst) loadFrameworkContext(frameworkIDs []string) string {
	var b strings.Builder
	b.WriteString("\nFramework controls:\n")
	for _, fwID := range frameworkIDs {
		data, err := os.ReadFile(filepath.Join("frameworks", fwID, "framework.yaml"))
		if err != nil {
			continue
		}
		var fw schema.Framework
		if err := yaml.Unmarshal(data, &fw); err != nil {
			continue
		}
		for _, ctrl := range fw.Controls {
			b.WriteString(fmt.Sprintf("  %s (%s): %s\n", ctrl.ID, fwID, ctrl.Title))
		}
	}
	return b.String()
}

// listDocuments returns a formatted list of document files in a directory.
func (a *Analyst) listDocuments(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Sprintf("(could not read %s: %v)", dir, err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}
	return strings.Join(files, "\n")
}

// extractJSON extracts a JSON array or object from a response that may have surrounding text.
func extractJSON(s string) string {
	// Find first [ or { and last ] or }.
	start := strings.IndexAny(s, "[{")
	if start == -1 {
		return s
	}
	// Find matching close bracket.
	open := rune(s[start])
	var close rune
	if open == '[' {
		close = ']'
	} else {
		close = '}'
	}
	depth := 0
	end := -1
	for i, r := range s[start:] {
		if r == open {
			depth++
		} else if r == close {
			depth--
			if depth == 0 {
				end = start + i + 1
				break
			}
		}
	}
	if end == -1 {
		return s[start:]
	}
	return s[start:end]
}
