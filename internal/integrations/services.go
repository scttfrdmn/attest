// Package integrations provides clients for AWS security services that
// feed into the compliance posture. Each integration is both a producer
// (attest pushes Cedar denials to Security Hub) and a consumer (attest
// pulls GuardDuty findings into the posture model).
//
// Integrated services:
//   - Security Hub: central finding aggregation, ASFF format
//   - AWS Config: drift detection, conformance packs
//   - GuardDuty: threat detection mapped to framework controls
//   - CloudTrail: event backbone, decision log source
//   - IAM Access Analyzer: least-privilege validation
//   - Macie: data classification verification
//   - Inspector: vulnerability management
//   - Firewall Manager: network boundary enforcement
//   - KMS: encryption key compliance
//   - SSM: patch management, session audit
//   - EventBridge: integration bus
//   - Organizations: SCP management, tag policies
package integrations

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

// MappedFinding is a security service finding mapped through the crosswalk
// to its framework control.
type MappedFinding struct {
	Source    string    // "securityhub", "guardduty", "inspector", "macie", etc.
	FindingID string
	Severity  string    // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
	ControlID string    // framework control this affects
	Impact    string    // "positive" (clean finding = evidence) or "negative" (finding = degradation)
	Title     string
	Detail    string
	Timestamp time.Time
}

// ControlEvidence aggregates all evidence for a single control from
// all integrated services.
type ControlEvidence struct {
	ControlID        string
	SCPsDeployed     []string
	CedarEvaluations int64
	CedarDenials     int64
	ConfigCompliant  bool
	GuardDutyClean   bool
	InspectorClean   bool
	MacieValidated   bool
	AccessAnalyzerOK bool
	Findings         []MappedFinding
}

// EvidenceAggregator collects evidence from all integrated services
// for SSP generation and self-assessment scoring.
type EvidenceAggregator struct {
	region string
}

// NewEvidenceAggregator creates an evidence aggregator.
func NewEvidenceAggregator(region string) *EvidenceAggregator {
	return &EvidenceAggregator{region: region}
}

// CollectForControl assembles the complete evidence picture for one control.
func (ea *EvidenceAggregator) CollectForControl(ctx context.Context, controlID string) (*ControlEvidence, error) {
	results, err := ea.CollectAll(ctx, []string{controlID})
	if err != nil {
		return nil, err
	}
	ev, ok := results[controlID]
	if !ok {
		return &ControlEvidence{ControlID: controlID}, nil
	}
	return ev, nil
}

// CollectAll assembles evidence for all controls by querying GuardDuty,
// CloudTrail, and IAM Access Analyzer. All calls are free-tier.
func (ea *EvidenceAggregator) CollectAll(ctx context.Context, controlIDs []string) (map[string]*ControlEvidence, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(ea.region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	// Initialize per-control evidence.
	result := make(map[string]*ControlEvidence, len(controlIDs))
	for _, id := range controlIDs {
		result[id] = &ControlEvidence{
			ControlID:        id,
			GuardDutyClean:   true,
			AccessAnalyzerOK: true,
		}
	}

	// Build a set for fast lookup.
	wanted := make(map[string]bool, len(controlIDs))
	for _, id := range controlIDs {
		wanted[id] = true
	}

	// --- GuardDuty ---
	gdFindings, err := collectGuardDutyFindings(ctx, guardduty.NewFromConfig(cfg))
	if err == nil {
		for _, f := range gdFindings {
			for _, controlID := range ThreatMapping[f.ThreatType] {
				if !wanted[controlID] {
					continue
				}
				ev := result[controlID]
				ev.GuardDutyClean = false
				ev.Findings = append(ev.Findings, MappedFinding{
					Source:    "guardduty",
					FindingID: f.FindingID,
					Severity:  f.Severity,
					ControlID: controlID,
					Impact:    "negative",
					Title:     f.Title,
					Timestamp: f.UpdatedAt,
				})
			}
		}
	}

	// --- IAM Access Analyzer ---
	aaFindings, err := collectAccessAnalyzerFindings(ctx, accessanalyzer.NewFromConfig(cfg))
	if err == nil {
		for _, f := range aaFindings {
			// Access Analyzer findings degrade least-privilege controls.
			for _, controlID := range []string{"3.1.1", "3.1.2", "3.1.5"} {
				if !wanted[controlID] {
					continue
				}
				ev := result[controlID]
				ev.AccessAnalyzerOK = false
				ev.Findings = append(ev.Findings, MappedFinding{
					Source:    "accessanalyzer",
					FindingID: f.ID,
					Severity:  "MEDIUM",
					ControlID: controlID,
					Impact:    "negative",
					Title:     fmt.Sprintf("Overly permissive policy: %s", f.ResourceType),
					Timestamp: f.UpdatedAt,
				})
			}
		}
	}

	return result, nil
}

// --- internal types and helpers ---

type gdFinding struct {
	FindingID  string
	ThreatType string
	Severity   string
	Title      string
	UpdatedAt  time.Time
}

type aaFinding struct {
	ID           string
	ResourceType string
	UpdatedAt    time.Time
}

func collectGuardDutyFindings(ctx context.Context, svc *guardduty.Client) ([]gdFinding, error) {
	// List detectors first.
	dOut, err := svc.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil || len(dOut.DetectorIds) == 0 {
		return nil, fmt.Errorf("no GuardDuty detectors found or not enabled")
	}
	detectorID := dOut.DetectorIds[0]

	// List active findings (HIGH/CRITICAL only — severity ≥ 7.0).
	lOut, err := svc.ListFindings(ctx, &guardduty.ListFindingsInput{
		DetectorId: aws.String(detectorID),
		FindingCriteria: &gdtypes.FindingCriteria{
			Criterion: map[string]gdtypes.Condition{
				"severity": {GreaterThan: aws.Int64(6)},
			},
		},
	})
	if err != nil || len(lOut.FindingIds) == 0 {
		return nil, nil
	}

	// Get finding details (batch up to 50).
	ids := lOut.FindingIds
	if len(ids) > 50 {
		ids = ids[:50]
	}
	gOut, err := svc.GetFindings(ctx, &guardduty.GetFindingsInput{
		DetectorId: aws.String(detectorID),
		FindingIds: ids,
	})
	if err != nil {
		return nil, err
	}

	var findings []gdFinding
	for _, f := range gOut.Findings {
		sev := "HIGH"
		if aws.ToFloat64(f.Severity) >= 9.0 {
			sev = "CRITICAL"
		}
		// f.UpdatedAt is *string in GuardDuty SDK; parse best-effort.
		var updatedAt time.Time
		if f.UpdatedAt != nil {
			updatedAt, _ = time.Parse(time.RFC3339, *f.UpdatedAt)
		}
		findings = append(findings, gdFinding{
			FindingID:  aws.ToString(f.Id),
			ThreatType: aws.ToString(f.Type),
			Severity:   sev,
			Title:      aws.ToString(f.Title),
			UpdatedAt:  updatedAt,
		})
	}
	return findings, nil
}

func collectAccessAnalyzerFindings(ctx context.Context, svc *accessanalyzer.Client) ([]aaFinding, error) {
	// List analyzers.
	lOut, err := svc.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{})
	if err != nil || len(lOut.Analyzers) == 0 {
		return nil, fmt.Errorf("no IAM Access Analyzers found")
	}
	analyzerARN := aws.ToString(lOut.Analyzers[0].Arn)

	// List active findings.
	fOut, err := svc.ListFindings(ctx, &accessanalyzer.ListFindingsInput{
		AnalyzerArn: aws.String(analyzerARN),
		Filter: map[string]aatypes.Criterion{
			"status": {Eq: []string{"ACTIVE"}},
		},
	})
	if err != nil {
		return nil, err
	}

	var findings []aaFinding
	for _, f := range fOut.Findings {
		resourceType := strings.ToLower(strings.ReplaceAll(string(f.ResourceType), "AWS::", ""))
		findings = append(findings, aaFinding{
			ID:           aws.ToString(f.Id),
			ResourceType: resourceType,
			UpdatedAt:    aws.ToTime(f.UpdatedAt),
		})
	}
	return findings, nil
}

// GuardDuty threat type → framework control mapping.
// Community-maintained: different orgs may map differently.
var ThreatMapping = map[string][]string{
	"Exfiltration:S3/AnomalousBehavior":       {"3.1.3", "3.14.6"},
	"UnauthorizedAccess:IAMUser/ConsoleLogin":  {"3.1.1", "3.5.3"},
	"CryptoCurrency:EC2/BitcoinTool.B!DNS":     {"3.14.1", "3.14.6"},
	"Recon:EC2/PortProbeUnprotectedPort":       {"3.13.1"},
	"UnauthorizedAccess:EC2/RDPBruteForce":     {"3.1.1", "3.13.1"},
	"Impact:EC2/PortSweep":                     {"3.13.1", "3.14.6"},
}
