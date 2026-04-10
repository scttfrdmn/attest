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
	"time"
)

// MappedFinding is a security service finding mapped through the crosswalk
// to its framework control.
type MappedFinding struct {
	Source     string    // "securityhub", "guardduty", "inspector", "macie", etc.
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
	return nil, fmt.Errorf("not implemented")
}

// CollectAll assembles evidence for all controls.
func (ea *EvidenceAggregator) CollectAll(ctx context.Context, controlIDs []string) (map[string]*ControlEvidence, error) {
	return nil, fmt.Errorf("not implemented")
}

// GuardDuty threat type → framework control mapping.
// Community-maintained: different orgs may map differently.
var ThreatMapping = map[string][]string{
	"Exfiltration:S3/AnomalousBehavior":          {"3.1.3", "3.14.6"},
	"UnauthorizedAccess:IAMUser/ConsoleLogin":     {"3.1.1", "3.5.3"},
	"CryptoCurrency:EC2/BitcoinTool.B!DNS":       {"3.14.1", "3.14.6"},
	"Recon:EC2/PortProbeUnprotectedPort":          {"3.13.1"},
	"UnauthorizedAccess:EC2/RDPBruteForce":        {"3.1.1", "3.13.1"},
	"Impact:EC2/PortSweep":                        {"3.13.1", "3.14.6"},
}
