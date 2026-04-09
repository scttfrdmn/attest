// Package schema defines the core data model for compliance frameworks,
// controls, policy artifacts, and the crosswalk that connects them.
package schema

import "time"

// SRE represents a Secure Research Environment — an AWS Organization
// configured as a compliance enclave. Accounts within it are environments
// that inherit the org-level compliance posture.
type SRE struct {
	// OrgID is the AWS Organization ID (o-XXXXXXXXXX).
	OrgID string `yaml:"org_id" json:"org_id"`

	// Name is the human-readable name for this SRE.
	Name string `yaml:"name" json:"name"`

	// Frameworks lists the active compliance frameworks for this SRE.
	// Derived from Artifact agreements + explicit activation.
	Frameworks []FrameworkRef `yaml:"frameworks" json:"frameworks"`

	// Environments maps account IDs to environment metadata.
	Environments map[string]Environment `yaml:"environments" json:"environments"`

	// Posture is the computed compliance state.
	Posture *Posture `yaml:"posture,omitempty" json:"posture,omitempty"`
}

// Environment is an AWS account within the SRE. Researchers get environments;
// they never configure compliance directly.
type Environment struct {
	AccountID   string            `yaml:"account_id" json:"account_id"`
	Name        string            `yaml:"name" json:"name"`
	OU          string            `yaml:"ou" json:"ou"`
	Owner       string            `yaml:"owner" json:"owner"`       // PI or lab
	Purpose     string            `yaml:"purpose" json:"purpose"`   // e.g., "HIPAA genomics"
	DataClasses []string          `yaml:"data_classes" json:"data_classes"` // CUI, PHI, FERPA, etc.
	Tags        map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// FrameworkRef identifies an active framework and its source.
type FrameworkRef struct {
	ID      string `yaml:"id" json:"id"`           // e.g., "nist-800-171-r2"
	Version string `yaml:"version" json:"version"` // e.g., "2.0"

	// ArtifactAgreementID links to the AWS Artifact agreement that activates
	// this framework (e.g., a signed BAA activates HIPAA).
	// Empty if framework is activated manually.
	ArtifactAgreementID string `yaml:"artifact_agreement_id,omitempty" json:"artifact_agreement_id,omitempty"`
}

// Framework is the full definition of a compliance framework.
// These are YAML files in the frameworks/ directory — community maintained,
// with Artifact-sourced shared responsibility data overlaid at runtime.
type Framework struct {
	ID      string `yaml:"id" json:"id"`
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version" json:"version"`
	Source  string `yaml:"source" json:"source"` // URL to authoritative source

	// ArtifactReports lists the Artifact report series relevant to this
	// framework (e.g., SOC 2 Type II, ISO 27001 cert).
	ArtifactReports []ArtifactReportRef `yaml:"artifact_reports" json:"artifact_reports"`

	// Controls is the complete control catalog.
	Controls []Control `yaml:"controls" json:"controls"`
}

// ArtifactReportRef links a framework to the AWS Artifact reports that
// evidence AWS's side of the shared responsibility model.
type ArtifactReportRef struct {
	Series   string `yaml:"series" json:"series"`     // Artifact report series
	Category string `yaml:"category" json:"category"` // Artifact report category
}

// Control is a single compliance requirement within a framework.
type Control struct {
	ID     string `yaml:"id" json:"id"`         // e.g., "3.1.3"
	Family string `yaml:"family" json:"family"` // e.g., "Access Control"
	Title  string `yaml:"title" json:"title"`

	// Responsibility indicates the shared responsibility split.
	Responsibility Responsibility `yaml:"responsibility" json:"responsibility"`

	// Structural lists the preventive enforcement artifacts (SCPs).
	Structural []StructuralEnforcement `yaml:"structural,omitempty" json:"structural,omitempty"`

	// Operational lists the runtime enforcement artifacts (Cedar policies).
	Operational []OperationalEnforcement `yaml:"operational,omitempty" json:"operational,omitempty"`

	// Monitoring lists the drift-detection artifacts (Config rules).
	Monitoring []MonitoringRule `yaml:"monitoring,omitempty" json:"monitoring,omitempty"`

	// Assessment defines how this control is evaluated for self-assessment
	// (e.g., NIST 800-171A assessment objectives).
	Assessment *AssessmentSpec `yaml:"assessment,omitempty" json:"assessment,omitempty"`
}

// Responsibility captures the shared responsibility model for a control.
type Responsibility struct {
	AWS      string `yaml:"aws" json:"aws"`           // what AWS covers
	Customer string `yaml:"customer" json:"customer"` // what the customer must do
}

// StructuralEnforcement defines an SCP that enforces a control boundary.
type StructuralEnforcement struct {
	ID          string   `yaml:"id" json:"id"`
	Description string   `yaml:"description" json:"description"`
	Actions     []string `yaml:"actions" json:"actions"` // IAM actions to deny/allow
	Conditions  []string `yaml:"conditions" json:"conditions,omitempty"`
	Effect      string   `yaml:"effect" json:"effect"` // "Deny" (SCPs are deny-only in practice)
}

// OperationalEnforcement defines a Cedar policy for runtime evaluation.
type OperationalEnforcement struct {
	ID          string                `yaml:"id" json:"id"`
	Description string                `yaml:"description" json:"description"`
	Entities    []string              `yaml:"entities" json:"entities"` // entity types involved
	Attributes  map[string][]string   `yaml:"attributes" json:"attributes"` // per-entity attributes to evaluate
	CedarPolicy string                `yaml:"cedar_policy,omitempty" json:"cedar_policy,omitempty"` // raw Cedar policy text
	Temporal    *TemporalConstraint   `yaml:"temporal,omitempty" json:"temporal,omitempty"`
}

// TemporalConstraint enables time-bounded or event-conditional policies.
// "During active IRB protocol, allow; when expired, deny."
type TemporalConstraint struct {
	ConditionType string `yaml:"condition_type" json:"condition_type"` // "expiry", "event", "schedule"
	Description   string `yaml:"description" json:"description"`
}

// MonitoringRule defines a Config rule for drift detection.
type MonitoringRule struct {
	ID           string `yaml:"id" json:"id"`
	ResourceType string `yaml:"resource_type" json:"resource_type"` // e.g., "AWS::S3::Bucket"
	Check        string `yaml:"check" json:"check"`
	Remediation  string `yaml:"remediation,omitempty" json:"remediation,omitempty"`
}

// AssessmentSpec defines how a control is evaluated for self-assessment.
// Maps to NIST 800-171A assessment objectives for CMMC.
type AssessmentSpec struct {
	// Objectives are the discrete assessment objectives (e.g., 3.1.3[a], 3.1.3[b]).
	Objectives []AssessmentObjective `yaml:"objectives" json:"objectives"`
}

// AssessmentObjective is a single testable assertion within a control.
type AssessmentObjective struct {
	ID          string `yaml:"id" json:"id"`     // e.g., "3.1.3[a]"
	Description string `yaml:"description" json:"description"`

	// AutoAssessable indicates whether attest can score this objective
	// automatically from the deployed policy state and evaluation logs.
	AutoAssessable bool `yaml:"auto_assessable" json:"auto_assessable"`

	// EvidenceSource describes where the evidence comes from.
	// "scp" = structural policy exists, "cedar" = operational evaluation logs,
	// "config" = Config rule compliance, "manual" = human attestation required.
	EvidenceSource string `yaml:"evidence_source" json:"evidence_source"`
}

// --- Crosswalk and Posture ---

// Crosswalk is the auditable mapping from framework controls to deployed
// policy artifacts. This is the core output of `attest compile`.
type Crosswalk struct {
	SRE        string          `yaml:"sre" json:"sre"`
	Framework  string          `yaml:"framework" json:"framework"`
	GeneratedAt time.Time      `yaml:"generated_at" json:"generated_at"`
	Entries    []CrosswalkEntry `yaml:"entries" json:"entries"`
}

// CrosswalkEntry maps one control to its enforcement artifacts.
type CrosswalkEntry struct {
	ControlID       string   `yaml:"control_id" json:"control_id"`
	SCPs            []string `yaml:"scps,omitempty" json:"scps,omitempty"`
	CedarPolicies   []string `yaml:"cedar_policies,omitempty" json:"cedar_policies,omitempty"`
	ConfigRules     []string `yaml:"config_rules,omitempty" json:"config_rules,omitempty"`
	ArtifactReports []string `yaml:"artifact_reports,omitempty" json:"artifact_reports,omitempty"` // AWS-side evidence
	Status          string   `yaml:"status" json:"status"` // "enforced", "partial", "gap", "aws_covered"
}

// Posture is the computed compliance state of an SRE at a point in time.
type Posture struct {
	ComputedAt    time.Time                 `yaml:"computed_at" json:"computed_at"`
	Frameworks    map[string]FrameworkPosture `yaml:"frameworks" json:"frameworks"`
	TotalControls int                        `yaml:"total_controls" json:"total_controls"`
	Enforced      int                        `yaml:"enforced" json:"enforced"`
	Partial       int                        `yaml:"partial" json:"partial"`
	Gaps          int                        `yaml:"gaps" json:"gaps"`
	AWSCovered    int                        `yaml:"aws_covered" json:"aws_covered"`
}

// FrameworkPosture is the compliance state for a single framework.
type FrameworkPosture struct {
	FrameworkID string            `yaml:"framework_id" json:"framework_id"`
	Controls    map[string]string `yaml:"controls" json:"controls"` // control_id → status
	Score       float64           `yaml:"score" json:"score"`       // 0.0 - 1.0 (for CMMC scoring)
}
