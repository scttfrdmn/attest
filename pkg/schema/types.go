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

	// ReviewSchedule specifies how often this administrative control must be reviewed.
	// Only applicable to controls with evidence_source: manual.
	ReviewSchedule *ReviewSchedule `yaml:"review_schedule,omitempty" json:"review_schedule,omitempty"`
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

	// AdminDependencies links this Cedar policy to the administrative controls
	// whose correctness it depends on. When training lapses (3.2.2), the Cedar
	// policy evaluating principal.cui_training_current degrades to "partial".
	AdminDependencies []AdminDependency `yaml:"admin_dependencies,omitempty" json:"admin_dependencies,omitempty"`
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

// --- Waivers ---

// Waiver is a time-bounded, approved exception to a compliance control.
// When a control cannot be fully enforced (e.g., air-gapped instruments
// requiring USB transfer), the waiver documents the exception, its
// compensating controls, and its expiry.
type Waiver struct {
	ID                 string    `yaml:"id" json:"id"`                                     // e.g., "W-2025-003"
	ControlID          string    `yaml:"control_id" json:"control_id"`                     // control being waived
	Title              string    `yaml:"title" json:"title"`                               // human-readable description
	Scope              string    `yaml:"scope" json:"scope"`                               // environment or OU scope
	ApprovedBy         string    `yaml:"approved_by" json:"approved_by"`                   // approver (e.g., "CISO Dr. Park")
	ApprovedAt         time.Time `yaml:"approved_at" json:"approved_at"`
	ExpiresAt          time.Time `yaml:"expires_at" json:"expires_at"`
	Status             string    `yaml:"status" json:"status"`                             // "active", "expiring", "expired"
	Justification      string    `yaml:"justification" json:"justification"`
	CompensatingControls []string `yaml:"compensating_controls" json:"compensating_controls"`
}

// --- Incidents ---

// Incident tracks a security event through its lifecycle.
// Incidents degrade affected control postures and generate POA&M entries.
type Incident struct {
	ID            string    `yaml:"id" json:"id"`                       // e.g., "INC-2025-012"
	Title         string    `yaml:"title" json:"title"`
	Severity      string    `yaml:"severity" json:"severity"`           // "critical", "high", "medium", "low"
	DetectedAt    time.Time `yaml:"detected_at" json:"detected_at"`
	ResolvedAt    time.Time `yaml:"resolved_at,omitempty" json:"resolved_at,omitempty"`
	Status        string    `yaml:"status" json:"status"`               // "open", "investigating", "remediated", "closed"
	AffectedControls []string `yaml:"affected_controls" json:"affected_controls"` // control IDs
	Remediation   string    `yaml:"remediation" json:"remediation"`
	Source        string    `yaml:"source" json:"source"`               // "guardduty", "securityhub", "cedar", "manual"
}

// --- Principal Attributes ---

// PrincipalAttributes are the entity attributes Cedar policies evaluate.
// Sourced from external systems via the principal attribute resolver.
type PrincipalAttributes struct {
	PrincipalARN       string            `json:"principal_arn"`
	HumanIdentity      string            `json:"human_identity,omitempty"`       // resolved human behind the role
	LabMembership      []string          `json:"lab_membership,omitempty"`       // from directory/HR
	CUITrainingCurrent bool              `json:"cui_training_current"`           // from LMS
	CUITrainingExpiry  time.Time         `json:"cui_training_expiry,omitempty"`  // from LMS
	IRBProtocols       []string          `json:"irb_protocols,omitempty"`        // from IRB system (Cayuse/iRIS)
	ComputeAllocation  float64           `json:"compute_allocation,omitempty"`   // from research computing
	AdminLevel         string            `json:"admin_level,omitempty"`          // "none", "env", "sre"
	Attributes         map[string]string `json:"attributes,omitempty"`           // extensible attributes
}

// --- Cedar Evaluation ---

// CedarDecision records a single Cedar PDP authorization decision.
type CedarDecision struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`       // e.g., "s3:PutObject"
	Principal   string    `json:"principal"`     // IAM ARN
	Resource    string    `json:"resource"`      // resource ARN
	Effect      string    `json:"effect"`        // "ALLOW", "DENY"
	PolicyID    string    `json:"policy_id"`     // which Cedar policy made the decision
	ControlID   string    `json:"control_id"`    // framework control satisfied
	AccountID   string    `json:"account_id"`
	WaiverID    string    `json:"waiver_id,omitempty"` // if allowed via waiver
	DenyReason  string    `json:"deny_reason,omitempty"`
}

// --- Policy Testing ---

// PolicyTestSuite defines a set of test scenarios for Cedar policies.
type PolicyTestSuite struct {
	Name  string       `yaml:"name" json:"name"`
	Cases []PolicyTestCase `yaml:"cases" json:"cases"`
}

// PolicyTestCase is a single test scenario.
type PolicyTestCase struct {
	Description string            `yaml:"description" json:"description"`
	Principal   map[string]any    `yaml:"principal" json:"principal"`     // entity attributes
	Action      string            `yaml:"action" json:"action"`
	Resource    map[string]any    `yaml:"resource" json:"resource"`       // entity attributes
	Expected    string            `yaml:"expected" json:"expected"`       // "ALLOW" or "DENY"
	ControlID   string            `yaml:"control_id" json:"control_id"`
}

// --- IaC Output ---

// IaCManifest describes the generated IaC artifacts from attest compile.
type IaCManifest struct {
	Format      string    `json:"format"`       // "terraform", "cdk"
	GeneratedAt time.Time `json:"generated_at"`
	Modules     []IaCModule `json:"modules"`
}

// IaCModule is a single IaC module or construct.
type IaCModule struct {
	Name     string   `json:"name"`      // e.g., "scps", "config-rules", "eventbridge"
	Path     string   `json:"path"`      // output directory
	Controls []string `json:"controls"`  // framework controls satisfied
}

// --- Posture History ---

// PostureSnapshot is a saved posture at a point in time for trend analysis.
type PostureSnapshot struct {
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	Posture   Posture   `json:"posture" yaml:"posture"`
	Label     string    `json:"label,omitempty" yaml:"label,omitempty"` // e.g., "assessment-2025-q1"
}

// --- Attestation ---

// Attestation is a human-affirmed statement that an administrative control is satisfied.
// Unlike technical controls (SCPs, Cedar policies), administrative controls require
// human processes — training programs, risk assessments, IR testing — that attest
// tracks via attestation records with bounded validity periods.
type Attestation struct {
	ID             string    `yaml:"id" json:"id"`                                 // e.g., "ATT-2026-003"
	ControlID      string    `yaml:"control_id" json:"control_id"`                 // e.g., "3.2.1"
	ObjectiveID    string    `yaml:"objective_id,omitempty" json:"objective_id,omitempty"` // e.g., "3.2.1[a]"
	Title          string    `yaml:"title" json:"title"`
	AffirmedBy     string    `yaml:"affirmed_by" json:"affirmed_by"`               // e.g., "CISO Dr. Park"
	AffirmedAt     time.Time `yaml:"affirmed_at" json:"affirmed_at"`
	ExpiresAt      time.Time `yaml:"expires_at" json:"expires_at"`
	EvidenceRef    string    `yaml:"evidence_ref" json:"evidence_ref"`             // path/URL/description
	EvidenceType   string    `yaml:"evidence_type" json:"evidence_type"`           // "policy_doc", "training_record", "test_report", "manual"
	ReviewSchedule string    `yaml:"review_schedule,omitempty" json:"review_schedule,omitempty"` // "annual", "semiannual", "quarterly"
	Status         string    `yaml:"status" json:"status"`                         // "current", "expiring", "expired"
	Notes          string    `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// --- Review Schedule ---

// ReviewSchedule specifies how frequently an administrative control must be reviewed.
type ReviewSchedule struct {
	Frequency string `yaml:"frequency" json:"frequency"` // "annual", "semiannual", "quarterly", "event_driven"
	Trigger   string `yaml:"trigger" json:"trigger"`     // "calendar" | "event"
}

// --- Admin Dependency ---

// AdminDependency links an operational (Cedar) control to the administrative
// controls whose correctness it depends on. When training (3.2.2) lapses,
// the Cedar policy evaluating principal.cui_training_current degrades.
type AdminDependency struct {
	ControlID   string `yaml:"control_id" json:"control_id"`   // admin control ID (e.g., "3.2.2")
	Attribute   string `yaml:"attribute" json:"attribute"`     // Cedar attribute ("principal.cui_training_current")
	Consequence string `yaml:"consequence" json:"consequence"` // what happens if unmet
}

// --- Classification Scheme ---

// ClassificationScheme maps an institutional data classification system
// (e.g., UC P-levels) to attest data classes and compliance frameworks.
type ClassificationScheme struct {
	SchemeID    string                         `yaml:"scheme_id" json:"scheme_id"`
	Name        string                         `yaml:"name" json:"name"`
	Description string                         `yaml:"description" json:"description"`
	Source      string                         `yaml:"source" json:"source"`
	Mappings    map[string]ClassificationMapping `yaml:"mappings" json:"mappings"`
}

// ClassificationMapping maps one institutional classification level to attest data classes.
type ClassificationMapping struct {
	AttestClasses []string `yaml:"attest_classes" json:"attest_classes"`
	Frameworks    []string `yaml:"frameworks" json:"frameworks"`
	Description   string   `yaml:"description" json:"description"`
	Notes         string   `yaml:"notes,omitempty" json:"notes,omitempty"`
}
