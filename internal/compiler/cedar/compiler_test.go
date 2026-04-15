package cedar

import (
	"strings"
	"testing"

	"github.com/scttfrdmn/attest/internal/framework"
	"github.com/scttfrdmn/attest/pkg/schema"
)

func TestCompile(t *testing.T) {
	rcs := &framework.ResolvedControlSet{
		Controls: map[string][]framework.ResolvedControl{
			"scp-test": {
				{
					FrameworkID: "test",
					Control: schema.Control{
						ID:     "3.1.1",
						Family: "Access Control",
						Operational: []schema.OperationalEnforcement{
							{
								ID:          "cedar-test-policy",
								Description: "Test policy",
								Entities:    []string{"principal", "resource"},
								Attributes: map[string][]string{
									"principal": {"authorized", "mfa_enabled"},
									"resource":  {"classification"},
								},
							},
						},
					},
				},
			},
		},
	}

	c := NewCompiler()
	policies, err := c.Compile(rcs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if len(policies) == 0 {
		t.Fatal("expected at least one policy")
	}
	p := policies[0]
	if !strings.Contains(p.PolicyText, "forbid") {
		t.Errorf("policy text missing 'forbid': %s", p.PolicyText)
	}
	if !strings.Contains(p.PolicyText, "unless") {
		t.Errorf("policy text missing 'unless': %s", p.PolicyText)
	}
}

func TestCompileWithHandwrittenCedarPolicy(t *testing.T) {
	handwritten := `forbid (principal, action == Action::"S3:PutObject", resource)
unless { resource.encrypted == true };`

	rcs := &framework.ResolvedControlSet{
		Controls: map[string][]framework.ResolvedControl{
			"scp-test": {
				{
					FrameworkID: "test",
					Control: schema.Control{
						ID:     "3.1.3",
						Family: "Access Control",
						Operational: []schema.OperationalEnforcement{
							{
								ID:          "cedar-handwritten",
								Description: "Hand-written Cedar",
								CedarPolicy: handwritten,
								Entities:    []string{"principal"},
							},
						},
					},
				},
			},
		},
	}

	c := NewCompiler()
	policies, err := c.Compile(rcs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("got %d policies, want 1", len(policies))
	}
	if !strings.Contains(policies[0].PolicyText, handwritten) {
		t.Errorf("expected hand-written policy preserved, got:\n%s", policies[0].PolicyText)
	}
}

func TestTemporalConstraints(t *testing.T) {
	tests := []struct {
		name           string
		conditionType  string
		wantContains   string
	}{
		{"expiry", "expiry", "principal.training_expiry"},
		{"event", "event", "principal.irb_active"},
		{"schedule", "schedule", "context.hour"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rcs := &framework.ResolvedControlSet{
				Controls: map[string][]framework.ResolvedControl{
					"scp-temporal-test": {
						{
							FrameworkID: "test",
							Control: schema.Control{
								ID:     "3.1.3",
								Family: "Access Control",
								Operational: []schema.OperationalEnforcement{
									{
										ID:          "cedar-temporal",
										Description: "Temporal test",
										Entities:    []string{"principal"},
										Attributes: map[string][]string{
											"principal": {"authorized"},
										},
										Temporal: &schema.TemporalConstraint{
											ConditionType: tt.conditionType,
											Description:   tt.name + " constraint",
										},
									},
								},
							},
						},
					},
				},
			}

			c := NewCompiler()
			policies, err := c.Compile(rcs)
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}
			if len(policies) == 0 {
				t.Fatal("expected at least one policy")
			}
			if !strings.Contains(policies[0].PolicyText, tt.wantContains) {
				t.Errorf("temporal %q: policy missing %q\nPolicy:\n%s",
					tt.conditionType, tt.wantContains, policies[0].PolicyText)
			}
		})
	}
}

func TestBuildSchema(t *testing.T) {
	rcs := &framework.ResolvedControlSet{
		Controls: map[string][]framework.ResolvedControl{
			"scp-test": {
				{
					FrameworkID: "test",
					Control: schema.Control{
						ID:     "3.1.3",
						Family: "Access Control",
						Operational: []schema.OperationalEnforcement{
							{
								ID:          "cedar-cui-data-movement",
								Description: "CUI data movement",
								Entities:    []string{"principal", "data_object"},
								Attributes: map[string][]string{
									"principal":   {"cui_training_current", "lab_id"},
									"data_object": {"classification", "source_region"},
								},
							},
						},
					},
				},
			},
		},
	}

	c := NewCompiler()
	schema := c.BuildSchema(rcs)

	if schema == "" {
		t.Fatal("BuildSchema() returned empty string")
	}
	if !strings.Contains(schema, "entity Principal") {
		t.Errorf("schema missing 'entity Principal':\n%s", schema)
	}
	if !strings.Contains(schema, "entity DataObject") {
		t.Errorf("schema missing 'entity DataObject':\n%s", schema)
	}
	if !strings.Contains(schema, "cui_training_current") {
		t.Errorf("schema missing 'cui_training_current':\n%s", schema)
	}
	if !strings.Contains(schema, "classification") {
		t.Errorf("schema missing 'classification':\n%s", schema)
	}
}

func TestInferCedarType(t *testing.T) {
	tests := []struct {
		attr     string
		wantType string
	}{
		{"cui_training_current", "Bool"},
		{"mfa_enabled", "Bool"},
		{"authorized", "Bool"},
		{"lab_id", "String"},
		{"classification", "String"},
		{"source_region", "String"},
		{"cui_training_expiry", "Long"},
		{"irb_protocols", "Set<String>"},
		{"lab_membership", "Set<String>"},
	}

	for _, tt := range tests {
		t.Run(tt.attr, func(t *testing.T) {
			got := inferCedarType(tt.attr)
			if got != tt.wantType {
				t.Errorf("inferCedarType(%q) = %q, want %q", tt.attr, got, tt.wantType)
			}
		})
	}
}

func TestBuildSchemaWithTemporalContext(t *testing.T) {
	rcs := &framework.ResolvedControlSet{
		Controls: map[string][]framework.ResolvedControl{
			"scp-test": {
				{
					FrameworkID: "test",
					Control: schema.Control{
						ID:     "3.1.3",
						Family: "Access Control",
						Operational: []schema.OperationalEnforcement{
							{
								ID:          "cedar-with-temporal",
								Description: "Temporal policy",
								Entities:    []string{"principal"},
								Attributes:  map[string][]string{"principal": {"authorized"}},
								Temporal: &schema.TemporalConstraint{
									ConditionType: "expiry",
									Description:   "Training expiry",
								},
							},
						},
					},
				},
			},
		},
	}

	c := NewCompiler()
	schemaText := c.BuildSchema(rcs)

	if !strings.Contains(schemaText, "entity Context") {
		t.Errorf("schema missing 'entity Context' for temporal constraint:\n%s", schemaText)
	}
	if !strings.Contains(schemaText, "current_time") {
		t.Errorf("schema missing 'current_time':\n%s", schemaText)
	}
}

func TestCompileFullFramework(t *testing.T) {
	loader := framework.NewLoader("../../../frameworks")
	fw, err := loader.Load("nist-800-171-r2")
	if err != nil {
		t.Fatalf("Load(nist-800-171-r2) error = %v", err)
	}

	rcs, err := framework.Resolve([]*schema.Framework{fw})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	c := NewCompiler()
	policies, err := c.Compile(rcs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if len(policies) == 0 {
		t.Fatal("expected at least one Cedar policy")
	}

	schemaText := c.BuildSchema(rcs)
	if schemaText == "" {
		t.Fatal("BuildSchema() returned empty string")
	}

	for _, p := range policies {
		if p.ID == "" {
			t.Error("policy has empty ID")
		}
		if p.PolicyText == "" {
			t.Errorf("policy %s has empty text", p.ID)
		}
	}
}
