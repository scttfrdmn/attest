package scp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/provabl/attest/internal/framework"
	"github.com/provabl/attest/pkg/schema"
)

func TestParseCondition(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantOperator string
		wantKey      string
		wantValues   []string
		wantErr      bool
	}{
		{
			name:         "bool != true",
			input:        "aws:MultiFactorAuthPresent != true",
			wantOperator: "Bool",
			wantKey:      "aws:MultiFactorAuthPresent",
			wantValues:   []string{"false"},
		},
		{
			name:         "bool == false",
			input:        "aws:SecureTransport == false",
			wantOperator: "Bool",
			wantKey:      "aws:SecureTransport",
			wantValues:   []string{"false"},
		},
		{
			name:         "bool == true",
			input:        "ec2:AssociatePublicIpAddress == true",
			wantOperator: "Bool",
			wantKey:      "ec2:AssociatePublicIpAddress",
			wantValues:   []string{"true"},
		},
		{
			name:         "not in list",
			input:        "aws:RequestedRegion not in [us-east-1, us-west-2, us-gov-west-1]",
			wantOperator: "StringNotEquals",
			wantKey:      "aws:RequestedRegion",
			wantValues:   []string{"us-east-1", "us-west-2", "us-gov-west-1"},
		},
		{
			name:         "in list",
			input:        "aws:RequestedRegion in [us-east-1, us-west-2]",
			wantOperator: "StringEquals",
			wantKey:      "aws:RequestedRegion",
			wantValues:   []string{"us-east-1", "us-west-2"},
		},
		{
			name:         "arn not equal with wildcard",
			input:        "aws:PrincipalARN != arn:aws:iam::*:role/SREAdmin",
			wantOperator: "ArnNotLike",
			wantKey:      "aws:PrincipalARN",
			wantValues:   []string{"arn:aws:iam::*:role/SREAdmin"},
		},
		{
			name:         "arn not equal no wildcard",
			input:        "aws:PrincipalARN != arn:aws:iam::123456789012:root",
			wantOperator: "ArnNotEquals",
			wantKey:      "aws:PrincipalARN",
			wantValues:   []string{"arn:aws:iam::123456789012:root"},
		},
		{
			name:         "arn equals with wildcard",
			input:        "aws:PrincipalARN == arn:aws:iam::*:root",
			wantOperator: "ArnLike",
			wantKey:      "aws:PrincipalARN",
			wantValues:   []string{"arn:aws:iam::*:root"},
		},
		{
			name:         "string not equals",
			input:        "s3:x-amz-server-side-encryption != aws:kms",
			wantOperator: "StringNotEquals",
			wantKey:      "s3:x-amz-server-side-encryption",
			wantValues:   []string{"aws:kms"},
		},
		{
			name:         "string equals",
			input:        "aws:PrincipalType == IAMUser",
			wantOperator: "StringEquals",
			wantKey:      "aws:PrincipalType",
			wantValues:   []string{"IAMUser"},
		},
		{
			name:         "does not contain",
			input:        "aws:PrincipalOrgPaths does not contain /admin/",
			wantOperator: "StringNotLike",
			wantKey:      "aws:PrincipalOrgPaths",
			wantValues:   []string{"*/admin/*"},
		},
		{
			name:         "contains",
			input:        "aws:PrincipalARN contains /developer/",
			wantOperator: "StringLike",
			wantKey:      "aws:PrincipalARN",
			wantValues:   []string{"*/developer/*"},
		},
		{
			name:    "unrecognized format",
			input:   "gibberish with no operator",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCondition(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseCondition(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.operator != tt.wantOperator {
				t.Errorf("operator = %q, want %q", got.operator, tt.wantOperator)
			}
			if got.key != tt.wantKey {
				t.Errorf("key = %q, want %q", got.key, tt.wantKey)
			}
			if len(got.values) != len(tt.wantValues) {
				t.Errorf("values = %v, want %v", got.values, tt.wantValues)
				return
			}
			for i, v := range tt.wantValues {
				if got.values[i] != v {
					t.Errorf("values[%d] = %q, want %q", i, got.values[i], v)
				}
			}
		})
	}
}

func TestConditionInCompiledSCP(t *testing.T) {
	// End-to-end: compile a control with a real condition and verify the JSON.
	rcs := &framework.ResolvedControlSet{
		Controls: map[string][]framework.ResolvedControl{
			"scp-require-mfa": {
				{
					FrameworkID: "test",
					Control: schema.Control{
						ID:     "3.1.1",
						Family: "Access Control",
						Structural: []schema.StructuralEnforcement{
							{
								ID:     "scp-require-mfa",
								Effect: "Deny",
								Actions: []string{"*"},
								Conditions: []string{
									"aws:MultiFactorAuthPresent != true",
									"aws:PrincipalType == IAMUser",
								},
							},
						},
					},
				},
			},
		},
	}

	c := NewCompiler()
	scps, err := c.Compile(rcs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if len(scps) != 1 {
		t.Fatalf("got %d SCPs, want 1", len(scps))
	}

	// Parse the JSON and check structure.
	var policy IAMPolicy
	if err := json.Unmarshal([]byte(scps[0].PolicyJSON), &policy); err != nil {
		t.Fatalf("invalid SCP JSON: %v", err)
	}
	if len(policy.Statement) != 1 {
		t.Fatalf("got %d statements, want 1", len(policy.Statement))
	}
	stmt := policy.Statement[0]
	if stmt.Condition == nil {
		t.Fatal("expected Condition block, got nil")
	}

	// Verify Bool condition present.
	boolCond, ok := stmt.Condition["Bool"].(map[string]any)
	if !ok {
		t.Fatalf("expected Bool condition, got %T", stmt.Condition["Bool"])
	}
	if boolCond["aws:MultiFactorAuthPresent"] != "false" {
		t.Errorf("Bool[aws:MultiFactorAuthPresent] = %v, want false", boolCond["aws:MultiFactorAuthPresent"])
	}
}

func TestSCPSizeLimit(t *testing.T) {
	// Build a large unique action set to exceed 5120 bytes.
	uniqueActions := []string{}
	for i := 0; i < 60; i++ {
		uniqueActions = append(uniqueActions, "s3:Action"+strings.Repeat("x", i+10))
	}

	rcs := &framework.ResolvedControlSet{
		Controls: map[string][]framework.ResolvedControl{
			"scp-big-test": {
				{
					FrameworkID: "test",
					Control: schema.Control{
						ID:     "3.1.1",
						Family: "Access Control",
						Structural: []schema.StructuralEnforcement{
							{
								ID:      "scp-big-test",
								Effect:  "Deny",
								Actions: uniqueActions,
							},
						},
					},
				},
			},
		},
	}

	c := NewCompiler()
	scps, err := c.Compile(rcs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	// All resulting SCPs must be within the size limit.
	for _, s := range scps {
		if len(s.PolicyJSON) > scpSizeLimit {
			t.Errorf("SCP %s exceeds size limit: %d > %d", s.ID, len(s.PolicyJSON), scpSizeLimit)
		}
		// Must be valid JSON.
		var p IAMPolicy
		if err := json.Unmarshal([]byte(s.PolicyJSON), &p); err != nil {
			t.Errorf("SCP %s has invalid JSON: %v", s.ID, err)
		}
	}
}

func TestCompileNIST800171(t *testing.T) {
	// Integration test: compile the full NIST 800-171 framework.
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
	scps, err := c.Compile(rcs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	if len(scps) == 0 {
		t.Fatal("expected at least one SCP")
	}

	// All SCPs must be valid JSON within size limit.
	for _, s := range scps {
		if len(s.PolicyJSON) > scpSizeLimit {
			t.Errorf("SCP %s exceeds size limit: %d", s.ID, len(s.PolicyJSON))
		}
		var p IAMPolicy
		if err := json.Unmarshal([]byte(s.PolicyJSON), &p); err != nil {
			t.Errorf("SCP %s invalid JSON: %v\nContent: %s", s.ID, err, s.PolicyJSON)
		}
		if len(p.Statement) == 0 {
			t.Errorf("SCP %s has no statements", s.ID)
		}
		for _, stmt := range p.Statement {
			if stmt.Effect != "Deny" && stmt.Effect != "Allow" {
				t.Errorf("SCP %s statement %s: invalid Effect %q", s.ID, stmt.Sid, stmt.Effect)
			}
			if stmt.Resource == "" {
				t.Errorf("SCP %s statement %s: missing Resource", s.ID, stmt.Sid)
			}
		}
	}
}
