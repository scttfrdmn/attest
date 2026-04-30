// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"testing"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
)

func newPermitAllPolicySet(t *testing.T) *cedar.PolicySet {
	t.Helper()
	// permit(principal, action, resource);
	ps, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(`permit(principal, action, resource);`))
	if err != nil {
		t.Fatalf("parse permit policy: %v", err)
	}
	return ps
}


func TestEvaluateWithPolicies_Allow(t *testing.T) {
	ev := NewEvaluator(nil)
	req := &AuthzRequest{
		PrincipalARN: "arn:aws:iam::123456789012:user/researcher",
		Action:       "s3:PutObject",
		ResourceARN:  "arn:aws:s3:::cui-data-bucket",
		Timestamp:    time.Now(),
	}
	decision, err := ev.EvaluateWithPolicies(context.Background(), newPermitAllPolicySet(t), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Effect != "ALLOW" {
		t.Errorf("expected ALLOW, got %s", decision.Effect)
	}
	if decision.Principal != req.PrincipalARN {
		t.Errorf("principal mismatch: got %s", decision.Principal)
	}
	if decision.Action != req.Action {
		t.Errorf("action mismatch: got %s", decision.Action)
	}
}

func TestEvaluateWithPolicies_Deny(t *testing.T) {
	ev := NewEvaluator(nil)
	req := &AuthzRequest{
		PrincipalARN: "arn:aws:iam::123456789012:user/researcher",
		Action:       "s3:DeleteObject",
		ResourceARN:  "arn:aws:s3:::cui-data-bucket",
	}
	// Empty policy set → no permit → deny by default.
	decision, err := ev.EvaluateWithPolicies(context.Background(), cedar.NewPolicySet(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Effect != "DENY" {
		t.Errorf("expected DENY with empty policy set, got %s", decision.Effect)
	}
}

func TestEvaluateWithPolicies_ForbidOverridesPermit(t *testing.T) {
	// Cedar: explicit forbid overrides any permit.
	policy := `
permit(principal, action, resource);
forbid(principal, action, resource) when { action == Action::"s3:DeleteObject" };
`
	ps, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policy))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	ev := NewEvaluator(nil)
	req := &AuthzRequest{
		PrincipalARN: "arn:aws:iam::123456789012:user/researcher",
		Action:       "s3:DeleteObject",
		ResourceARN:  "arn:aws:s3:::bucket",
	}
	decision, err := ev.EvaluateWithPolicies(context.Background(), ps, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Effect != "DENY" {
		t.Errorf("expected DENY (forbid overrides permit), got %s", decision.Effect)
	}
}

func TestEvaluateWithPolicies_Stats(t *testing.T) {
	ev := NewEvaluator(nil)
	req := &AuthzRequest{
		PrincipalARN: "arn:aws:iam::123456789012:user/researcher",
		Action:       "s3:GetObject",
		ResourceARN:  "arn:aws:s3:::bucket",
	}
	ps := newPermitAllPolicySet(t)
	for i := 0; i < 3; i++ {
		if _, err := ev.EvaluateWithPolicies(context.Background(), ps, req); err != nil {
			t.Fatalf("evaluation %d failed: %v", i, err)
		}
	}
	// One deny via empty policy set.
	if _, err := ev.EvaluateWithPolicies(context.Background(), cedar.NewPolicySet(), req); err != nil {
		t.Fatalf("deny evaluation failed: %v", err)
	}
	total, permits, denies := ev.GetStats()
	if total != 4 {
		t.Errorf("expected total=4, got %d", total)
	}
	if permits != 3 {
		t.Errorf("expected permits=3, got %d", permits)
	}
	if denies != 1 {
		t.Errorf("expected denies=1, got %d", denies)
	}
}

func TestBuildAttributes(t *testing.T) {
	attrs := map[string]any{
		"principal.cui_training_current": "true",
		"principal.admin_level":          "read-only",
		"resource.classification":        "CUI",
	}
	rec := buildAttributes(attrs, "principal")
	if rec.Len() != 2 {
		t.Errorf("expected 2 principal attributes, got %d", rec.Len())
	}
	// resource attributes should not appear.
	rec2 := buildAttributes(attrs, "resource")
	if rec2.Len() != 1 {
		t.Errorf("expected 1 resource attribute, got %d", rec2.Len())
	}
}

func TestBuildAttributes_Empty(t *testing.T) {
	rec := buildAttributes(nil, "principal")
	if rec.Len() != 0 {
		t.Errorf("expected empty record for nil attrs, got %d", rec.Len())
	}
}

func TestEvaluateWithPolicies_WithAttributes(t *testing.T) {
	// Policy that allows only when principal.mfa_present == true.
	policy := `permit(principal, action, resource) when { principal.mfa_present == true };`
	ps, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policy))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	ev := NewEvaluator(nil)

	tests := []struct {
		name       string
		attrs      map[string]any
		wantEffect string
	}{
		{"mfa true", map[string]any{"principal.mfa_present": "true"}, "ALLOW"},
		{"mfa false", map[string]any{"principal.mfa_present": "false"}, "DENY"},
		{"no mfa attr", map[string]any{}, "DENY"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &AuthzRequest{
				PrincipalARN: "arn:aws:iam::123456789012:user/researcher",
				Action:       "s3:PutObject",
				ResourceARN:  "arn:aws:s3:::bucket",
				Attributes:   tc.attrs,
			}
			d, err := ev.EvaluateWithPolicies(context.Background(), ps, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Effect != tc.wantEffect {
				t.Errorf("attrs %v: expected %s, got %s", tc.attrs, tc.wantEffect, d.Effect)
			}
		})
	}
}
