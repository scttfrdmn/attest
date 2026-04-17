package principal

import (
	"context"
	"testing"

	"github.com/provabl/attest/pkg/schema"
)

// TestRoleNameFromARN verifies IAM ARN → role name extraction.
func TestRoleNameFromARN(t *testing.T) {
	tests := []struct {
		arn  string
		want string
		desc string
	}{
		{"arn:aws:iam::123456789012:role/researcher", "researcher", "simple role"},
		{"arn:aws:iam::123456789012:role/path/to/role-name", "role-name", "role with path"},
		{"arn:aws:iam::123456789012:user/alice", "", "user ARN — not a role"},
		{"arn:aws:sts::123456789012:assumed-role/researcher/session", "", "assumed-role without /role/"},
		{"", "", "empty ARN"},
		{"not-an-arn", "", "non-ARN string"},
		{"arn:aws:iam::123:role/", "", "empty role name"},
	}
	for _, tt := range tests {
		got := roleNameFromARN(tt.arn)
		if got != tt.want {
			t.Errorf("[%s] roleNameFromARN(%q) = %q, want %q", tt.desc, tt.arn, got, tt.want)
		}
	}
}

// TestExtractCN verifies LDAP DN → CN extraction.
func TestExtractCN(t *testing.T) {
	tests := []struct {
		dn   string
		want string
	}{
		{"CN=lab-genomics,OU=groups,DC=university,DC=edu", "lab-genomics"},
		{"cn=research-team,OU=groups", "research-team"},
		{"lab-group", "lab-group"},    // bare name, no CN= prefix
		{"", ""},                       // empty
		{"CN=,OU=groups", ""},          // empty CN value
	}
	for _, tt := range tests {
		got := extractCN(tt.dn)
		if got != tt.want {
			t.Errorf("extractCN(%q) = %q, want %q", tt.dn, got, tt.want)
		}
	}
}

// mockSource is a test AttributeSource that injects fixed attributes.
type mockSource struct {
	name   string
	setFn  func(attrs *schema.PrincipalAttributes)
	errOut error
}

func (m *mockSource) Name() string { return m.name }
func (m *mockSource) Resolve(_ context.Context, _ string, attrs *schema.PrincipalAttributes) error {
	if m.errOut != nil {
		return m.errOut
	}
	if m.setFn != nil {
		m.setFn(attrs)
	}
	return nil
}

// TestResolverChain verifies that multiple sources are called and attributes accumulated.
func TestResolverChain(t *testing.T) {
	src1 := &mockSource{
		name: "src1",
		setFn: func(a *schema.PrincipalAttributes) {
			a.CUITrainingCurrent = true
		},
	}
	src2 := &mockSource{
		name: "src2",
		setFn: func(a *schema.PrincipalAttributes) {
			a.LabMembership = append(a.LabMembership, "genomics-lab")
			a.AdminLevel = "env"
		},
	}

	resolver := NewResolver(src1, src2)
	attrs, err := resolver.Resolve(context.Background(), "arn:aws:iam::123:role/researcher")
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if !attrs.CUITrainingCurrent {
		t.Error("CUITrainingCurrent should be true (set by src1)")
	}
	if len(attrs.LabMembership) != 1 || attrs.LabMembership[0] != "genomics-lab" {
		t.Errorf("LabMembership = %v, want [genomics-lab]", attrs.LabMembership)
	}
	if attrs.AdminLevel != "env" {
		t.Errorf("AdminLevel = %q, want env", attrs.AdminLevel)
	}
}

// TestResolverGracefulFailure verifies that a failing source doesn't abort resolution.
func TestResolverGracefulFailure(t *testing.T) {
	import_errors_New := func(s string) error {
		return &testErr{s}
	}
	failing := &mockSource{
		name:   "failing",
		errOut: import_errors_New("LDAP unavailable"),
	}
	succeeding := &mockSource{
		name: "succeeding",
		setFn: func(a *schema.PrincipalAttributes) {
			a.CUITrainingCurrent = true
		},
	}

	resolver := NewResolver(failing, succeeding)
	attrs, err := resolver.Resolve(context.Background(), "arn:aws:iam::123:role/r")
	// Should NOT return error — failing source is non-fatal.
	if err != nil {
		t.Errorf("Resolve() with failing source should not error: %v", err)
	}
	// Succeeding source should still populate attributes.
	if !attrs.CUITrainingCurrent {
		t.Error("CUITrainingCurrent should be true from succeeding source")
	}
}

// TestResolverPrincipalARN verifies the output has the correct PrincipalARN set.
func TestResolverPrincipalARN(t *testing.T) {
	resolver := NewResolver()
	arn := "arn:aws:iam::123:role/test"
	attrs, _ := resolver.Resolve(context.Background(), arn)
	if attrs.PrincipalARN != arn {
		t.Errorf("PrincipalARN = %q, want %q", attrs.PrincipalARN, arn)
	}
}

type testErr struct{ msg string }
func (e *testErr) Error() string { return e.msg }
