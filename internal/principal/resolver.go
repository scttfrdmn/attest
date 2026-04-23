// Package principal resolves entity attributes for Cedar policy evaluation.
// Cedar policies evaluate principal.cui_training_current, principal.irb_protocol_active,
// etc. — this package sources those attributes from external institutional systems.
//
// The resolver chain: IAM role ARN → human identity → attribute sources → Cedar entity.
//
// Attribute sources (plugin interface):
//   - SAML/Shibboleth session tags (federated identity)
//   - LDAP/Active Directory groups (lab membership, department)
//   - LMS API (CUI training status, CITI training, expiry dates)
//   - IRB management system (Cayuse, iRIS — active protocols)
//   - Research computing allocation system (compute budgets)
//
// The plugin interface is open source. Connectors for specific institutional
// systems are community-maintained.
package principal

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/provabl/attest/pkg/schema"
)

// AttributeSource is the plugin interface for principal attribute resolution.
// Institutions implement this for their specific systems.
type AttributeSource interface {
	// Name returns the source identifier (e.g., "ldap", "lms", "irb").
	Name() string

	// Resolve populates attributes for a principal.
	// Sources should gracefully handle unavailability — missing attributes
	// cause Cedar policies to default to deny via the forbid-unless pattern.
	Resolve(ctx context.Context, principalARN string, attrs *schema.PrincipalAttributes) error
}

// Resolver chains multiple attribute sources to hydrate Cedar entities.
type Resolver struct {
	sources []AttributeSource
}

// NewResolver creates a principal attribute resolver with the given sources.
func NewResolver(sources ...AttributeSource) *Resolver {
	return &Resolver{sources: sources}
}

// Resolve hydrates attributes for a principal by querying all registered sources.
// Sources that fail are skipped (not fatal) — Cedar policy evaluation proceeds
// with whatever attributes were successfully resolved.
func (r *Resolver) Resolve(ctx context.Context, principalARN string) (*schema.PrincipalAttributes, error) {
	attrs := &schema.PrincipalAttributes{
		PrincipalARN: principalARN,
	}
	for _, src := range r.sources {
		if err := src.Resolve(ctx, principalARN, attrs); err != nil {
			// Log but don't fail — missing attributes → Cedar defaults to deny.
			fmt.Fprintf(os.Stderr, "warning: principal source %s could not resolve %s: %v\n", src.Name(), principalARN, err)
		}
	}
	return attrs, nil
}

// --- SAML/Shibboleth source ---

// SAMLSource resolves principal attributes from IAM role session tags and role tags.
// When federated users assume a role via SAML/Shibboleth, their IdP can set session
// tags that are propagated to STS credentials. This source reads those tags.
//
// Expected IAM role tags (set by IdP or manually):
//
//	attest:cui-training     = "true" | "false"
//	attest:cui-expiry       = RFC3339 timestamp (e.g., "2026-06-01T00:00:00Z")
//	attest:lab-id           = lab identifier (e.g., "chen-genomics-lab")
//	attest:admin-level      = "none" | "env" | "sre"
type SAMLSource struct {
	iamSvc iamAPI
	stsSvc stsAPI
	region string
}

type iamAPI interface {
	ListRoleTags(ctx context.Context, params *iam.ListRoleTagsInput, optFns ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error)
}

type stsAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// NewSAMLSource creates a SAML attribute source backed by real AWS SDK clients.
func NewSAMLSource(ctx context.Context, region string) (*SAMLSource, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config for SAMLSource: %w", err)
	}
	return &SAMLSource{
		iamSvc: iam.NewFromConfig(cfg),
		stsSvc: sts.NewFromConfig(cfg),
		region: region,
	}, nil
}

func (s *SAMLSource) Name() string { return "saml" }

// Resolve reads IAM role tags for the role identified in principalARN and maps
// attest:* tags to PrincipalAttributes fields.
func (s *SAMLSource) Resolve(ctx context.Context, principalARN string, attrs *schema.PrincipalAttributes) error {
	roleName := roleNameFromARN(principalARN)
	if roleName == "" {
		return nil // Not a role ARN; skip silently.
	}

	var nextMarker *string
	tags := make(map[string]string)

	for {
		out, err := s.iamSvc.ListRoleTags(ctx, &iam.ListRoleTagsInput{
			RoleName: aws.String(roleName),
			Marker:   nextMarker,
		})
		if err != nil {
			// Role may not exist or may not have tags — not fatal.
			return nil
		}
		for _, t := range out.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
		if !out.IsTruncated {
			break
		}
		nextMarker = out.Marker
	}

	// Map attest:* tags to PrincipalAttributes.
	if v, ok := tags["attest:cui-training"]; ok {
		attrs.CUITrainingCurrent = strings.ToLower(v) == "true"
	}
	if v, ok := tags["attest:cui-expiry"]; ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			attrs.CUITrainingExpiry = t
		}
	}
	if v, ok := tags["attest:lab-id"]; ok && v != "" {
		attrs.LabMembership = append(attrs.LabMembership, v)
	}
	if v, ok := tags["attest:admin-level"]; ok {
		attrs.AdminLevel = v
	}
	return nil
}

// roleNameFromARN extracts the role name from an IAM role ARN.
// Returns "" if the ARN doesn't represent a role.
// Example: "arn:aws:iam::123456789012:role/my-role" → "my-role"
func roleNameFromARN(arn string) string {
	const rolePrefix = ":role/"
	idx := strings.LastIndex(arn, rolePrefix)
	if idx == -1 {
		return ""
	}
	name := arn[idx+len(rolePrefix):]
	// Strip path components if present (e.g., "path/role-name" → "role-name").
	if i := strings.LastIndex(name, "/"); i != -1 {
		name = name[i+1:]
	}
	return name
}

// --- LDAP/Active Directory source ---

// LDAPSource resolves principal attributes from LDAP/Active Directory.
// Connects to an LDAP server and queries group membership for the user
// associated with the IAM role name (via cn attribute).
//
// Groups matching "lab-*" or "research-*" are mapped to LabMembership.
// Groups matching "admin-*" set AdminLevel = "env".
type LDAPSource struct {
	URL      string // e.g., "ldap://ldap.university.edu:389"
	BaseDN   string // e.g., "dc=university,dc=edu"
	BindDN   string // service account DN (optional, anonymous bind if empty)
	BindPass string // service account password
}

// NewLDAPSource creates an LDAP attribute source.
func NewLDAPSource(url, baseDN string) *LDAPSource {
	return &LDAPSource{URL: url, BaseDN: baseDN}
}

func (l *LDAPSource) Name() string { return "ldap" }

// Resolve queries LDAP for group membership of the user behind the IAM role.
// Gracefully returns nil if LDAP is unavailable — Cedar policies that require
// lab membership will default to deny when these attributes are absent.
func (l *LDAPSource) Resolve(ctx context.Context, principalARN string, attrs *schema.PrincipalAttributes) error {
	roleName := roleNameFromARN(principalARN)
	if roleName == "" {
		return nil // not a role ARN
	}

	conn, err := ldap.DialURL(l.URL)
	if err != nil {
		return nil // LDAP unavailable — not fatal, Cedar defaults to deny
	}
	defer conn.Close()

	// Bind (anonymous or service account).
	if l.BindDN != "" {
		if err := conn.Bind(l.BindDN, l.BindPass); err != nil {
			return nil // bind failed — log but don't block evaluation
		}
	} else {
		// Anonymous bind: warn that this may return limited data and exposes
		// the directory to unauthenticated queries. Use BindDN/BindPass in production.
		fmt.Fprintf(os.Stderr, "warning: LDAP source %s using anonymous bind — configure BindDN/BindPass for production\n", l.URL)
	}

	// Search for user by cn matching the IAM role name.
	searchReq := ldap.NewSearchRequest(
		l.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		100,  // size limit
		10,   // time limit seconds
		false,
		fmt.Sprintf("(&(objectClass=person)(cn=%s))", ldap.EscapeFilter(roleName)),
		[]string{"memberOf", "cn", "mail"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil || len(result.Entries) == 0 {
		return nil // user not found — not fatal
	}

	entry := result.Entries[0]
	for _, group := range entry.GetAttributeValues("memberOf") {
		// Extract CN from the group DN: "CN=lab-genomics,OU=groups,DC=..."
		groupCN := extractCN(group)
		// Validate group name: only allow safe characters that can appear in
		// LabMembership values used in Cedar policies and log output.
		if !isValidGroupName(groupCN) {
			continue
		}
		switch {
		case strings.HasPrefix(groupCN, "lab-") || strings.HasPrefix(groupCN, "research-"):
			attrs.LabMembership = append(attrs.LabMembership, groupCN)
		case strings.HasPrefix(groupCN, "admin-"):
			attrs.AdminLevel = "env"
		}
	}

	return nil
}

// isValidGroupName validates LDAP group CNs before storing in PrincipalAttributes.
// Only allows alphanumeric, dash, and underscore — prevents special characters
// (newlines, quotes, ANSI escapes) from propagating into Cedar evaluation or logs.
func isValidGroupName(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// extractCN parses the CN value from a distinguished name.
// "CN=lab-genomics,OU=groups,DC=uni,DC=edu" → "lab-genomics"
func extractCN(dn string) string {
	parts := strings.Split(dn, ",")
	if len(parts) == 0 {
		return dn
	}
	first := strings.TrimSpace(parts[0])
	if after, ok := strings.CutPrefix(first, "CN="); ok {
		return after
	}
	if after, ok := strings.CutPrefix(first, "cn="); ok {
		return after
	}
	return first
}
