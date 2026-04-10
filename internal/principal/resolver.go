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

	"github.com/scttfrdmn/attest/pkg/schema"
)

// AttributeSource is the plugin interface for principal attribute resolution.
// Institutions implement this for their specific systems.
type AttributeSource interface {
	// Name returns the source identifier (e.g., "ldap", "lms", "irb").
	Name() string

	// Resolve populates attributes for a principal.
	// The source should only set attributes it owns — other sources fill the rest.
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

// Resolve hydrates attributes for a principal by querying all sources.
func (r *Resolver) Resolve(ctx context.Context, principalARN string) (*schema.PrincipalAttributes, error) {
	attrs := &schema.PrincipalAttributes{
		PrincipalARN: principalARN,
	}
	for _, src := range r.sources {
		if err := src.Resolve(ctx, principalARN, attrs); err != nil {
			return nil, fmt.Errorf("resolving %s from %s: %w", principalARN, src.Name(), err)
		}
	}
	return attrs, nil
}

// SAMLSource resolves attributes from SAML/Shibboleth session tags.
type SAMLSource struct{}

func (s *SAMLSource) Name() string { return "saml" }
func (s *SAMLSource) Resolve(ctx context.Context, arn string, attrs *schema.PrincipalAttributes) error {
	// TODO: Extract SAML session tags from STS GetCallerIdentity or role tags.
	return nil
}

// LDAPSource resolves attributes from LDAP/Active Directory.
type LDAPSource struct {
	URL    string
	BaseDN string
}

func (l *LDAPSource) Name() string { return "ldap" }
func (l *LDAPSource) Resolve(ctx context.Context, arn string, attrs *schema.PrincipalAttributes) error {
	// TODO: Query LDAP for group membership, department, PI affiliation.
	return nil
}
