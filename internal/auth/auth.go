// Package auth integrates Bouncing for authentication and Cedar for
// authorization on the attest dashboard. The same Cedar PDP that runs
// compliance also governs dashboard access control.
//
// Roles (enforced by Cedar, not application logic):
//   - admin: full access, deploy policies, manage waivers
//   - compliance_officer: view all posture, generate documents, manage waivers
//   - security_engineer: view all, operate Cedar PDP, review proposed policies
//   - pi_researcher: view own environments only
//   - auditor: read-only access to everything, cannot deploy
package auth

import (
	"context"
	"fmt"
	"net/http"
)

// Role is a dashboard authorization role.
type Role string

const (
	RoleAdmin             Role = "admin"
	RoleComplianceOfficer Role = "compliance_officer"
	RoleSecurityEngineer  Role = "security_engineer"
	RolePIResearcher      Role = "pi_researcher"
	RoleAuditor           Role = "auditor"
)

// User is an authenticated dashboard user.
type User struct {
	ID         string
	Name       string
	Email      string
	Role       Role
	AuthMethod string // "passkey", "oauth", "saml"
}

// Middleware returns an HTTP middleware that authenticates via Bouncing
// and authorizes via Cedar.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Validate Bouncing token, resolve user, check Cedar policy.
		next.ServeHTTP(w, r)
	})
}

// UserFromContext extracts the authenticated user from the request context.
func UserFromContext(ctx context.Context) (*User, error) {
	return nil, fmt.Errorf("not implemented")
}
