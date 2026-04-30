// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package dashboard

import (
	_ "embed"
	"fmt"
	"os"
	"net/http"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/provabl/attest/internal/auth"
)

//go:embed policies/dashboard.cedar
var dashboardPolicyCedar []byte

// loadDashboardPolicies parses the embedded Cedar policy file.
// Called once at server construction; parse errors surface as startup failures.
func loadDashboardPolicies() (*cedar.PolicySet, error) {
	ps, err := cedar.NewPolicySetFromBytes("dashboard.cedar", dashboardPolicyCedar)
	if err != nil {
		return nil, fmt.Errorf("parsing dashboard Cedar policies: %w", err)
	}
	return ps, nil
}

// dashboardAction maps an HTTP (path, method) pair to a logical Cedar action ID.
// GET requests map to read:* actions; mutating methods map to write:* or generate.
// Returns an error for paths not registered as dashboard routes.
func dashboardAction(path, method string) (string, error) {
	isWrite := method == http.MethodPost || method == http.MethodPut ||
		method == http.MethodDelete || method == http.MethodPatch

	switch path {
	case "/":
		return "read:index", nil
	case "/api/posture":
		return "read:posture", nil
	case "/api/frameworks":
		return "read:frameworks", nil
	case "/api/environments":
		return "read:environments", nil
	case "/api/waivers":
		if isWrite {
			return "write:waivers", nil
		}
		return "read:waivers", nil
	case "/api/incidents":
		if isWrite {
			return "write:incidents", nil
		}
		return "read:incidents", nil
	case "/api/operations/stream":
		return "stream:operations", nil
	case "/api/generate":
		return "generate", nil
	}
	return "", fmt.Errorf("unmapped dashboard path: %s %s", method, path)
}

// cedarGuard returns an HTTP middleware that evaluates the dashboard Cedar policies
// before passing the request to the next handler. It extracts the authenticated user
// from the request context (placed there by the OIDC middleware), maps the HTTP
// operation to a logical action, and calls cedar.Authorize.
//
// The policy set is passed as a parameter (not global state) so the guard is
// independently testable and the policy is loaded once at server construction.
func cedarGuard(ps *cedar.PolicySet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.UserFromContext(r.Context())
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		actionID, err := dashboardAction(r.URL.Path, r.Method)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		principalUID := types.NewEntityUID(types.EntityType("DashboardUser"), types.String(user.Email))
		actionUID := types.NewEntityUID(types.EntityType("DashboardAction"), types.String(actionID))
		resourceUID := types.NewEntityUID(types.EntityType("DashboardEndpoint"), types.String(r.URL.Path))

		entities := types.EntityMap{
			principalUID: types.Entity{
				UID: principalUID,
				Attributes: types.NewRecord(types.RecordMap{
					types.String("role"):  types.String(string(user.Role)),
					types.String("email"): types.String(user.Email),
				}),
			},
			actionUID:   types.Entity{UID: actionUID},
			resourceUID: types.Entity{UID: resourceUID},
		}

		req := types.Request{
			Principal: principalUID,
			Action:    actionUID,
			Resource:  resourceUID,
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		if len(diag.Errors) > 0 {
			// Log Cedar evaluation errors for security audit trail — these indicate
			// policy or entity model issues, not authorization failures.
			fmt.Fprintf(os.Stderr, "dashboard: Cedar authorization error for %s %s: %v\n",
				r.Method, r.URL.Path, diag.Errors)
		}
		if decision != types.Decision(true) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
