package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/provabl/attest/internal/auth"
	"github.com/provabl/attest/pkg/schema"
)

// ok200 is a no-op handler that always returns 200 — used to verify cedarGuard permits pass through.
var ok200 = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func withUser(r *http.Request, role auth.Role, email string) *http.Request {
	u := &auth.User{Role: role, Email: email, Name: "Test User"}
	return r.WithContext(auth.WithUser(r.Context(), u))
}

func TestLoadDashboardPolicies(t *testing.T) {
	ps, err := loadDashboardPolicies()
	if err != nil {
		t.Fatalf("policy parse failed: %v", err)
	}
	if ps == nil {
		t.Fatal("expected non-nil PolicySet")
	}
}

func TestDashboardAction(t *testing.T) {
	tests := []struct {
		path    string
		method  string
		want    string
		wantErr bool
	}{
		{"/", http.MethodGet, "read:index", false},
		{"/api/posture", http.MethodGet, "read:posture", false},
		{"/api/frameworks", http.MethodGet, "read:frameworks", false},
		{"/api/environments", http.MethodGet, "read:environments", false},
		{"/api/waivers", http.MethodGet, "read:waivers", false},
		{"/api/waivers", http.MethodPost, "write:waivers", false},
		{"/api/waivers", http.MethodPut, "write:waivers", false},
		{"/api/waivers", http.MethodDelete, "write:waivers", false},
		{"/api/incidents", http.MethodGet, "read:incidents", false},
		{"/api/incidents", http.MethodPost, "write:incidents", false},
		{"/api/operations/stream", http.MethodGet, "stream:operations", false},
		{"/api/generate", http.MethodGet, "generate", false},
		{"/api/generate", http.MethodPost, "generate", false},
		{"/api/unknown", http.MethodGet, "", true},
		{"/api/unknown", http.MethodPost, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			got, err := dashboardAction(tc.path, tc.method)
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v, got err=%v", tc.wantErr, err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCedarGuard(t *testing.T) {
	ps, err := loadDashboardPolicies()
	if err != nil {
		t.Fatalf("loadDashboardPolicies: %v", err)
	}

	tests := []struct {
		name       string
		role       auth.Role
		path       string
		method     string
		noUser     bool
		wantStatus int
	}{
		// admin: full access
		{"admin read posture", auth.RoleAdmin, "/api/posture", http.MethodGet, false, http.StatusOK},
		{"admin read environments", auth.RoleAdmin, "/api/environments", http.MethodGet, false, http.StatusOK},
		{"admin generate", auth.RoleAdmin, "/api/generate", http.MethodGet, false, http.StatusOK},
		{"admin write waivers", auth.RoleAdmin, "/api/waivers", http.MethodPost, false, http.StatusOK},
		{"admin stream operations", auth.RoleAdmin, "/api/operations/stream", http.MethodGet, false, http.StatusOK},

		// compliance_officer: same as admin
		{"co read posture", auth.RoleComplianceOfficer, "/api/posture", http.MethodGet, false, http.StatusOK},
		{"co generate", auth.RoleComplianceOfficer, "/api/generate", http.MethodGet, false, http.StatusOK},
		{"co write waivers", auth.RoleComplianceOfficer, "/api/waivers", http.MethodPost, false, http.StatusOK},

		// security_engineer: reads + incidents write + stream; no generate, no waiver writes
		{"se read posture", auth.RoleSecurityEngineer, "/api/posture", http.MethodGet, false, http.StatusOK},
		{"se read waivers", auth.RoleSecurityEngineer, "/api/waivers", http.MethodGet, false, http.StatusOK},
		{"se write incidents", auth.RoleSecurityEngineer, "/api/incidents", http.MethodPost, false, http.StatusOK},
		{"se stream ops", auth.RoleSecurityEngineer, "/api/operations/stream", http.MethodGet, false, http.StatusOK},
		{"se generate denied", auth.RoleSecurityEngineer, "/api/generate", http.MethodGet, false, http.StatusForbidden},
		{"se write waivers denied", auth.RoleSecurityEngineer, "/api/waivers", http.MethodPost, false, http.StatusForbidden},

		// pi_researcher: posture, frameworks, environments only
		{"pi read posture", auth.RolePIResearcher, "/api/posture", http.MethodGet, false, http.StatusOK},
		{"pi read frameworks", auth.RolePIResearcher, "/api/frameworks", http.MethodGet, false, http.StatusOK},
		{"pi read environments", auth.RolePIResearcher, "/api/environments", http.MethodGet, false, http.StatusOK},
		{"pi read waivers denied", auth.RolePIResearcher, "/api/waivers", http.MethodGet, false, http.StatusForbidden},
		{"pi read incidents denied", auth.RolePIResearcher, "/api/incidents", http.MethodGet, false, http.StatusForbidden},
		{"pi stream ops denied", auth.RolePIResearcher, "/api/operations/stream", http.MethodGet, false, http.StatusForbidden},
		{"pi generate denied", auth.RolePIResearcher, "/api/generate", http.MethodGet, false, http.StatusForbidden},

		// auditor: all reads; no stream, no generate, no writes
		{"auditor read posture", auth.RoleAuditor, "/api/posture", http.MethodGet, false, http.StatusOK},
		{"auditor read waivers", auth.RoleAuditor, "/api/waivers", http.MethodGet, false, http.StatusOK},
		{"auditor read incidents", auth.RoleAuditor, "/api/incidents", http.MethodGet, false, http.StatusOK},
		{"auditor stream ops denied", auth.RoleAuditor, "/api/operations/stream", http.MethodGet, false, http.StatusForbidden},
		{"auditor generate denied", auth.RoleAuditor, "/api/generate", http.MethodGet, false, http.StatusForbidden},
		{"auditor write waivers denied", auth.RoleAuditor, "/api/waivers", http.MethodPost, false, http.StatusForbidden},
		{"auditor write incidents denied", auth.RoleAuditor, "/api/incidents", http.MethodPost, false, http.StatusForbidden},

		// no user in context → always forbidden
		{"no user denied", auth.RoleAdmin, "/api/posture", http.MethodGet, true, http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if !tc.noUser {
				req = withUser(req, tc.role, "user@lab.edu")
			}
			rr := httptest.NewRecorder()
			cedarGuard(ps, ok200).ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Errorf("role=%s %s %s: got %d, want %d",
					tc.role, tc.method, tc.path, rr.Code, tc.wantStatus)
			}
		})
	}
}

func TestHandleEnvironments_PIFilter(t *testing.T) {
	// Build a sre.yaml with three environments: two owned by pi@lab.edu, one by other@lab.edu.
	dir := t.TempDir()
	sre := schema.SRE{
		OrgID: "o-testorg12345",
		Environments: map[string]schema.Environment{
			"env-001": {AccountID: "111111111111", Name: "Quantum Lab", Owner: "pi@lab.edu"},
			"env-002": {AccountID: "222222222222", Name: "Genomics Lab", Owner: "pi@lab.edu"},
			"env-003": {AccountID: "333333333333", Name: "Climate Modeling", Owner: "other@lab.edu"},
		},
	}
	data, err := yaml.Marshal(sre)
	if err != nil {
		t.Fatalf("marshal sre: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sre.yaml"), data, 0640); err != nil {
		t.Fatalf("write sre.yaml: %v", err)
	}

	s := &Server{storeDir: dir}

	envResponse := func(role auth.Role, email string) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/environments", nil)
		ctx := auth.WithUser(context.Background(), &auth.User{Role: role, Email: email})
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		s.handleEnvironments(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("handleEnvironments returned %d", rr.Code)
		}
		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		return resp
	}

	t.Run("pi_researcher sees only own environments", func(t *testing.T) {
		resp := envResponse(auth.RolePIResearcher, "pi@lab.edu")
		envs, ok := resp["environments"].(map[string]any)
		if !ok {
			t.Fatalf("environments field not a map: %T", resp["environments"])
		}
		if len(envs) != 2 {
			t.Errorf("expected 2 environments for pi@lab.edu, got %d", len(envs))
		}
		if _, hasOther := envs["env-003"]; hasOther {
			t.Error("pi@lab.edu should not see env-003 (owned by other@lab.edu)")
		}
	})

	t.Run("admin sees all environments", func(t *testing.T) {
		resp := envResponse(auth.RoleAdmin, "admin@lab.edu")
		envs, ok := resp["environments"].(map[string]any)
		if !ok {
			t.Fatalf("environments field not a map: %T", resp["environments"])
		}
		if len(envs) != 3 {
			t.Errorf("expected 3 environments for admin, got %d", len(envs))
		}
	})

	t.Run("auditor sees all environments", func(t *testing.T) {
		resp := envResponse(auth.RoleAuditor, "auditor@lab.edu")
		envs, ok := resp["environments"].(map[string]any)
		if !ok {
			t.Fatalf("environments field not a map: %T", resp["environments"])
		}
		if len(envs) != 3 {
			t.Errorf("expected 3 environments for auditor, got %d", len(envs))
		}
	})

	t.Run("pi_researcher with different email sees no environments", func(t *testing.T) {
		resp := envResponse(auth.RolePIResearcher, "stranger@lab.edu")
		envs, ok := resp["environments"].(map[string]any)
		if !ok {
			t.Fatalf("environments field not a map: %T", resp["environments"])
		}
		if len(envs) != 0 {
			t.Errorf("expected 0 environments for stranger@lab.edu, got %d", len(envs))
		}
	})
}
