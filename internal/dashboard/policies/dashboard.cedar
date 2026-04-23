// Dashboard authorization policies for attest.
// Evaluated per-request by cedarGuard in cedar_authz.go.
//
// Entity model:
//   Principal: DashboardUser::"<email>"  { role: String, email: String }
//   Action:    DashboardAction::"<id>"   (see dashboardAction() for mappings)
//   Resource:  DashboardEndpoint::"<path>"

// admin: full access to all dashboard endpoints.
permit(principal, action, resource)
when { principal.role == "admin" };

// compliance_officer: same as admin for dashboard purposes.
permit(principal, action, resource)
when { principal.role == "compliance_officer" };

// security_engineer: all reads, incidents write, operations SSE.
// Cannot generate documents or write waivers.
permit(principal, action, resource)
when {
    principal.role == "security_engineer" &&
    (action == DashboardAction::"read:index"         ||
     action == DashboardAction::"read:posture"       ||
     action == DashboardAction::"read:frameworks"    ||
     action == DashboardAction::"read:environments"  ||
     action == DashboardAction::"read:waivers"       ||
     action == DashboardAction::"read:incidents"     ||
     action == DashboardAction::"write:incidents"    ||
     action == DashboardAction::"stream:operations")
};

// pi_researcher: posture, frameworks, and own environments only.
// Environment ownership filtering is enforced server-side in handleEnvironments.
permit(principal, action, resource)
when {
    principal.role == "pi_researcher" &&
    (action == DashboardAction::"read:index"        ||
     action == DashboardAction::"read:posture"      ||
     action == DashboardAction::"read:frameworks"   ||
     action == DashboardAction::"read:environments")
};

// auditor: read-only access to posture, frameworks, environments, waivers, incidents.
// No operations SSE, no generate, no write operations.
permit(principal, action, resource)
when {
    principal.role == "auditor" &&
    (action == DashboardAction::"read:index"         ||
     action == DashboardAction::"read:posture"       ||
     action == DashboardAction::"read:frameworks"    ||
     action == DashboardAction::"read:environments"  ||
     action == DashboardAction::"read:waivers"       ||
     action == DashboardAction::"read:incidents")
};
