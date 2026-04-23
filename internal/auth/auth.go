// Package auth implements OIDC-based authentication and Cedar authorization
// for the attest dashboard. Supports institutional SSO (Shibboleth, Okta,
// Azure AD, any OIDC-compliant IdP) via OAuth2/OIDC code flow.
//
// Roles are mapped from OIDC claims and enforced by Cedar policies:
//   - admin: full access, deploy policies, manage waivers
//   - compliance_officer: view all posture, generate documents, manage waivers
//   - security_engineer: view all, operate Cedar PDP, review proposed policies
//   - pi_researcher: view own environments only
//   - auditor: read-only access to everything, cannot deploy
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	oidclib "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
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

// sessionCookieName is the name of the session cookie.
const sessionCookieName = "attest_session"

// sessionMaxAge is how long a session cookie lasts.
// 4 hours — reduced from 8h; appropriate for an administrative security tool.
const sessionMaxAge = 4 * time.Hour

// User is an authenticated dashboard user.
type User struct {
	ID         string
	Name       string
	Email      string
	Role       Role
	AuthMethod string // "oidc", "token"
	ExpiresAt  time.Time
}

// OIDCConfig holds the configuration for OIDC authentication.
type OIDCConfig struct {
	IssuerURL    string // e.g., "https://sso.university.edu"
	ClientID     string // from ATTEST_OIDC_CLIENT_ID
	ClientSecret string // from ATTEST_OIDC_CLIENT_SECRET; never log this value
	RedirectURL  string // e.g., "http://localhost:8080/callback"
	// RoleClaim is the OIDC claim name that maps to a dashboard role.
	// Defaults to "attest_role". Common alternatives: "groups", "roles".
	RoleClaim string
	// RoleMapping maps claim values to dashboard roles.
	// e.g., {"compliance-officers": "compliance_officer", "it-admins": "admin"}
	RoleMapping map[string]Role
}

// OIDCHandler implements OIDC login/callback/logout for the dashboard.
type OIDCHandler struct {
	cfg      *OIDCConfig
	provider *oidclib.Provider
	oauth2   oauth2.Config
	verifier *oidclib.IDTokenVerifier
	// mu protects sessions from concurrent access (multiple HTTP goroutines).
	mu       sync.RWMutex
	// sessions is an in-memory session store: token → User.
	// Sessions are lost on restart. For HA deployments, replace with a
	// signed cookie (JWT) or external store (Redis).
	sessions map[string]*User
}

// NewOIDCHandler creates an OIDC auth handler. Call RegisterRoutes(mux) to wire it.
func NewOIDCHandler(ctx context.Context, cfg *OIDCConfig) (*OIDCHandler, error) {
	provider, err := oidclib.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discovering OIDC provider at %s: %w", cfg.IssuerURL, err)
	}

	h := &OIDCHandler{
		cfg:      cfg,
		provider: provider,
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidclib.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.Verifier(&oidclib.Config{ClientID: cfg.ClientID}),
		sessions: make(map[string]*User),
	}
	return h, nil
}

// RegisterRoutes adds /login, /callback, /logout to the given mux.
func (h *OIDCHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/callback", h.handleCallback)
	mux.HandleFunc("/logout", h.handleLogout)
}

// Middleware returns an HTTP middleware that validates the session cookie.
// Routes that don't require auth (e.g., /login) should be registered before this.
func (h *OIDCHandler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow /login, /callback, /logout without auth.
		if r.URL.Path == "/login" || r.URL.Path == "/callback" || r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login?redirect="+url.QueryEscape(r.URL.Path), http.StatusFound) // nosemgrep: go.lang.security.injection.open-redirect.open-redirect
			return
		}

		h.mu.RLock()
		user, ok := h.sessions[cookie.Value]
		h.mu.RUnlock()

		if !ok || user == nil || time.Now().After(user.ExpiresAt) {
			h.mu.Lock()
			delete(h.sessions, cookie.Value)
			h.mu.Unlock()
			http.Redirect(w, r, "/login?redirect="+url.QueryEscape(r.URL.Path), http.StatusFound) // nosemgrep: go.lang.security.injection.open-redirect.open-redirect
			return
		}

		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), user)))
	})
}

func (h *OIDCHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomState()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Store state in a short-lived cookie to prevent CSRF.
	http.SetCookie(w, &http.Cookie{ // nosemgrep: go.lang.security.audit.net.cookie-missing-secure
		Name:     "oidc_state",
		Value:    state,
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   !isLocalAddr(h.oauth2.RedirectURL),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, h.oauth2.AuthCodeURL(state), http.StatusFound)
}

func (h *OIDCHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Validate state — use constant-time comparison to prevent timing oracle.
	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || subtle.ConstantTimeCompare(
		[]byte(r.URL.Query().Get("state")),
		[]byte(stateCookie.Value),
	) != 1 {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	// Clear state cookie — flags must match the original for browsers to honour the deletion.
	http.SetCookie(w, &http.Cookie{ // nosemgrep: go.lang.security.audit.net.cookie-missing-secure
		Name:     "oidc_state",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !isLocalAddr(h.oauth2.RedirectURL),
		SameSite: http.SameSiteLaxMode,
	})

	// Exchange code for token.
	token, err := h.oauth2.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	// Verify ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}
	idToken, err := h.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "id_token verification failed", http.StatusUnauthorized)
		return
	}

	// Extract claims.
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "claims extraction failed", http.StatusInternalServerError)
		return
	}

	user := &User{
		ID:         idToken.Subject,
		Name:       stringClaim(claims, "name"),
		Email:      stringClaim(claims, "email"),
		Role:       h.resolveRole(claims),
		AuthMethod: "oidc",
		ExpiresAt:  time.Now().Add(sessionMaxAge),
	}

	// Create session.
	sessionToken, err := randomState()
	if err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	h.sessions[sessionToken] = user
	h.mu.Unlock()

	// Set session cookie. Secure flag is true when not on localhost.
	http.SetCookie(w, &http.Cookie{ // nosemgrep: go.lang.security.audit.net.cookie-missing-secure
		Name:     sessionCookieName,
		Value:    sessionToken,
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   !isLocalAddr(h.oauth2.RedirectURL),
		SameSite: http.SameSiteLaxMode,
	})

	// Validate redirect — only accept relative paths to prevent open redirect.
	redirect := "/"
	if raw := r.URL.Query().Get("redirect"); raw != "" &&
		strings.HasPrefix(raw, "/") &&
		!strings.Contains(raw, "://") &&
		!strings.HasPrefix(raw, "//") {
		redirect = raw
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *OIDCHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		h.mu.Lock()
		delete(h.sessions, cookie.Value)
		h.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{ // nosemgrep: go.lang.security.audit.net.cookie-missing-secure
		Name:     sessionCookieName,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !isLocalAddr(h.oauth2.RedirectURL),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// resolveRole maps OIDC claims to a dashboard role.
func (h *OIDCHandler) resolveRole(claims map[string]any) Role {
	roleClaim := h.cfg.RoleClaim
	if roleClaim == "" {
		roleClaim = "attest_role"
	}

	// Try direct role claim first.
	if v, ok := claims[roleClaim].(string); ok {
		if role, ok := h.cfg.RoleMapping[v]; ok {
			return role
		}
		switch Role(v) {
		case RoleAdmin, RoleComplianceOfficer, RoleSecurityEngineer, RolePIResearcher, RoleAuditor:
			return Role(v)
		}
	}

	// Try groups claim (array of strings).
	if groups, ok := claims[roleClaim].([]any); ok {
		for _, g := range groups {
			if gs, ok := g.(string); ok {
				if role, ok := h.cfg.RoleMapping[gs]; ok {
					return role
				}
			}
		}
	}

	// Default to auditor (read-only) for authenticated users with no explicit role.
	return RoleAuditor
}

// isLocalAddr reports whether an address string refers to a loopback/localhost
// endpoint. Used to decide whether session cookies should be Secure-only.
func isLocalAddr(addr string) bool {
	return strings.Contains(addr, "localhost") ||
		strings.Contains(addr, "127.0.0.1") ||
		strings.Contains(addr, "::1")
}

// --- context helpers ---

// userContextKey is the context key for the authenticated user.
type userContextKey struct{}

// WithUser stores an authenticated user in the request context.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userContextKey{}, u)
}

// UserFromContext extracts the authenticated user from the request context.
func UserFromContext(ctx context.Context) (*User, error) {
	u, ok := ctx.Value(userContextKey{}).(*User)
	if !ok || u == nil {
		return nil, fmt.Errorf("no authenticated user in context")
	}
	return u, nil
}

// --- utility helpers ---

// randomState generates a cryptographically random 256-bit (32-byte) state token,
// base64url-encoded. Used for OIDC state parameter and session tokens.
func randomState() (string, error) {
	b := make([]byte, 32) // 256 bits — was 16 (128 bits); increased per NIST recommendation
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// SerializeUser serializes a User to JSON (for logging/debugging — never log tokens).
func SerializeUser(u *User) (string, error) {
	b, err := json.Marshal(u)
	return string(b), err
}

// --- static token auth (kept for local/CI use) ---

// StaticTokenMiddleware returns HTTP middleware that validates a static bearer token.
// Used with attest serve --auth when OIDC is not configured.
func StaticTokenMiddleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
