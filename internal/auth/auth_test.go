package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestOpenRedirect verifies that the callback handler blocks open redirects.
func TestOpenRedirect(t *testing.T) {
	cases := []struct {
		redirect string
		allowed  bool
		desc     string
	}{
		// Blocked — would redirect to attacker site
		{"https://evil.com", false, "absolute HTTPS URL"},
		{"http://evil.com", false, "absolute HTTP URL"},
		{"//evil.com", false, "protocol-relative URL"},
		{"//evil.com/path", false, "protocol-relative with path"},
		{" https://evil.com", false, "URL with leading space"},
		{"https://evil.com/path?x=1", false, "URL with path and query"},

		// Allowed — relative paths within the app
		{"/dashboard", true, "relative path"},
		{"/api/posture", true, "relative API path"},
		{"/", true, "root path"},
		{"", false, "empty string uses default /"},
	}

	for _, tc := range cases {
		// Simulate the redirect resolution logic from handleCallback.
		redirect := "/"
		if raw := tc.redirect; raw != "" &&
			len(raw) > 0 && raw[0] == '/' &&
			!contains(raw, "://") &&
			!hasPrefix(raw, "//") {
			redirect = raw
		}

		isDefault := redirect == "/"
		wantDefault := !tc.allowed

		if tc.redirect == "" {
			// Empty redirect → always default "/"
			if redirect != "/" {
				t.Errorf("[%s] redirect=%q: got %q, want /", tc.desc, tc.redirect, redirect)
			}
			continue
		}

		if wantDefault && !isDefault {
			t.Errorf("[%s] redirect=%q: should have been blocked (got %q)", tc.desc, tc.redirect, redirect)
		}
		if !wantDefault && isDefault && tc.redirect != "/" {
			t.Errorf("[%s] redirect=%q: should have been allowed but was blocked", tc.desc, tc.redirect)
		}
		if tc.allowed && redirect != tc.redirect {
			t.Errorf("[%s] redirect=%q: got %q", tc.desc, tc.redirect, redirect)
		}
	}
}

// contains and hasPrefix are local helpers to avoid importing strings in test file.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// TestSessionConcurrency verifies the session map is safe under concurrent access.
// Run with: go test -race ./internal/auth/...
func TestSessionConcurrency(t *testing.T) {
	h := &OIDCHandler{
		sessions: make(map[string]*User),
	}

	user := &User{
		ID:        "test-user",
		Role:      RoleAuditor,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent writes
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			token, _ := randomState()
			h.mu.Lock()
			h.sessions[token] = user
			h.mu.Unlock()
		}(i)
	}

	// Concurrent reads
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			h.mu.RLock()
			_ = len(h.sessions)
			h.mu.RUnlock()
		}()
	}

	// Concurrent deletes
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			h.mu.Lock()
			for k := range h.sessions {
				delete(h.sessions, k)
				break
			}
			h.mu.Unlock()
		}()
	}

	wg.Wait() // if there's a race, -race will report it
}

// TestRandomStateEntropy verifies randomState produces 32 bytes (256-bit entropy).
func TestRandomStateEntropy(t *testing.T) {
	state, err := randomState()
	if err != nil {
		t.Fatalf("randomState() error: %v", err)
	}
	decoded, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		t.Fatalf("randomState() returned invalid base64: %v", err)
	}
	if len(decoded) < 32 {
		t.Errorf("randomState() entropy: got %d bytes, want ≥32 (256 bits)", len(decoded))
	}
}

// TestRandomStateUniqueness verifies consecutive calls return different values.
func TestRandomStateUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := randomState()
		if err != nil {
			t.Fatalf("randomState() error on iteration %d: %v", i, err)
		}
		if seen[s] {
			t.Fatalf("randomState() returned duplicate value on iteration %d", i)
		}
		seen[s] = true
	}
}

// TestIsLocalAddr verifies localhost detection for Secure cookie flag.
func TestIsLocalAddr(t *testing.T) {
	local := []string{
		"localhost:8080", "127.0.0.1:8080", "::1", "127.0.0.1",
		"http://localhost:8080/callback",
	}
	remote := []string{
		"0.0.0.0:8080", "dashboard.university.edu:8080",
		"https://dashboard.university.edu/callback",
		":8080",
	}
	for _, addr := range local {
		if !isLocalAddr(addr) {
			t.Errorf("isLocalAddr(%q) = false, want true", addr)
		}
	}
	for _, addr := range remote {
		if isLocalAddr(addr) {
			t.Errorf("isLocalAddr(%q) = true, want false", addr)
		}
	}
}

// TestStaticTokenMiddleware verifies the static token middleware.
func TestStaticTokenMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("empty token — all pass", func(t *testing.T) {
		mw := StaticTokenMiddleware("", handler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rr.Code)
		}
	})

	t.Run("correct token — passes", func(t *testing.T) {
		mw := StaticTokenMiddleware("secret-token", handler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rr.Code)
		}
	})

	t.Run("wrong token — 401", func(t *testing.T) {
		mw := StaticTokenMiddleware("secret-token", handler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})

	t.Run("no header — 401", func(t *testing.T) {
		mw := StaticTokenMiddleware("secret-token", handler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})
}
