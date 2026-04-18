package grc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNewClient_RequiresEndpoint(t *testing.T) {
	_, err := NewClient("", PlatformGeneric, false)
	if err == nil {
		t.Error("NewClient with empty endpoint should return error")
	}
}

func TestNewClient_Success(t *testing.T) {
	c, err := NewClient("https://example.com/api/oscal", PlatformGeneric, false)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if c == nil {
		t.Fatal("NewClient() returned nil client")
	}
}

func TestPush_Success(t *testing.T) {
	var receivedBody []byte
	var receivedAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		receivedBody = buf[:n]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Use newClientDirect for localhost test server (bypasses SSRF validation).
	c := newClientDirect(srv.URL, PlatformGeneric, false, "test-secret-token")
	payload := []byte(`{"system-security-plan":{"uuid":"test-uuid"}}`)
	result, err := c.Push(context.Background(), "ssp", payload)
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}

	// Verify Authorization header is set from env var.
	if receivedAuth != "Bearer test-secret-token" {
		t.Errorf("Authorization = %q, want 'Bearer test-secret-token'", receivedAuth)
	}

	// Verify payload was transmitted.
	if string(receivedBody) != string(payload) {
		t.Errorf("received body %q, want %q", receivedBody, payload)
	}
}

func TestPush_NoTokenWhenEnvNotSet(t *testing.T) {
	os.Unsetenv("ATTEST_GRC_TOKEN")
	var receivedAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newClientDirect(srv.URL, PlatformGeneric, false, "")
	_, err := c.Push(context.Background(), "ssp", []byte(`{}`))
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}
	if receivedAuth != "" {
		t.Errorf("Authorization header set when no token configured: %q", receivedAuth)
	}
}

func TestPush_FailFastOn4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newClientDirect(srv.URL, PlatformGeneric, false, "")
	result, err := c.Push(context.Background(), "ssp", []byte(`{}`))
	if err == nil {
		t.Error("Push() should return error on 401")
	}
	if result == nil || result.StatusCode != 401 {
		t.Errorf("expected result with StatusCode=401, got %v", result)
	}
}

func TestPush_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newClientDirect(srv.URL, PlatformGeneric, false, "")
	result, err := c.Push(context.Background(), "ssp", []byte(`{}`))
	if err == nil {
		t.Error("Push() should return error on 500")
	}
	if result == nil || result.StatusCode != 500 {
		t.Errorf("expected result with StatusCode=500, got %v", result)
	}
}

func TestPush_DryRun(t *testing.T) {
	// In dry-run mode, no HTTP request should be made.
	c, _ := NewClient("https://this-should-not-be-called.example.com", PlatformGeneric, true)
	result, err := c.Push(context.Background(), "ssp", []byte(`{"test":"payload"}`))
	if err != nil {
		t.Fatalf("dry-run Push() error: %v", err)
	}
	if result == nil {
		t.Fatal("dry-run should return a result")
	}
	// No status code since no real request was made.
	if result.StatusCode != 0 {
		t.Errorf("dry-run StatusCode = %d, want 0", result.StatusCode)
	}
}

func TestPlatformHeaders_ServiceNow(t *testing.T) {
	var receivedAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newClientDirect(srv.URL, PlatformServiceNow, false, "")
	_, _ = c.Push(context.Background(), "ssp", []byte(`{}`))
	if receivedAccept != "application/json" {
		t.Errorf("ServiceNow Accept header = %q, want application/json", receivedAccept)
	}
}

// TestNewClient_SSRFPrevention covers the CRITICAL SSRF fix: endpoint validation.
func TestNewClient_SSRFPrevention(t *testing.T) {
	ssrfURLs := []struct {
		url  string
		desc string
	}{
		{"http://169.254.169.254/latest/meta-data/", "AWS metadata endpoint"},
		{"http://127.0.0.1:6379", "localhost Redis"},
		{"http://localhost:9200", "localhost Elasticsearch"},
		{"file:///etc/passwd", "file:// scheme"},
		{"ftp://internal.example.com", "ftp:// scheme"},
		{"http://10.0.0.1/api", "private RFC 1918 IP"},
		{"http://192.168.1.1/", "private RFC 1918 IP"},
		{"http://172.16.0.1/", "private RFC 1918 IP"},
	}
	for _, tc := range ssrfURLs {
		_, err := NewClient(tc.url, PlatformGeneric, false)
		if err == nil {
			t.Errorf("NewClient(%q) should be rejected (%s)", tc.url, tc.desc)
		}
	}
}

func TestNewClient_SafeURLs(t *testing.T) {
	safeURLs := []string{
		"https://company.service-now.com/api/now/table/sn_grc_document",
		"https://archer.company.com/api/core",
		"http://grc.research.university.edu/api/oscal",
		"https://api.example.com:8443/oscal",
	}
	for _, u := range safeURLs {
		c, err := NewClient(u, PlatformGeneric, false)
		if err != nil {
			t.Errorf("NewClient(%q) should be valid, got: %v", u, err)
		}
		if c == nil {
			t.Errorf("NewClient(%q) returned nil", u)
		}
	}
}

func TestValidatePlatform(t *testing.T) {
	valid := []string{"servicenow", "archer", "generic"}
	for _, p := range valid {
		platform, err := ValidatePlatform(p)
		if err != nil {
			t.Errorf("ValidatePlatform(%q) error: %v", p, err)
		}
		if string(platform) == "" {
			t.Errorf("ValidatePlatform(%q) returned empty platform", p)
		}
	}

	invalid := []string{"unknown", "../../etc", "SERVICENOW", ""}
	for _, p := range invalid {
		_, err := ValidatePlatform(p)
		if err == nil {
			t.Errorf("ValidatePlatform(%q) should return error", p)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("truncate = %q, want hello...", got)
	}
	if got := truncate("short", 100); got != "short" {
		t.Errorf("truncate short string = %q, want short", got)
	}
}

func TestPushResult_DocumentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := newClientDirect(srv.URL, PlatformGeneric, false, "")
	result, err := c.Push(context.Background(), "assessment", []byte(`{}`))
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}
	if result.DocumentType != "assessment" {
		t.Errorf("DocumentType = %q, want assessment", result.DocumentType)
	}
	if !strings.Contains(result.Endpoint, srv.URL) {
		t.Errorf("Endpoint = %q, want to contain %s", result.Endpoint, srv.URL)
	}
}
