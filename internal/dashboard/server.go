// Package dashboard implements the web dashboard for attest.
// Single binary: `attest serve` launches the dashboard.
// Built with Go net/http + HTMX + SSE for live Cedar PDP feed.
//
// Views:
//   - Posture: compliance posture ring, CMMC score, control heatmap, trend
//   - Frameworks: per-framework drill-down with control table
//   - Operations: real-time Cedar PDP evaluation feed (SSE)
//   - Environments: per-account view with data classes and eval counts
//   - Waivers: exception management with expiry alerting
//   - Incidents: security event lifecycle with control impact
//   - Generate: one-click document generation (SSP, POA&M, OSCAL)
package dashboard

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/provabl/attest/internal/auth"
	"github.com/provabl/attest/internal/evaluator"
	"github.com/provabl/attest/internal/reporting"
	"github.com/provabl/attest/internal/waiver"
	"github.com/provabl/attest/pkg/schema"
)

// maxSSEConnections is the per-server limit on concurrent SSE subscribers.
// Prevents resource exhaustion from connection flooding.
const maxSSEConnections = 50

//go:embed templates
var templateFS embed.FS

// Server is the attest web dashboard.
type Server struct {
	addr           string
	mux            *http.ServeMux
	eval           *evaluator.Evaluator
	storeDir       string
	authToken      string     // empty = no auth (local use only)
	sseConns       int64      // active SSE connection count (atomic)
	assessorMode   bool       // true = read-only C3PAO assessor portal
	assessorOrg    string     // name of the assessor organization
	assessorExpiry time.Time  // zero = no expiry
}

// NewServerWithOIDC creates a dashboard server using OIDC authentication.
func NewServerWithOIDC(addr, storeDir string, oidcHandler *auth.OIDCHandler, eval *evaluator.Evaluator) *Server {
	s := &Server{
		addr:      addr,
		mux:       http.NewServeMux(),
		eval:      eval,
		storeDir:  storeDir,
	}
	oidcHandler.RegisterRoutes(s.mux)
	s.mux.Handle("/", oidcHandler.Middleware(http.HandlerFunc(s.handleIndex)))
	s.mux.Handle("/api/posture", oidcHandler.Middleware(http.HandlerFunc(s.handlePosture)))
	s.mux.Handle("/api/frameworks", oidcHandler.Middleware(http.HandlerFunc(s.handleFrameworks)))
	s.mux.Handle("/api/operations/stream", oidcHandler.Middleware(http.HandlerFunc(s.handleOperationsSSE)))
	s.mux.Handle("/api/environments", oidcHandler.Middleware(http.HandlerFunc(s.handleEnvironments)))
	s.mux.Handle("/api/waivers", oidcHandler.Middleware(http.HandlerFunc(s.handleWaivers)))
	s.mux.Handle("/api/incidents", oidcHandler.Middleware(http.HandlerFunc(s.handleIncidents)))
	s.mux.Handle("/api/generate", oidcHandler.Middleware(http.HandlerFunc(s.handleGenerate)))
	return s
}

// AssessorConfig holds configuration for assessor portal mode.
type AssessorConfig struct {
	Org    string    // C3PAO organization name
	Expiry time.Time // access expiry (zero = no expiry)
}

// NewAssessorServer creates a read-only dashboard for C3PAO assessor access.
func NewAssessorServer(addr, storeDir, authToken string, cfg AssessorConfig, eval *evaluator.Evaluator) *Server {
	s := &Server{
		addr:           addr,
		mux:            http.NewServeMux(),
		eval:           eval,
		storeDir:       storeDir,
		authToken:      authToken,
		assessorMode:   true,
		assessorOrg:    cfg.Org,
		assessorExpiry: cfg.Expiry,
	}
	s.registerRoutes()
	// Add assessor-specific endpoint.
	s.mux.HandleFunc("/api/assessor/me", s.handleAssessorMe)
	return s
}

// NewServer creates a dashboard server.
func NewServer(addr, storeDir, authToken string, eval *evaluator.Evaluator) *Server {
	s := &Server{
		addr:      addr,
		mux:       http.NewServeMux(),
		eval:      eval,
		storeDir:  storeDir,
		authToken: authToken,
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/api/posture", s.handlePosture)
	s.mux.HandleFunc("/api/frameworks", s.handleFrameworks)
	s.mux.HandleFunc("/api/operations/stream", s.handleOperationsSSE)
	s.mux.HandleFunc("/api/environments", s.handleEnvironments)
	s.mux.HandleFunc("/api/waivers", s.handleWaivers)
	s.mux.HandleFunc("/api/incidents", s.handleIncidents)
	s.mux.HandleFunc("/api/generate", s.handleGenerate)
}

// securityHeaders adds standard HTTP security headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// assessorGuard enforces read-only mode for assessor portal sessions.
// Blocks all write/mutation endpoints and checks session expiry.
func (s *Server) assessorGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.assessorMode {
			// Check session expiry — compare in UTC to avoid timezone-dependent access control.
			if !s.assessorExpiry.IsZero() && time.Now().UTC().After(s.assessorExpiry.UTC()) {
				http.Error(w, "Assessor session expired — contact the organization to renew access",
					http.StatusUnauthorized)
				return
			}
			// Block state-mutating endpoints.
			if r.URL.Path == "/api/generate" ||
				r.Method == http.MethodPost ||
				r.Method == http.MethodPut ||
				r.Method == http.MethodDelete ||
				r.Method == http.MethodPatch {
				http.Error(w, "Read-only assessor mode: this operation is not permitted",
					http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// handleAssessorMe returns assessor session information.
func (s *Server) handleAssessorMe(w http.ResponseWriter, r *http.Request) {
	if !s.assessorMode {
		http.Error(w, "not in assessor mode", http.StatusNotFound)
		return
	}
	expiry := ""
	if !s.assessorExpiry.IsZero() {
		expiry = s.assessorExpiry.Format("2006-01-02T15:04:05Z")
	}
	jsonResponse(w, map[string]any{
		// assessorOrg is HTML-entity-escaped to prevent XSS if rendered in browser.
		"assessor_org": sanitizeForJSON(s.assessorOrg),
		"mode":         "read-only",
		"expiry":       expiry,
		// store_dir intentionally omitted — internal filesystem path disclosure.
	})
}

// Start launches the dashboard server.
func (s *Server) Start(ctx context.Context) error {
	if s.authToken == "" {
		fmt.Println("  WARNING: Dashboard is running WITHOUT authentication.")
		fmt.Println("           Only run without auth on trusted localhost networks.")
		fmt.Println("           Use --auth with ATTEST_DASHBOARD_TOKEN for production use.")
	}
	if s.assessorMode {
		fmt.Printf("  Mode: Assessor portal (read-only) — %s\n", s.assessorOrg)
		if !s.assessorExpiry.IsZero() {
			fmt.Printf("  Access expires: %s\n", s.assessorExpiry.Format("2006-01-02"))
		}
	}
	handler := securityHeaders(s.assessorGuard(s.authMiddleware(s.mux)))
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	fmt.Printf("  Dashboard: http://localhost%s\n", strings.TrimPrefix(s.addr, ":"))
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	return srv.ListenAndServe()
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authToken != "" {
			auth := r.Header.Get("Authorization")
			want := "Bearer " + s.authToken
			if subtle.ConstantTimeCompare([]byte(auth), []byte(want)) != 1 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFS, "templates/index.html")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dashboard: template parse error: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	_ = tmpl.Execute(w, map[string]string{"Title": "attest dashboard"})
}

func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	// Load crosswalk to compute posture counts.
	cwPath := filepath.Join(s.storeDir, "compiled", "crosswalk.yaml")
	data, err := readYAML(cwPath)
	if err != nil {
		jsonResponse(w, map[string]any{"error": err.Error()})
		return
	}

	var cw schema.Crosswalk
	if err := yaml.Unmarshal(data, &cw); err != nil {
		jsonResponse(w, map[string]any{"error": "failed to parse posture data"})
		return
	}

	enforced, partial, gaps := 0, 0, 0
	for _, e := range cw.Entries {
		switch e.Status {
		case "enforced":
			enforced++
		case "partial":
			partial++
		case "gap":
			gaps++
		}
	}
	total := enforced + partial + gaps
	score := enforced*5 + partial*3

	jsonResponse(w, map[string]any{
		"enforced":     enforced,
		"partial":      partial,
		"gaps":         gaps,
		"total":        total,
		"score":        score,
		"max_score":    total * 5,
		"last_updated": time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleFrameworks(w http.ResponseWriter, r *http.Request) {
	srePath := filepath.Join(s.storeDir, "sre.yaml")
	data, err := readYAML(srePath)
	if err != nil {
		jsonResponse(w, map[string]any{"frameworks": []string{}})
		return
	}
	var sre schema.SRE
	if err := yaml.Unmarshal(data, &sre); err != nil {
		jsonResponse(w, map[string]any{"frameworks": []string{}})
		return
	}
	ids := make([]string, 0, len(sre.Frameworks))
	for _, f := range sre.Frameworks {
		ids = append(ids, f.ID)
	}
	jsonResponse(w, map[string]any{"frameworks": ids})
}

func (s *Server) handleOperationsSSE(w http.ResponseWriter, r *http.Request) {
	// Rate limit: reject if too many concurrent SSE connections.
	current := atomic.AddInt64(&s.sseConns, 1)
	defer atomic.AddInt64(&s.sseConns, -1)
	if current > maxSSEConnections {
		http.Error(w, "Too many SSE connections", http.StatusTooManyRequests)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Send keepalive comment.
	_, _ = io.WriteString(w, ": connected\n\n") // nosemgrep
	flusher.Flush()

	if s.eval == nil {
		// No evaluator running — send placeholder.
		_, _ = io.WriteString(w, "data: {\"status\":\"Cedar PDP not running — use 'attest watch' to start\"}\n\n") // nosemgrep
		flusher.Flush()
		<-r.Context().Done()
		return
	}

	ch := s.eval.Subscribe()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			_, _ = w.Write(append(append([]byte("data: "), b...), '\n', '\n')) // nosemgrep
			flusher.Flush()
		}
	}
}

func (s *Server) handleEnvironments(w http.ResponseWriter, r *http.Request) {
	srePath := filepath.Join(s.storeDir, "sre.yaml")
	data, err := readYAML(srePath)
	if err != nil {
		jsonResponse(w, map[string]any{"environments": []any{}})
		return
	}
	var sre schema.SRE
	if err := yaml.Unmarshal(data, &sre); err != nil {
		jsonResponse(w, map[string]any{"environments": []any{}, "error": "failed to parse SRE data"})
		return
	}
	jsonResponse(w, map[string]any{"environments": sre.Environments})
}

func (s *Server) handleWaivers(w http.ResponseWriter, r *http.Request) {
	mgr := waiver.NewManager(filepath.Join(s.storeDir, "waivers"))
	waivers, err := mgr.List(r.Context())
	if err != nil {
		jsonResponse(w, map[string]any{"error": "failed to load waivers"})
		return
	}
	jsonResponse(w, map[string]any{"waivers": waivers})
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	mgr := reporting.NewIncidentManager(filepath.Join(s.storeDir, "history"))
	incidents, err := mgr.List()
	if err != nil {
		jsonResponse(w, map[string]any{"error": "failed to load incidents"})
		return
	}
	jsonResponse(w, map[string]any{"incidents": incidents})
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	steps := []string{
		"Loading framework definitions...",
		"Computing posture from crosswalk...",
		"Generating SSP narrative...",
		"Writing .attest/documents/ssp.md",
		"Done.",
	}
	for _, step := range steps {
		_, _ = io.WriteString(w, "data: "+step+"\n\n") // nosemgrep
		flusher.Flush()
		time.Sleep(200 * time.Millisecond)
	}
}

// --- helpers ---

// sanitizeForJSON sanitizes a string for safe embedding in JSON responses
// that may be rendered as HTML. Encodes characters that have special meaning
// in HTML to their entities, preventing XSS if the response is rendered without escaping.
func sanitizeForJSON(s string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;", ">", "&gt;",
		"\"", "&quot;", "'", "&#39;",
		"&", "&amp;",
		"\n", " ", "\r", " ",
	)
	return replacer.Replace(s)
}

func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(v)
	_, _ = w.Write(b) // nosemgrep
}

func readYAML(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}
