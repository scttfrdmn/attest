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
//   - Tests & Deploy: policy test results, proposed artifacts, git/IaC status
//   - Generate: one-click document generation (SSP, POA&M, OSCAL)
//   - AI Analyst: interactive compliance analyst agent
package dashboard

import (
	"context"
	"fmt"
	"net/http"
)

// Server is the attest web dashboard.
type Server struct {
	addr string
	mux  *http.ServeMux
}

// NewServer creates a dashboard server.
func NewServer(addr string) *Server {
	s := &Server{
		addr: addr,
		mux:  http.NewServeMux(),
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

// Start launches the dashboard server.
func (s *Server) Start(ctx context.Context) error {
	return fmt.Errorf("not implemented")
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request)         {}
func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request)       {}
func (s *Server) handleFrameworks(w http.ResponseWriter, r *http.Request)    {}
func (s *Server) handleOperationsSSE(w http.ResponseWriter, r *http.Request) {}
func (s *Server) handleEnvironments(w http.ResponseWriter, r *http.Request)  {}
func (s *Server) handleWaivers(w http.ResponseWriter, r *http.Request)       {}
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request)     {}
func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request)      {}
