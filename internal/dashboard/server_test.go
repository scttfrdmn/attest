package dashboard

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// TestAuthMiddleware verifies the bearer token middleware behaviour.
func TestAuthMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("no auth token configured — all requests pass", func(t *testing.T) {
		s := &Server{authToken: ""}
		mw := s.authMiddleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("correct token — request passes", func(t *testing.T) {
		s := &Server{authToken: "correct-secret-token-16chars"}
		mw := s.authMiddleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer correct-secret-token-16chars")
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("wrong token — 401", func(t *testing.T) {
		s := &Server{authToken: "correct-secret-token-16chars"}
		mw := s.authMiddleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rr.Code)
		}
	})

	t.Run("missing Authorization header — 401 when auth enabled", func(t *testing.T) {
		s := &Server{authToken: "some-token-long-enough"}
		mw := s.authMiddleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rr.Code)
		}
	})

	t.Run("wrong scheme (Basic) — 401", func(t *testing.T) {
		s := &Server{authToken: "some-token-long-enough"}
		mw := s.authMiddleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic some-token-long-enough")
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rr.Code)
		}
	})
}

// TestSSEConnectionLimit verifies the maxSSEConnections enforcement.
func TestSSEConnectionLimit(t *testing.T) {
	s := &Server{storeDir: t.TempDir()}

	// Pre-fill the connection counter to one below the limit.
	atomic.StoreInt64(&s.sseConns, maxSSEConnections-1)

	// The handler will increment to maxSSEConnections, then block waiting for events.
	// We can't easily test the full SSE flow without a real connection,
	// but we CAN verify the 429 path by filling to the limit first.

	// Pre-fill to the limit.
	atomic.StoreInt64(&s.sseConns, maxSSEConnections)

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/operations/stream", nil)
	s.handleOperationsSSE(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 (Too Many Requests)", rr2.Code)
	}

	// Verify counter is decremented after rejection.
	// (The handler decrements even on rejection because we used defer)
	// After rejection at maxSSEConnections, count should stay at maxSSEConnections
	// (the +1 and -1 cancel out).
	finalCount := atomic.LoadInt64(&s.sseConns)
	if finalCount != maxSSEConnections {
		t.Errorf("sseConns after rejection = %d, want %d", finalCount, maxSSEConnections)
	}
}

// TestSSEConnectionCounterDecrement verifies concurrent safety.
func TestSSEConnectionCounterDecrement(t *testing.T) {
	s := &Server{storeDir: t.TempDir()}
	atomic.StoreInt64(&s.sseConns, 0)

	// Simulate maxSSEConnections+10 concurrent requests at the limit.
	// All should get 429 since we pre-set the counter.
	atomic.StoreInt64(&s.sseConns, maxSSEConnections)

	var wg sync.WaitGroup
	rejected := int64(0)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/operations/stream", nil)
			s.handleOperationsSSE(rr, req)
			if rr.Code == http.StatusTooManyRequests {
				atomic.AddInt64(&rejected, 1)
			}
		}()
	}
	wg.Wait()

	if rejected != 10 {
		t.Errorf("rejected = %d, want 10", rejected)
	}
	// Counter should return to maxSSEConnections (each request increments then decrements).
	if got := atomic.LoadInt64(&s.sseConns); got != maxSSEConnections {
		t.Errorf("sseConns after concurrent rejections = %d, want %d", got, maxSSEConnections)
	}
}

// TestHandlePostureContentType verifies JSON content type on API endpoints.
func TestHandlePostureContentType(t *testing.T) {
	s := &Server{storeDir: t.TempDir()} // no crosswalk → returns error JSON

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	rr := httptest.NewRecorder()
	s.handlePosture(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
