// Package grc provides a client for pushing OSCAL compliance documents to
// enterprise GRC (Governance, Risk, and Compliance) platforms via HTTP.
//
// Supported platforms:
//   - ServiceNow GRC (POST to /api/now/table/sn_grc_document)
//   - RSA Archer (POST to /api/core/content/application/<id>)
//   - Generic OSCAL receiver (any HTTP endpoint accepting JSON)
//
// Auth: ATTEST_GRC_TOKEN environment variable (Bearer token or API key).
// Never pass tokens on the command line — they appear in process listings.
package grc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Platform identifies the target GRC system for endpoint/header configuration.
type Platform string

const (
	PlatformServiceNow Platform = "servicenow"
	PlatformArcher     Platform = "archer"
	PlatformGeneric    Platform = "generic"
)

// PushResult records the outcome of a single push operation.
type PushResult struct {
	DocumentType string    // "ssp", "assessment", "posture"
	Endpoint     string
	StatusCode   int
	PushedAt     time.Time
	Error        string
}

// Client pushes OSCAL documents to a GRC platform endpoint.
type Client struct {
	endpoint   string
	platform   Platform
	token      string
	httpClient *http.Client
	dryRun     bool
}

// NewClient creates a GRC push client.
// Token is read from ATTEST_GRC_TOKEN env var; endpoint from the --endpoint flag.
func NewClient(endpoint string, platform Platform, dryRun bool) (*Client, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("GRC endpoint is required (--endpoint <url>)")
	}
	token := os.Getenv("ATTEST_GRC_TOKEN")
	// Token is optional for generic receivers that use other auth (e.g., mTLS)
	return &Client{
		endpoint: endpoint,
		platform: platform,
		token:    token,
		dryRun:   dryRun,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Push sends an OSCAL document (pre-marshaled JSON) to the configured endpoint.
// The docType parameter is used for logging ("ssp", "assessment", "posture").
func (c *Client) Push(ctx context.Context, docType string, payload []byte) (*PushResult, error) {
	result := &PushResult{
		DocumentType: docType,
		Endpoint:     c.endpoint,
		PushedAt:     time.Now().UTC(),
	}

	if c.dryRun {
		// In dry-run mode, print the payload that would be sent.
		fmt.Printf("DRY RUN — would POST %s to %s\n", docType, c.endpoint)
		fmt.Printf("Payload (%d bytes):\n%s\n", len(payload), truncate(string(payload), 500))
		return result, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "attest/0.11.0")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	c.setPlatformHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 400 {
		result.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		return result, fmt.Errorf("GRC push failed: %s", result.Error)
	}

	return result, nil
}

// PushWithRetry wraps Push with exponential backoff on server errors (5xx).
// 4xx errors (bad request, unauthorized) are not retried.
func (c *Client) PushWithRetry(ctx context.Context, docType string, payload []byte, maxRetries int) (*PushResult, error) {
	var lastErr error
	backoff := 2 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				if backoff > 60*time.Second {
					backoff = 60 * time.Second
				}
			}
		}

		result, err := c.Push(ctx, docType, payload)
		if err == nil {
			return result, nil
		}

		// Don't retry on 4xx (client errors) — fix the request.
		if result != nil && result.StatusCode >= 400 && result.StatusCode < 500 {
			return result, err
		}

		lastErr = err
		if attempt < maxRetries {
			fmt.Printf("  Retry %d/%d after %s (last error: %v)\n", attempt+1, maxRetries, backoff, err)
		}
	}
	return nil, fmt.Errorf("push failed after %d retries: %w", maxRetries, lastErr)
}

// WatchAndPush watches the posture history directory for new snapshots and
// pushes them to the GRC endpoint. Blocks until ctx is cancelled.
func (c *Client) WatchAndPush(ctx context.Context, historyDir string, generateFn func() ([]byte, error), interval time.Duration) error {
	fmt.Printf("Watching for posture changes (interval: %s)...\n", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			payload, err := generateFn()
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: could not generate OSCAL payload: %v\n", err)
				continue
			}
			result, err := c.PushWithRetry(ctx, "posture", payload, 3)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: push failed: %v\n", err)
				continue
			}
			fmt.Printf("  Pushed posture snapshot to %s (HTTP %d)\n", result.Endpoint, result.StatusCode)
		}
	}
}

// setPlatformHeaders sets platform-specific HTTP headers.
func (c *Client) setPlatformHeaders(req *http.Request) {
	switch c.platform {
	case PlatformServiceNow:
		req.Header.Set("Accept", "application/json")
		// ServiceNow GRC uses X-WantSessionNotifications for async delivery
	case PlatformArcher:
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Http-Method-Override", "PUT") // Archer uses override header
	}
}

// truncate returns the first n chars of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
