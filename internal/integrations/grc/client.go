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
	"net"
	"net/http"
	"net/url"
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

	// maxRetryLimit caps PushWithRetry to prevent infinite loops.
	maxRetryLimit = 10
)

// ValidPlatforms is the set of recognised platform identifiers.
var ValidPlatforms = map[string]Platform{
	"servicenow": PlatformServiceNow,
	"archer":     PlatformArcher,
	"generic":    PlatformGeneric,
}

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
// Validates that endpoint is a safe http(s) URL (not a private IP, localhost, or
// non-HTTP scheme) to prevent SSRF attacks.
// Token is read from ATTEST_GRC_TOKEN env var; endpoint from the --endpoint flag.
func NewClient(endpoint string, platform Platform, dryRun bool) (*Client, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("GRC endpoint is required (--endpoint <url>)")
	}

	// SSRF protection: validate endpoint is a safe external https/http URL.
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}

	token := os.Getenv("ATTEST_GRC_TOKEN")
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

// validateEndpoint ensures the URL uses http(s) and does not target private IPs
// or localhost (SSRF prevention).
func validateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("endpoint must use http or https scheme, got: %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("endpoint must include a hostname")
	}
	// Reject localhost and loopback.
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
		return fmt.Errorf("endpoint cannot target localhost — GRC platforms are external services")
	}
	// Reject link-local (AWS metadata service is 169.254.169.254).
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
			return fmt.Errorf("endpoint cannot target private/internal IP address: %s", host)
		}
	}
	return nil
}

// ValidatePlatform returns the Platform constant for a given string, or an error.
func ValidatePlatform(s string) (Platform, error) {
	p, ok := ValidPlatforms[s]
	if !ok {
		keys := make([]string, 0, len(ValidPlatforms))
		for k := range ValidPlatforms {
			keys = append(keys, k)
		}
		return "", fmt.Errorf("--platform must be one of %s, got: %q", strings.Join(keys, ", "), s)
	}
	return p, nil
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
		// Don't include raw response body in error (may contain sensitive data).
		result.Error = fmt.Sprintf("HTTP %d: server returned error", resp.StatusCode)
		_ = body // consumed but not propagated
		return result, fmt.Errorf("GRC push failed: %s", result.Error)
	}

	return result, nil
}

// PushWithRetry wraps Push with exponential backoff on server errors (5xx).
// 4xx errors are not retried. maxRetries is capped at maxRetryLimit (10).
func (c *Client) PushWithRetry(ctx context.Context, docType string, payload []byte, maxRetries int) (*PushResult, error) {
	if maxRetries > maxRetryLimit {
		maxRetries = maxRetryLimit
	}
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

		// Don't retry on 4xx (client errors).
		if result != nil && result.StatusCode >= 400 && result.StatusCode < 500 {
			return result, err
		}

		lastErr = err
		if attempt < maxRetries {
			fmt.Printf("  Retry %d/%d after %s\n", attempt+1, maxRetries, backoff)
		}
	}
	return nil, fmt.Errorf("push failed after %d retries: %w", maxRetries, lastErr)
}

// WatchAndPush watches for posture changes and pushes at the given interval.
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
	case PlatformArcher:
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Http-Method-Override", "PUT")
	}
}

// newClientDirect creates a client bypassing endpoint validation — for unit tests only.
// Production callers must use NewClient which enforces SSRF protection.
func newClientDirect(endpoint string, platform Platform, dryRun bool, token string) *Client {
	return &Client{
		endpoint: endpoint,
		platform: platform,
		token:    token,
		dryRun:   dryRun,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// truncate returns the first n Unicode code points of s, appending "..." if truncated.
// Uses rune (code point) slicing rather than byte slicing to avoid invalid UTF-8 output.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
