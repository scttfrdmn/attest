// Package artifact provides a client for the AWS Artifact API.
// It discovers available compliance reports, retrieves shared responsibility
// matrices, and detects agreement-gated framework activations (e.g., a signed
// BAA activates HIPAA controls for the org).
package artifact

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Report represents a compliance report from AWS Artifact.
type Report struct {
	ID          string
	Name        string
	Category    string // e.g., "SOC", "ISO", "FedRAMP"
	Series      string
	Description string
	PeriodStart time.Time
	PeriodEnd   time.Time
	Version     int
	ARN         string
}

// Agreement represents a customer-accepted agreement (BAA, NDA, ITAR addendum, etc.).
type Agreement struct {
	ID          string
	Type        string // e.g., "BAA", "ITAR", "NDA"
	State       string // "ACTIVE", "TERMINATED"
	AcceptedAt  time.Time
}

// Client wraps the AWS Artifact API.
type Client struct {
	// awsClient would be the actual SDK client; omitted for scaffold.
	region string
}

// NewClient creates an Artifact API client.
func NewClient(region string) (*Client, error) {
	return &Client{region: region}, nil
}

// ListReports enumerates all available compliance reports.
// Paginates automatically. Results include metadata for change detection.
func (c *Client) ListReports(ctx context.Context) ([]Report, error) {
	// TODO: Call artifact:ListReports, paginate via nextToken, map to Report.
	// Each report has: id, name, category, series, description, periodStart,
	// periodEnd, version, arn, state, acceptanceType.
	return nil, fmt.Errorf("not implemented")
}

// GetReportMetadata retrieves metadata for a specific report without downloading it.
// Used for version tracking and change detection between scans.
func (c *Client) GetReportMetadata(ctx context.Context, reportID string) (*Report, error) {
	return nil, fmt.Errorf("not implemented")
}

// DownloadReport retrieves the actual report document via presigned URL.
// Returns the raw document bytes (typically PDF).
func (c *Client) DownloadReport(ctx context.Context, reportID string, termToken string) ([]byte, error) {
	// Step 1: Call GetTermForReport to get the term token (if not provided).
	// Step 2: Call GetReport with reportId + termToken → presigned S3 URL.
	// Step 3: HTTP GET on the presigned URL → document bytes.
	return nil, fmt.Errorf("not implemented")
}

// ListAgreements enumerates all accepted customer agreements.
// This tells us which frameworks are activated for this org:
//   - Signed BAA → HIPAA controls active
//   - ITAR addendum → ITAR controls active
//   - etc.
func (c *Client) ListAgreements(ctx context.Context) ([]Agreement, error) {
	return nil, fmt.Errorf("not implemented")
}

// DetectFrameworkActivations maps active agreements to framework IDs.
// Returns the set of frameworks this org has opted into via Artifact agreements.
func (c *Client) DetectFrameworkActivations(ctx context.Context) (map[string]Agreement, error) {
	agreements, err := c.ListAgreements(ctx)
	if err != nil {
		return nil, err
	}

	// Map agreement types to framework IDs.
	activations := make(map[string]Agreement)
	for _, a := range agreements {
		if a.State != "ACTIVE" {
			continue
		}
		switch a.Type {
		case "BAA":
			activations["hipaa"] = a
		case "ITAR":
			activations["itar"] = a
		// Add more as frameworks are defined.
		}
	}
	return activations, nil
}

// DetectReportChanges compares current report versions against a previously
// stored manifest. Returns reports that have been updated since last scan.
// This triggers re-extraction of shared responsibility data.
func (c *Client) DetectReportChanges(ctx context.Context, lastKnown map[string]int) ([]Report, error) {
	reports, err := c.ListReports(ctx)
	if err != nil {
		return nil, err
	}

	var changed []Report
	for _, r := range reports {
		if known, ok := lastKnown[r.ID]; !ok || r.Version > known {
			changed = append(changed, r)
		}
	}
	return changed, nil
}

// fetchPresigned performs an HTTP GET on a presigned S3 URL.
func fetchPresigned(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching presigned URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("presigned URL returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
