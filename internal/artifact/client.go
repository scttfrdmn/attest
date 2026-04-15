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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsartifact "github.com/aws/aws-sdk-go-v2/service/artifact"
	"github.com/aws/aws-sdk-go-v2/service/artifact/types"
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
	Version     int64
	ARN         string
}

// Agreement represents a customer-accepted agreement (BAA, NDA, ITAR addendum, etc.).
type Agreement struct {
	ID         string
	Type       string    // e.g., "BAA", "ITAR", "CUSTOM"
	State      string    // "ACTIVE", "TERMINATED"
	AcceptedAt time.Time // EffectiveStart from the API
}

// artifactAPI is the interface we use for the Artifact SDK client,
// defined to enable mocking in tests.
type artifactAPI interface {
	ListReports(ctx context.Context, params *awsartifact.ListReportsInput, optFns ...func(*awsartifact.Options)) (*awsartifact.ListReportsOutput, error)
	GetReportMetadata(ctx context.Context, params *awsartifact.GetReportMetadataInput, optFns ...func(*awsartifact.Options)) (*awsartifact.GetReportMetadataOutput, error)
	GetReport(ctx context.Context, params *awsartifact.GetReportInput, optFns ...func(*awsartifact.Options)) (*awsartifact.GetReportOutput, error)
	GetTermForReport(ctx context.Context, params *awsartifact.GetTermForReportInput, optFns ...func(*awsartifact.Options)) (*awsartifact.GetTermForReportOutput, error)
	ListCustomerAgreements(ctx context.Context, params *awsartifact.ListCustomerAgreementsInput, optFns ...func(*awsartifact.Options)) (*awsartifact.ListCustomerAgreementsOutput, error)
}

// Client wraps the AWS Artifact API.
type Client struct {
	svc    artifactAPI
	region string
}

// NewClient creates an Artifact API client using the default credential chain.
func NewClient(ctx context.Context, region string) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &Client{
		svc:    awsartifact.NewFromConfig(cfg),
		region: region,
	}, nil
}

// newClientWithSvc creates a client with an injected API implementation (for testing).
func newClientWithSvc(svc artifactAPI, region string) *Client {
	return &Client{svc: svc, region: region}
}

// ListReports enumerates all available compliance reports.
// Paginates automatically. Results include metadata for change detection.
func (c *Client) ListReports(ctx context.Context) ([]Report, error) {
	var reports []Report
	var nextToken *string

	for {
		out, err := c.svc.ListReports(ctx, &awsartifact.ListReportsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing Artifact reports: %w", err)
		}

		for _, r := range out.Reports {
			reports = append(reports, reportSummaryToReport(r))
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return reports, nil
}

// GetReportMetadata retrieves metadata for a specific report without downloading it.
// Used for version tracking and change detection between scans.
func (c *Client) GetReportMetadata(ctx context.Context, reportID string) (*Report, error) {
	out, err := c.svc.GetReportMetadata(ctx, &awsartifact.GetReportMetadataInput{
		ReportId: aws.String(reportID),
	})
	if err != nil {
		return nil, fmt.Errorf("getting report metadata %s: %w", reportID, err)
	}
	if out.ReportDetails == nil {
		return nil, fmt.Errorf("report %s: no details returned", reportID)
	}
	r := reportDetailToReport(out.ReportDetails)
	return &r, nil
}

// DownloadReport retrieves the actual report document via presigned URL.
// Returns the raw document bytes (typically PDF).
// If termToken is empty, it is fetched automatically via GetTermForReport.
func (c *Client) DownloadReport(ctx context.Context, reportID string, termToken string) ([]byte, error) {
	if termToken == "" {
		termOut, err := c.svc.GetTermForReport(ctx, &awsartifact.GetTermForReportInput{
			ReportId: aws.String(reportID),
		})
		if err != nil {
			return nil, fmt.Errorf("getting term for report %s: %w", reportID, err)
		}
		if termOut.TermToken == nil {
			return nil, fmt.Errorf("report %s: no term token returned", reportID)
		}
		termToken = *termOut.TermToken
	}

	out, err := c.svc.GetReport(ctx, &awsartifact.GetReportInput{
		ReportId:  aws.String(reportID),
		TermToken: aws.String(termToken),
	})
	if err != nil {
		return nil, fmt.Errorf("getting report %s: %w", reportID, err)
	}
	if out.DocumentPresignedUrl == nil {
		return nil, fmt.Errorf("report %s: no presigned URL returned", reportID)
	}

	return fetchPresigned(*out.DocumentPresignedUrl)
}

// ListAgreements enumerates all accepted customer agreements.
// This tells us which frameworks are activated for this org:
//   - Signed BAA → HIPAA controls active
//   - ITAR addendum → ITAR controls active
func (c *Client) ListAgreements(ctx context.Context) ([]Agreement, error) {
	var agreements []Agreement
	var nextToken *string

	for {
		out, err := c.svc.ListCustomerAgreements(ctx, &awsartifact.ListCustomerAgreementsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing customer agreements: %w", err)
		}

		for _, a := range out.CustomerAgreements {
			agreements = append(agreements, customerAgreementToAgreement(a))
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return agreements, nil
}

// DetectFrameworkActivations maps active agreements to framework IDs.
// Returns the set of frameworks this org has opted into via Artifact agreements.
func (c *Client) DetectFrameworkActivations(ctx context.Context) (map[string]Agreement, error) {
	agreements, err := c.ListAgreements(ctx)
	if err != nil {
		return nil, err
	}

	// Map agreement types to framework IDs.
	// Agreement.Type comes from AgreementType enum; names from the Artifact console
	// (e.g., the HIPAA BAA shows Type="BAA").
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
		}
	}
	return activations, nil
}

// DetectReportChanges compares current report versions against a previously
// stored manifest. Returns reports that have been updated since last scan.
// This triggers re-extraction of shared responsibility data.
func (c *Client) DetectReportChanges(ctx context.Context, lastKnown map[string]int64) ([]Report, error) {
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

// --- type mapping helpers ---

func reportSummaryToReport(r types.ReportSummary) Report {
	rep := Report{
		ID:          aws.ToString(r.Id),
		Name:        aws.ToString(r.Name),
		Category:    aws.ToString(r.Category),
		Series:      aws.ToString(r.Series),
		Description: aws.ToString(r.Description),
		ARN:         aws.ToString(r.Arn),
	}
	if r.Version != nil {
		rep.Version = *r.Version
	}
	if r.PeriodStart != nil {
		rep.PeriodStart = *r.PeriodStart
	}
	if r.PeriodEnd != nil {
		rep.PeriodEnd = *r.PeriodEnd
	}
	return rep
}

func reportDetailToReport(r *types.ReportDetail) Report {
	rep := Report{
		ID:          aws.ToString(r.Id),
		Name:        aws.ToString(r.Name),
		Category:    aws.ToString(r.Category),
		Series:      aws.ToString(r.Series),
		Description: aws.ToString(r.Description),
		ARN:         aws.ToString(r.Arn),
	}
	if r.Version != nil {
		rep.Version = *r.Version
	}
	if r.PeriodStart != nil {
		rep.PeriodStart = *r.PeriodStart
	}
	if r.PeriodEnd != nil {
		rep.PeriodEnd = *r.PeriodEnd
	}
	return rep
}

func customerAgreementToAgreement(a types.CustomerAgreementSummary) Agreement {
	ag := Agreement{
		ID:    aws.ToString(a.Id),
		Type:  string(a.Type),
		State: string(a.State),
	}
	if a.EffectiveStart != nil {
		ag.AcceptedAt = *a.EffectiveStart
	}
	return ag
}

// fetchPresigned performs an HTTP GET on a presigned S3 URL.
func fetchPresigned(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec // presigned URLs are generated by the AWS SDK
	if err != nil {
		return nil, fmt.Errorf("fetching presigned URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("presigned URL returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
