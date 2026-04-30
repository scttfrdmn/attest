// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"context"
	"fmt"
	"testing"
	"time"

	awsartifact "github.com/aws/aws-sdk-go-v2/service/artifact"
	"github.com/aws/aws-sdk-go-v2/service/artifact/types"
)

// mockArtifactAPI is a test double for the Artifact SDK client.
type mockArtifactAPI struct {
	listReportsPages         [][]*types.ReportSummary
	listReportsErr           error
	getReportMetadataOutput  *awsartifact.GetReportMetadataOutput
	getReportMetadataErr     error
	getReportOutput          *awsartifact.GetReportOutput
	getReportErr             error
	getTermForReportOutput   *awsartifact.GetTermForReportOutput
	getTermForReportErr      error
	listAgreementsOutput     *awsartifact.ListCustomerAgreementsOutput
	listAgreementsErr        error
	listReportsCallCount     int
}

func (m *mockArtifactAPI) ListReports(ctx context.Context, params *awsartifact.ListReportsInput, _ ...func(*awsartifact.Options)) (*awsartifact.ListReportsOutput, error) {
	if m.listReportsErr != nil {
		return nil, m.listReportsErr
	}
	page := m.listReportsCallCount
	m.listReportsCallCount++
	if page >= len(m.listReportsPages) {
		return &awsartifact.ListReportsOutput{}, nil
	}
	out := &awsartifact.ListReportsOutput{}
	for _, rp := range m.listReportsPages[page] {
		out.Reports = append(out.Reports, *rp)
	}
	if page+1 < len(m.listReportsPages) {
		token := fmt.Sprintf("token-%d", page+1)
		out.NextToken = &token
	}
	return out, nil
}

func (m *mockArtifactAPI) GetReportMetadata(ctx context.Context, params *awsartifact.GetReportMetadataInput, _ ...func(*awsartifact.Options)) (*awsartifact.GetReportMetadataOutput, error) {
	return m.getReportMetadataOutput, m.getReportMetadataErr
}

func (m *mockArtifactAPI) GetReport(ctx context.Context, params *awsartifact.GetReportInput, _ ...func(*awsartifact.Options)) (*awsartifact.GetReportOutput, error) {
	return m.getReportOutput, m.getReportErr
}

func (m *mockArtifactAPI) GetTermForReport(ctx context.Context, params *awsartifact.GetTermForReportInput, _ ...func(*awsartifact.Options)) (*awsartifact.GetTermForReportOutput, error) {
	return m.getTermForReportOutput, m.getTermForReportErr
}

func (m *mockArtifactAPI) ListCustomerAgreements(ctx context.Context, params *awsartifact.ListCustomerAgreementsInput, _ ...func(*awsartifact.Options)) (*awsartifact.ListCustomerAgreementsOutput, error) {
	return m.listAgreementsOutput, m.listAgreementsErr
}

func strPtr(s string) *string { return &s }
func int64Ptr(i int64) *int64 { return &i }

func TestListReports(t *testing.T) {
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		pages       [][]*types.ReportSummary
		apiErr      error
		wantLen     int
		wantErr     bool
	}{
		{
			name: "single page",
			pages: [][]*types.ReportSummary{
				{
					{Id: strPtr("r-1"), Name: strPtr("SOC 2"), Category: strPtr("SOC"), Version: int64Ptr(3), PeriodStart: &start, PeriodEnd: &end},
					{Id: strPtr("r-2"), Name: strPtr("ISO 27001"), Category: strPtr("ISO"), Version: int64Ptr(1)},
				},
			},
			wantLen: 2,
		},
		{
			name: "multi-page pagination",
			pages: [][]*types.ReportSummary{
				{{Id: strPtr("r-1"), Name: strPtr("SOC 2"), Category: strPtr("SOC"), Version: int64Ptr(1)}},
				{{Id: strPtr("r-2"), Name: strPtr("ISO 27001"), Category: strPtr("ISO"), Version: int64Ptr(1)}},
				{{Id: strPtr("r-3"), Name: strPtr("FedRAMP"), Category: strPtr("FedRAMP"), Version: int64Ptr(2)}},
			},
			wantLen: 3,
		},
		{
			name:    "empty results",
			pages:   [][]*types.ReportSummary{},
			wantLen: 0,
		},
		{
			name:    "API error",
			apiErr:  fmt.Errorf("AccessDenied"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockArtifactAPI{
				listReportsPages: tt.pages,
				listReportsErr:   tt.apiErr,
			}
			c := newClientWithSvc(mock, "us-west-2")
			reports, err := c.ListReports(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("ListReports() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(reports) != tt.wantLen {
				t.Errorf("ListReports() got %d reports, want %d", len(reports), tt.wantLen)
			}
			// Spot-check field mapping on first report.
			if len(reports) > 0 && tt.pages != nil && len(tt.pages) > 0 {
				if reports[0].ID != deref(tt.pages[0][0].Id) {
					t.Errorf("ID mismatch: got %q, want %q", reports[0].ID, deref(tt.pages[0][0].Id))
				}
			}
		})
	}
}

func TestGetReportMetadata(t *testing.T) {
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		output   *awsartifact.GetReportMetadataOutput
		apiErr   error
		wantErr  bool
		wantName string
	}{
		{
			name: "success",
			output: &awsartifact.GetReportMetadataOutput{
				ReportDetails: &types.ReportDetail{
					Id: strPtr("r-1"), Name: strPtr("SOC 2 Type II"),
					Version: int64Ptr(5), PeriodStart: &start,
				},
			},
			wantName: "SOC 2 Type II",
		},
		{
			name:    "API error",
			apiErr:  fmt.Errorf("not found"),
			wantErr: true,
		},
		{
			name:    "nil details",
			output:  &awsartifact.GetReportMetadataOutput{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockArtifactAPI{
				getReportMetadataOutput: tt.output,
				getReportMetadataErr:    tt.apiErr,
			}
			c := newClientWithSvc(mock, "us-west-2")
			r, err := c.GetReportMetadata(context.Background(), "r-1")
			if (err != nil) != tt.wantErr {
				t.Errorf("GetReportMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && r.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", r.Name, tt.wantName)
			}
		})
	}
}

func TestDetectFrameworkActivations(t *testing.T) {
	active := types.CustomerAgreementState("ACTIVE")
	terminated := types.CustomerAgreementState("TERMINATED")

	tests := []struct {
		name              string
		agreements        []types.CustomerAgreementSummary
		wantActivations   map[string]bool
		wantNotActivated  []string
	}{
		{
			name: "BAA activates HIPAA",
			agreements: []types.CustomerAgreementSummary{
				{Id: strPtr("a-1"), Type: "BAA", State: active},
			},
			wantActivations:  map[string]bool{"hipaa": true},
			wantNotActivated: []string{"itar"},
		},
		{
			name: "terminated BAA does not activate HIPAA",
			agreements: []types.CustomerAgreementSummary{
				{Id: strPtr("a-1"), Type: "BAA", State: terminated},
			},
			wantActivations:  map[string]bool{},
			wantNotActivated: []string{"hipaa"},
		},
		{
			name: "ITAR activates itar framework",
			agreements: []types.CustomerAgreementSummary{
				{Id: strPtr("a-1"), Type: "ITAR", State: active},
			},
			wantActivations:  map[string]bool{"itar": true},
			wantNotActivated: []string{"hipaa"},
		},
		{
			name: "multiple active agreements",
			agreements: []types.CustomerAgreementSummary{
				{Id: strPtr("a-1"), Type: "BAA", State: active},
				{Id: strPtr("a-2"), Type: "ITAR", State: active},
			},
			wantActivations: map[string]bool{"hipaa": true, "itar": true},
		},
		{
			name:             "no agreements",
			agreements:       []types.CustomerAgreementSummary{},
			wantActivations:  map[string]bool{},
			wantNotActivated: []string{"hipaa", "itar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockArtifactAPI{
				listAgreementsOutput: &awsartifact.ListCustomerAgreementsOutput{
					CustomerAgreements: tt.agreements,
				},
			}
			c := newClientWithSvc(mock, "us-west-2")
			acts, err := c.DetectFrameworkActivations(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for fw, want := range tt.wantActivations {
				_, got := acts[fw]
				if got != want {
					t.Errorf("framework %q activated=%v, want %v", fw, got, want)
				}
			}
			for _, fw := range tt.wantNotActivated {
				if _, ok := acts[fw]; ok {
					t.Errorf("framework %q should not be activated", fw)
				}
			}
		})
	}
}

func TestDetectReportChanges(t *testing.T) {
	tests := []struct {
		name      string
		reports   []*types.ReportSummary
		lastKnown map[string]int64
		wantIDs   []string
	}{
		{
			name: "new report not in manifest",
			reports: []*types.ReportSummary{
				{Id: strPtr("r-1"), Name: strPtr("SOC 2"), Version: int64Ptr(1)},
			},
			lastKnown: map[string]int64{},
			wantIDs:   []string{"r-1"},
		},
		{
			name: "updated report (higher version)",
			reports: []*types.ReportSummary{
				{Id: strPtr("r-1"), Name: strPtr("SOC 2"), Version: int64Ptr(5)},
			},
			lastKnown: map[string]int64{"r-1": 3},
			wantIDs:   []string{"r-1"},
		},
		{
			name: "unchanged report not returned",
			reports: []*types.ReportSummary{
				{Id: strPtr("r-1"), Name: strPtr("SOC 2"), Version: int64Ptr(3)},
			},
			lastKnown: map[string]int64{"r-1": 3},
			wantIDs:   []string{},
		},
		{
			name: "mix of changed and unchanged",
			reports: []*types.ReportSummary{
				{Id: strPtr("r-1"), Version: int64Ptr(2)}, // changed
				{Id: strPtr("r-2"), Version: int64Ptr(1)}, // unchanged
				{Id: strPtr("r-3"), Version: int64Ptr(1)}, // new
			},
			lastKnown: map[string]int64{"r-1": 1, "r-2": 1},
			wantIDs:   []string{"r-1", "r-3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockArtifactAPI{
				listReportsPages: [][]*types.ReportSummary{tt.reports},
			}
			c := newClientWithSvc(mock, "us-west-2")
			changed, err := c.DetectReportChanges(context.Background(), tt.lastKnown)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			gotIDs := make(map[string]bool)
			for _, r := range changed {
				gotIDs[r.ID] = true
			}
			for _, wantID := range tt.wantIDs {
				if !gotIDs[wantID] {
					t.Errorf("expected report %q in changed set", wantID)
				}
			}
			if len(changed) != len(tt.wantIDs) {
				t.Errorf("got %d changed reports, want %d", len(changed), len(tt.wantIDs))
			}
		})
	}
}

// deref dereferences a string pointer (test helper).
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
