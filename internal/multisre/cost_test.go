// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package multisre

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

// mockCEClient implements ceAPI for testing without AWS credentials.
type mockCEClient struct {
	output *costexplorer.GetCostAndUsageOutput
	err    error
}

func (m *mockCEClient) GetCostAndUsage(_ context.Context, _ *costexplorer.GetCostAndUsageInput,
	_ ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
	return m.output, m.err
}

func TestCostCollector_Aggregation(t *testing.T) {
	mock := &mockCEClient{
		output: &costexplorer.GetCostAndUsageOutput{
			ResultsByTime: []cetypes.ResultByTime{
				{
					Groups: []cetypes.Group{
						{Keys: []string{"Amazon EC2"}, Metrics: map[string]cetypes.MetricValue{"UnblendedCost": {Amount: aws.String("1200.50")}}},
						{Keys: []string{"AWS Lambda"}, Metrics: map[string]cetypes.MetricValue{"UnblendedCost": {Amount: aws.String("45.20")}}},
						{Keys: []string{"Amazon S3"}, Metrics: map[string]cetypes.MetricValue{"UnblendedCost": {Amount: aws.String("23.80")}}},
					},
				},
				{
					// Second time bucket — should be summed.
					Groups: []cetypes.Group{
						{Keys: []string{"Amazon EC2"}, Metrics: map[string]cetypes.MetricValue{"UnblendedCost": {Amount: aws.String("100.00")}}},
					},
				},
			},
		},
	}

	c := newCostCollectorWithClient(mock)
	summary, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	// Total should aggregate across all time buckets.
	expectedTotal := 1200.50 + 45.20 + 23.80 + 100.00 // = 1369.50
	if diff := summary.MonthlyCostUSD - expectedTotal; diff > 0.01 || diff < -0.01 {
		t.Errorf("MonthlyCostUSD = %.2f, want %.2f", summary.MonthlyCostUSD, expectedTotal)
	}

	// Top services should be sorted by cost descending.
	if len(summary.TopServices) == 0 {
		t.Fatal("TopServices must not be empty")
	}
	if summary.TopServices[0].Service != "Amazon EC2" {
		t.Errorf("TopServices[0] = %q, want Amazon EC2 (highest cost)", summary.TopServices[0].Service)
	}

	// Period and timestamp should be set.
	if summary.Period == "" {
		t.Error("Period must not be empty")
	}
	if summary.LastUpdated.IsZero() {
		t.Error("LastUpdated must not be zero")
	}
}

func TestCostCollector_EmptyResult(t *testing.T) {
	mock := &mockCEClient{
		output: &costexplorer.GetCostAndUsageOutput{ResultsByTime: nil},
	}
	c := newCostCollectorWithClient(mock)
	summary, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() empty result error: %v", err)
	}
	if summary.MonthlyCostUSD != 0 {
		t.Errorf("empty result: MonthlyCostUSD = %.2f, want 0", summary.MonthlyCostUSD)
	}
	if len(summary.TopServices) != 0 {
		t.Errorf("empty result: TopServices = %v, want []", summary.TopServices)
	}
}

func TestCostCollector_Top5Limit(t *testing.T) {
	// 10 services → top 5 returned.
	var groups []cetypes.Group
	for i := 0; i < 10; i++ {
		groups = append(groups, cetypes.Group{
			Keys:    []string{fmt.Sprintf("Service-%02d", i)},
			Metrics: map[string]cetypes.MetricValue{"UnblendedCost": {Amount: aws.String(fmt.Sprintf("%d.00", (10-i)*100))}},
		})
	}
	mock := &mockCEClient{
		output: &costexplorer.GetCostAndUsageOutput{
			ResultsByTime: []cetypes.ResultByTime{{Groups: groups}},
		},
	}
	c := newCostCollectorWithClient(mock)
	summary, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if len(summary.TopServices) > 5 {
		t.Errorf("TopServices has %d entries, want ≤5", len(summary.TopServices))
	}
}
