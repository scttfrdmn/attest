package multisre

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

// CostSummary holds AWS Cost Explorer data for a single SRE.
type CostSummary struct {
	MonthlyCostUSD float64       // total cost for the last 30 days
	TopServices    []ServiceCost // top services by spend
	Period         string        // e.g., "2026-03-17 to 2026-04-17"
	LastUpdated    time.Time
}

// ServiceCost is the cost for a single AWS service.
type ServiceCost struct {
	Service string
	USD     float64
}

// ceAPI is the Cost Explorer interface (for testing with mocks).
type ceAPI interface {
	GetCostAndUsage(ctx context.Context, params *costexplorer.GetCostAndUsageInput,
		optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
}

// CostCollector queries AWS Cost Explorer for a single SRE's monthly spend.
type CostCollector struct {
	ceClient ceAPI
}

// NewCostCollector creates a cost collector using the default AWS config.
func NewCostCollector(ctx context.Context, region string) (*CostCollector, error) {
	// Cost Explorer is a global service — always us-east-1 regardless of region flag.
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config for Cost Explorer: %w", err)
	}
	return &CostCollector{ceClient: costexplorer.NewFromConfig(cfg)}, nil
}

// newCostCollectorWithClient creates a collector with an injected client (for testing).
func newCostCollectorWithClient(ce ceAPI) *CostCollector {
	return &CostCollector{ceClient: ce}
}

// Collect returns the last 30 days of cost data for the SRE.
// Requires the caller's AWS credentials to have ce:GetCostAndUsage permission.
func (c *CostCollector) Collect(ctx context.Context) (*CostSummary, error) {
	end := time.Now().UTC().Format("2006-01-02")
	start := time.Now().UTC().AddDate(0, 0, -30).Format("2006-01-02")

	out, err := c.ceClient.GetCostAndUsage(ctx, &costexplorer.GetCostAndUsageInput{
		TimePeriod: &cetypes.DateInterval{
			Start: aws.String(start),
			End:   aws.String(end),
		},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{"UnblendedCost"},
		GroupBy: []cetypes.GroupDefinition{
			{Type: cetypes.GroupDefinitionTypeDimension, Key: aws.String("SERVICE")},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Cost Explorer query: %w", err)
	}

	summary := &CostSummary{
		Period:      start + " to " + end,
		LastUpdated: time.Now().UTC(),
	}

	// Aggregate by service across all time buckets.
	serviceMap := make(map[string]float64)
	for _, result := range out.ResultsByTime {
		for _, group := range result.Groups {
			if len(group.Keys) == 0 {
				continue
			}
			service := group.Keys[0]
			if amt, ok := group.Metrics["UnblendedCost"]; ok && amt.Amount != nil {
				usd, _ := strconv.ParseFloat(*amt.Amount, 64)
				serviceMap[service] += usd
				summary.MonthlyCostUSD += usd
			}
		}
	}

	// Build top-5 services by cost.
	type svcEntry struct{ name string; cost float64 }
	var services []svcEntry
	for name, cost := range serviceMap {
		services = append(services, svcEntry{name, cost})
	}
	// Sort descending by cost (insertion sort for small N).
	for i := 1; i < len(services); i++ {
		for j := i; j > 0 && services[j].cost > services[j-1].cost; j-- {
			services[j], services[j-1] = services[j-1], services[j]
		}
	}
	limit := 5
	if len(services) < limit {
		limit = len(services)
	}
	for _, s := range services[:limit] {
		summary.TopServices = append(summary.TopServices, ServiceCost{
			Service: s.name,
			USD:     s.cost,
		})
	}

	return summary, nil
}
