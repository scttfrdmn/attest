// Package reporting generates trend analysis, multi-SRE aggregation,
// and incident lifecycle reports from posture history.
package reporting

import (
	"context"
	"fmt"
	"time"

	"github.com/scttfrdmn/attest/pkg/schema"
)

// TrendReport shows posture change over time.
type TrendReport struct {
	Window      time.Duration
	Snapshots   []schema.PostureSnapshot
	ScoreTrend  []ScorePoint
	GapsClosed  int
	GapsOpened  int
	Velocity    float64 // gaps closed per week
}

// ScorePoint is a single data point in the trend.
type ScorePoint struct {
	Timestamp time.Time
	Score     float64
	Gaps      int
}

// Reporter generates compliance reports.
type Reporter struct {
	historyDir string // .attest/history/
}

// NewReporter creates a reporter that reads from the posture history store.
func NewReporter(historyDir string) *Reporter {
	return &Reporter{historyDir: historyDir}
}

// GenerateTrend produces a trend report over the given window.
func (r *Reporter) GenerateTrend(ctx context.Context, window time.Duration) (*TrendReport, error) {
	return nil, fmt.Errorf("not implemented")
}

// IncidentReport summarizes security incidents and their compliance impact.
type IncidentReport struct {
	Incidents       []schema.Incident
	MeanTimeResolve time.Duration
	ControlsAffected int
	CUIExposure     bool // whether Cedar logs confirm CUI exposure
	SSPNarrative    string // computed narrative for SSP inclusion
}

// GenerateIncidentReport produces the incident history for SSP inclusion.
func (r *Reporter) GenerateIncidentReport(ctx context.Context, incidents []schema.Incident) (*IncidentReport, error) {
	return nil, fmt.Errorf("not implemented")
}
