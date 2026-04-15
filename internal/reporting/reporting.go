// Package reporting generates trend analysis from posture history.
package reporting

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/scttfrdmn/attest/pkg/schema"
)

// TrendReport shows posture change over a time window.
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
	Score     float64 // 0–100 percent
	Gaps      int
}

// Reporter generates compliance reports from posture history.
type Reporter struct {
	historyDir string // .attest/history/
}

// NewReporter creates a reporter.
func NewReporter(historyDir string) *Reporter {
	return &Reporter{historyDir: historyDir}
}

// GenerateTrend produces a trend report over the given time window.
func (r *Reporter) GenerateTrend(ctx context.Context, window time.Duration) (*TrendReport, error) {
	entries, err := os.ReadDir(r.historyDir)
	if os.IsNotExist(err) {
		return &TrendReport{Window: window}, nil
	}
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().Add(-window)
	var snapshots []schema.PostureSnapshot

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(r.historyDir, e.Name()))
		if err != nil {
			continue
		}
		var snap schema.PostureSnapshot
		if err := yaml.Unmarshal(data, &snap); err != nil {
			continue
		}
		if snap.Timestamp.After(cutoff) {
			snapshots = append(snapshots, snap)
		}
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.Before(snapshots[j].Timestamp)
	})

	trend := &TrendReport{Window: window, Snapshots: snapshots}

	for _, snap := range snapshots {
		total := snap.Posture.TotalControls
		if total == 0 {
			total = 1
		}
		score := float64(snap.Posture.Enforced*5+snap.Posture.Partial*3) / float64(total*5) * 100
		trend.ScoreTrend = append(trend.ScoreTrend, ScorePoint{
			Timestamp: snap.Timestamp,
			Score:     score,
			Gaps:      snap.Posture.Gaps,
		})
	}

	if len(trend.ScoreTrend) >= 2 {
		first := trend.ScoreTrend[0]
		last := trend.ScoreTrend[len(trend.ScoreTrend)-1]
		trend.GapsClosed = first.Gaps - last.Gaps
		if trend.GapsClosed < 0 {
			trend.GapsOpened = -trend.GapsClosed
			trend.GapsClosed = 0
		}
		weeks := window.Hours() / (24 * 7)
		if weeks > 0 && trend.GapsClosed > 0 {
			trend.Velocity = float64(trend.GapsClosed) / weeks
		}
	}

	return trend, nil
}
