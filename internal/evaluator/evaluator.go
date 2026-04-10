// Package evaluator implements the continuous Cedar PDP for runtime
// compliance evaluation. It consumes CloudTrail events via EventBridge,
// evaluates each against compiled Cedar policies, records decisions to
// S3 (partitioned for Athena), and emits denials to Security Hub.
package evaluator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/scttfrdmn/attest/pkg/schema"
)

// Evaluator is the Cedar PDP runtime.
type Evaluator struct {
	policies []CompiledPolicy
	stats    *Stats
	mu       sync.RWMutex
}

// CompiledPolicy is a Cedar policy loaded for evaluation.
type CompiledPolicy struct {
	ID         string
	PolicyText string
	ControlID  string
}

// Stats tracks evaluation statistics (thread-safe for dashboard).
type Stats struct {
	mu          sync.RWMutex
	Total       int64
	Permits     int64
	Denies      int64
	PeriodStart time.Time
}

// NewEvaluator creates a Cedar PDP evaluator from compiled policies.
func NewEvaluator(policies []CompiledPolicy) *Evaluator {
	return &Evaluator{
		policies: policies,
		stats:    &Stats{PeriodStart: time.Now()},
	}
}

// Evaluate runs a single authorization request against all loaded policies.
func (e *Evaluator) Evaluate(ctx context.Context, req *AuthzRequest) (*schema.CedarDecision, error) {
	// TODO: Build Cedar entities from request, evaluate against policy set,
	// record decision, emit to Security Hub on deny.
	return nil, fmt.Errorf("not implemented")
}

// AuthzRequest is an authorization request derived from a CloudTrail event.
type AuthzRequest struct {
	Action      string
	PrincipalARN string
	ResourceARN  string
	AccountID   string
	Attributes  map[string]any
	Timestamp   time.Time
}

// Start begins consuming EventBridge events and evaluating them.
func (e *Evaluator) Start(ctx context.Context) error {
	// TODO: Subscribe to EventBridge, consume events, evaluate each.
	return fmt.Errorf("not implemented")
}

// GetStats returns current evaluation statistics.
func (e *Evaluator) GetStats() (total, permits, denies int64) {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()
	return e.stats.Total, e.stats.Permits, e.stats.Denies
}
