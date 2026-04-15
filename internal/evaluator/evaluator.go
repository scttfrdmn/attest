// Package evaluator implements the Cedar PDP for runtime compliance evaluation.
// One-shot evaluation is supported via EvaluateWithPolicies. Continuous evaluation
// via EventBridge is scaffolded (Start method) — full EventBridge integration is v1.0.0.
package evaluator

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

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

// AuthzRequest is an authorization request.
type AuthzRequest struct {
	Action       string
	PrincipalARN string
	ResourceARN  string
	AccountID    string
	Attributes   map[string]any // "entity.attribute" → value
	Timestamp    time.Time
}

// NewEvaluator creates a Cedar PDP evaluator.
func NewEvaluator(policies []CompiledPolicy) *Evaluator {
	return &Evaluator{
		policies: policies,
		stats:    &Stats{PeriodStart: time.Now()},
	}
}

// EvaluateWithPolicies evaluates a request against a pre-loaded PolicySet.
// This is the primary entry point for one-shot evaluation (attest evaluate).
func (e *Evaluator) EvaluateWithPolicies(ctx context.Context, ps *cedar.PolicySet, req *AuthzRequest) (*schema.CedarDecision, error) {
	now := time.Now()

	// Build entity map from the request.
	entities := types.EntityMap{}

	// Principal entity.
	principalUID := types.NewEntityUID(types.EntityType("Principal"), types.String(req.PrincipalARN))
	principalAttrs := buildAttributes(req.Attributes, "principal")
	entities[principalUID] = types.Entity{UID: principalUID, Attributes: principalAttrs}

	// Resource entity.
	resourceUID := types.NewEntityUID(types.EntityType("Resource"), types.String(req.ResourceARN))
	resourceAttrs := buildAttributes(req.Attributes, "resource")
	entities[resourceUID] = types.Entity{UID: resourceUID, Attributes: resourceAttrs}

	// Action entity.
	actionUID := types.NewEntityUID(types.EntityType("Action"), types.String(req.Action))
	entities[actionUID] = types.Entity{UID: actionUID}

	cedarReq := types.Request{
		Principal: principalUID,
		Action:    actionUID,
		Resource:  resourceUID,
	}

	decision, diag := ps.IsAuthorized(entities, cedarReq)

	effect := "DENY"
	if decision == types.Decision(true) {
		effect = "ALLOW"
	}

	d := &schema.CedarDecision{
		Timestamp:   now,
		Action:      req.Action,
		Principal:   req.PrincipalARN,
		Resource:    req.ResourceARN,
		Effect:      effect,
		AccountID:   req.AccountID,
	}

	// Extract policy ID from diagnostics.
	if len(diag.Reasons) > 0 {
		var ids []string
		for _, r := range diag.Reasons {
			ids = append(ids, string(r.PolicyID))
		}
		d.PolicyID = strings.Join(ids, ", ")
	}

	// Update stats.
	e.stats.mu.Lock()
	e.stats.Total++
	if effect == "ALLOW" {
		e.stats.Permits++
	} else {
		e.stats.Denies++
	}
	e.stats.mu.Unlock()

	return d, nil
}

// Evaluate runs a single authorization request (loads policies from compiled dir).
// Prefer EvaluateWithPolicies when you already have a PolicySet loaded.
func (e *Evaluator) Evaluate(ctx context.Context, req *AuthzRequest) (*schema.CedarDecision, error) {
	return nil, fmt.Errorf("use EvaluateWithPolicies with a loaded PolicySet")
}

// Start begins consuming EventBridge events and evaluating them.
// EventBridge integration is deferred to v1.0.0 — use attest evaluate for one-shot.
func (e *Evaluator) Start(ctx context.Context) error {
	return fmt.Errorf("EventBridge continuous evaluation deferred to v1.0.0; use 'attest evaluate' for one-shot evaluation")
}

// GetStats returns current evaluation statistics (thread-safe).
func (e *Evaluator) GetStats() (total, permits, denies int64) {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()
	return e.stats.Total, e.stats.Permits, e.stats.Denies
}

// buildAttributes extracts attributes for a given entity prefix from the flat map.
// Input: {"principal.cui_training_current": "true"} → Record with "cui_training_current": Bool(true)
func buildAttributes(attrs map[string]any, prefix string) types.Record {
	rm := types.RecordMap{}
	for k, v := range attrs {
		parts := strings.SplitN(k, ".", 2)
		if len(parts) != 2 || parts[0] != prefix {
			continue
		}
		attrName := parts[1]
		rm[types.String(attrName)] = toValue(v)
	}
	return types.NewRecord(rm)
}

// toValue converts a Go value to a Cedar Value.
func toValue(v any) types.Value {
	switch val := v.(type) {
	case bool:
		return types.Boolean(val)
	case string:
		// Parse "true"/"false" strings as Bool.
		switch strings.ToLower(val) {
		case "true":
			return types.Boolean(true)
		case "false":
			return types.Boolean(false)
		}
		return types.String(val)
	case int64:
		return types.Long(val)
	case float64:
		return types.Long(int64(val))
	default:
		return types.String(fmt.Sprintf("%v", v))
	}
}
