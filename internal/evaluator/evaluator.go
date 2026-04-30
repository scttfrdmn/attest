// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package evaluator implements the Cedar PDP for runtime compliance evaluation.
// One-shot evaluation is supported via EvaluateWithPolicies. Continuous evaluation
// uses a CloudTrail polling loop (Start method). Full EventBridge integration is v1.0.0.
package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/provabl/attest/pkg/schema"
)

// DecisionEvent is emitted for every Cedar evaluation in continuous mode.
// Dashboard subscribers receive these over SSE.
type DecisionEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Principal string    `json:"principal"`
	Resource  string    `json:"resource"`
	Effect    string    `json:"effect"`
	PolicyID  string    `json:"policy_id,omitempty"`
}

// Evaluator is the Cedar PDP runtime.
type Evaluator struct {
	policies  []CompiledPolicy
	stats     *Stats
	mu        sync.RWMutex
	broadcast chan DecisionEvent // non-nil when running in continuous mode
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

	decision, diag := cedar.Authorize(ps, entities, cedarReq)

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

// Subscribe returns a channel that receives DecisionEvents in continuous mode.
// The channel is closed when the evaluator stops. Only valid after Start is called.
func (e *Evaluator) Subscribe() <-chan DecisionEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broadcast == nil {
		e.broadcast = make(chan DecisionEvent, 64)
	}
	return e.broadcast
}

// Start polls CloudTrail for management events and evaluates each one against
// the loaded Cedar policies. Decisions are written to .attest/history/cedar-decisions.jsonl
// and broadcast to any dashboard SSE subscribers.
//
// The ctSvc parameter is the CloudTrail client. If nil, Start returns an error.
// The cedarDir is the path to compiled Cedar policies.
// The historyDir is where cedar-decisions.jsonl is written.
// interval is how often to poll (default: 30s).
func (e *Evaluator) Start(ctx context.Context, ctSvc *cloudtrail.Client, cedarDir, historyDir string, interval time.Duration) error {
	if ctSvc == nil {
		return fmt.Errorf("cloudtrail client required for continuous evaluation")
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}

	// Load Cedar policies.
	ps, err := loadPoliciesFromDir(cedarDir)
	if err != nil {
		return fmt.Errorf("loading Cedar policies from %s: %w", cedarDir, err)
	}

	// Open decision log.
	if err := os.MkdirAll(historyDir, 0750); err != nil {
		return fmt.Errorf("creating history dir: %w", err)
	}
	logFile, err := os.OpenFile(
		filepath.Join(historyDir, "cedar-decisions.jsonl"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("opening decision log: %w", err)
	}
	defer logFile.Close()

	// Ensure broadcast channel is ready.
	e.mu.Lock()
	if e.broadcast == nil {
		e.broadcast = make(chan DecisionEvent, 64)
	}
	bcast := e.broadcast
	e.mu.Unlock()
	defer close(bcast)

	poller := newCloudTrailPoller(ctSvc)
	lastPoll := time.Now().Add(-interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			reqs, err := poller.Poll(ctx, lastPoll, now)
			lastPoll = now
			if err != nil {
				continue // log and retry next tick
			}
			for _, req := range reqs {
				decision, err := e.EvaluateWithPolicies(ctx, ps, req)
				if err != nil {
					continue
				}
				ev := DecisionEvent{
					Timestamp: decision.Timestamp,
					Action:    decision.Action,
					Principal: decision.Principal,
					Resource:  decision.Resource,
					Effect:    decision.Effect,
					PolicyID:  decision.PolicyID,
				}
				// Write to log.
				if b, err := json.Marshal(ev); err == nil {
					_, _ = logFile.Write(append(b, '\n'))
				}
				// Broadcast (non-blocking).
				select {
				case bcast <- ev:
				default:
				}
			}
		}
	}
}

// loadPoliciesFromDir loads all .cedar files from a directory into a PolicySet.
func loadPoliciesFromDir(dir string) (*cedar.PolicySet, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return cedar.NewPolicySet(), nil
	}
	if err != nil {
		return nil, err
	}
	ps := cedar.NewPolicySet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cedar") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		parsed, err := cedar.NewPolicySetFromBytes(e.Name(), data)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", e.Name(), err)
		}
		for id, policy := range parsed.All() {
			ps.Add(id, policy)
		}
	}
	return ps, nil
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
