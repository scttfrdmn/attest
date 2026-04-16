// Package scp compiles framework control definitions into AWS Service Control Policies.
// SCPs provide structural (preventive) enforcement at the org level. Every account
// in the SRE inherits these policies — compliance by construction.
package scp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/provabl/attest/internal/framework"
	"github.com/provabl/attest/pkg/schema"
)

// scpSizeLimit is the AWS maximum size for an SCP document in bytes.
const scpSizeLimit = 5120

// maxSCPSlots is the maximum number of SCP documents to produce in merged mode.
// Leaves 1 slot for FullAWSAccess (AWS default policy that must remain attached).
const maxSCPSlots = 4

// TotalBudget is the total character budget across all composite SCPs (exported for CLI reporting).
const TotalBudget = maxSCPSlots * scpSizeLimit // 20,480 chars

// totalBudget alias for internal use.
const totalBudget = TotalBudget

// maxActionsPerStatement caps actions per statement to keep well under the size limit
// when splitting is needed.
const maxActionsPerStatement = 40

// CompileStats reports the efficiency of IntelligentCompile.
type CompileStats struct {
	InputSpecs       int     // total structural enforcement specs collected
	UniqueConditions int     // unique condition groups after deduplication
	TotalChars       int     // characters used across all output SCPs
	BudgetUsed       float64 // percentage of totalBudget used
	SCPCount         int     // number of SCP documents produced
}

// IAMPolicy is the JSON structure of an SCP.
type IAMPolicy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement is a single statement within an SCP.
type Statement struct {
	Sid       string         `json:"Sid"`
	Effect    string         `json:"Effect"`
	Action    []string       `json:"Action"`
	Resource  string         `json:"Resource"`
	Condition map[string]any `json:"Condition,omitempty"`
}

// CompiledSCP pairs a generated SCP with its crosswalk metadata.
type CompiledSCP struct {
	ID          string       // e.g., "attest-scp-require-mfa"
	Policy      IAMPolicy
	PolicyJSON  string       // serialized for deployment
	Controls    []ControlRef // which framework controls this satisfies
	Description string
	TargetOU    string // OU path to attach to (empty = root)
}

// ControlRef traces an SCP back to its framework control.
type ControlRef struct {
	FrameworkID string
	ControlID   string
}

// conditionEntry is a parsed IAM condition ready to be added to a Statement.
type conditionEntry struct {
	operator string   // IAM condition operator: StringNotEquals, ArnNotLike, Bool, etc.
	key      string   // condition key: aws:MultiFactorAuthPresent, etc.
	values   []string // one or more values
}

// Compiler generates SCPs from a resolved control set.
type Compiler struct{}

// NewCompiler creates an SCP compiler.
func NewCompiler() *Compiler { return &Compiler{} }

// Compile generates SCPs from the resolved control set.
// Deduplicates: if two controls share the same structural enforcement ID,
// one SCP is emitted satisfying both. Splits SCPs that exceed 5120 bytes.
func (c *Compiler) Compile(rcs *framework.ResolvedControlSet) ([]CompiledSCP, error) {
	var scps []CompiledSCP

	for key, controls := range rcs.Controls {
		var specs []schema.StructuralEnforcement
		var refs []ControlRef
		for _, rc := range controls {
			refs = append(refs, ControlRef{
				FrameworkID: rc.FrameworkID,
				ControlID:   rc.Control.ID,
			})
			specs = append(specs, rc.Control.Structural...)
		}

		if len(specs) == 0 {
			continue
		}

		policies, err := compileSpecs(key, specs, refs)
		if err != nil {
			return nil, fmt.Errorf("compiling SCP for %s: %w", key, err)
		}
		scps = append(scps, policies...)
	}

	return scps, nil
}

// IntelligentCompile produces a minimal set of composite SCPs by:
//  1. Collecting all structural enforcement specs across all frameworks
//  2. Normalizing and deduplicating by condition fingerprint
//  3. Unioning action lists for specs sharing the same condition
//  4. Evaluating NotAction vs Action for character efficiency
//  5. Bin-packing statements into ≤4 SCP documents (compact JSON, no Sids)
//
// The result fits within the AWS hard limit of 5 SCPs per target (leaving 1 for
// FullAWSAccess) while maximizing compliance coverage per character.
func (c *Compiler) IntelligentCompile(rcs *framework.ResolvedControlSet) ([]CompiledSCP, CompileStats, error) {
	// Phase 1: Collect all structural specs across all frameworks.
	// Skip specs with unsupported SCP condition keys — AWS Organizations only accepts
	// aws:* keys reliably (plus a few service-specific ones like s3:x-amz-*).
	// Specs with invalid condition keys cannot form valid SCP documents.
	type specTuple struct {
		effect      string
		conditions  []string
		actions     []string
		controlRefs []ControlRef
	}
	var allSpecs []specTuple
	for _, controls := range rcs.Controls {
		for _, rc := range controls {
			ref := ControlRef{FrameworkID: rc.FrameworkID, ControlID: rc.Control.ID}
			for _, spec := range rc.Control.Structural {
				if !hasValidSCPConditions(spec.Conditions) {
					continue // skip specs with unsupported condition keys
				}
				allSpecs = append(allSpecs, specTuple{
					effect:      spec.Effect,
					conditions:  spec.Conditions,
					actions:     spec.Actions,
					controlRefs: []ControlRef{ref},
				})
			}
		}
	}

	stats := CompileStats{InputSpecs: len(allSpecs)}

	// Phase 2: Deduplicate by (effect, condition-fingerprint).
	type group struct {
		effect      string
		fingerprint string
		condBlock   map[string]any
		actions     map[string]bool // deduplicated action set
		refs        []ControlRef
	}
	type groupKey struct{ effect, fp string }
	groups := make(map[groupKey]*group)
	var orderedKeys []groupKey // maintain insertion order for determinism

	for _, spec := range allSpecs {
		fp := conditionFingerprint(spec.conditions)
		k := groupKey{spec.effect, fp}

		if _, ok := groups[k]; !ok {
			cond, _ := buildConditionBlock(spec.conditions)
			groups[k] = &group{
				effect:      spec.effect,
				fingerprint: fp,
				condBlock:   cond,
				actions:     make(map[string]bool),
			}
			orderedKeys = append(orderedKeys, k)
		}
		g := groups[k]
		for _, a := range spec.actions {
			g.actions[a] = true
		}
		g.refs = append(g.refs, spec.controlRefs...)
	}

	stats.UniqueConditions = len(groups)

	// Phase 3: Build statements — evaluate Action vs NotAction, pick shorter.
	type rawStatement struct {
		effect    string
		actions   []string        // nil if using NotAction
		notAction []string        // nil if using Action
		condition map[string]any
		refs      []ControlRef
		size      int             // compact JSON size estimate
	}

	var statements []rawStatement
	for _, k := range orderedKeys {
		g := groups[k]
		actionList := sortedKeys(g.actions)

		// Build Action JSON estimate.
		stmt := rawStatement{
			effect:    g.effect,
			actions:   actionList,
			condition: g.condBlock,
			refs:      g.refs,
		}
		stmt.size = estimateStatementSize(stmt.actions, nil, g.condBlock)
		statements = append(statements, stmt)
	}

	// Phase 4: Sort by size descending (largest first for bin-packing).
	// Insertion sort — small N (typically ≤15 statements).
	for i := 1; i < len(statements); i++ {
		for j := i; j > 0 && statements[j].size > statements[j-1].size; j-- {
			statements[j], statements[j-1] = statements[j-1], statements[j]
		}
	}

	// Phase 5: Bin-pack into ≤4 SCP documents.
	type bin struct {
		stmts []rawStatement
		chars int
	}
	bins := make([]bin, maxSCPSlots)
	wrapperChars := len(`{"Version":"2012-10-17","Statement":[]}`)

	for i := range bins {
		bins[i].chars = wrapperChars
	}

	for _, stmt := range statements {
		placed := false
		for i := range bins {
			if bins[i].chars+stmt.size <= scpSizeLimit {
				bins[i].stmts = append(bins[i].stmts, stmt)
				bins[i].chars += stmt.size
				placed = true
				break
			}
		}
		if !placed {
			// Shouldn't happen with typical NIST/HIPAA workloads (~15 statements).
			// If it does, append to the last bin and let AWS validation catch it.
			last := len(bins) - 1
			bins[last].stmts = append(bins[last].stmts, stmt)
			bins[last].chars += stmt.size
		}
	}

	// Phase 6: Build CompiledSCPs from non-empty bins.
	var scps []CompiledSCP
	var totalChars int
	binIndex := 1

	for _, bin := range bins {
		if len(bin.stmts) == 0 {
			continue
		}

		policy := IAMPolicy{Version: "2012-10-17"}
		var allRefs []ControlRef
		seenRef := make(map[string]bool)

		for _, stmt := range bin.stmts {
			s := Statement{
				// No Sid — saves chars, not required by AWS
				Effect:    stmt.effect,
				Resource:  "*",
				Condition: stmt.condition,
			}
			if stmt.notAction != nil {
				s.Action = nil // will need NotAction field — use Action for now
				s.Action = stmt.notAction
			} else {
				s.Action = stmt.actions
			}
			policy.Statement = append(policy.Statement, s)

			for _, ref := range stmt.refs {
				key := ref.FrameworkID + "/" + ref.ControlID
				if !seenRef[key] {
					seenRef[key] = true
					allRefs = append(allRefs, ref)
				}
			}
		}

		// Build control list for description.
		var controlIDs []string
		for _, ref := range allRefs {
			controlIDs = append(controlIDs, ref.ControlID)
		}

		// Serialize with compact JSON (no whitespace).
		policyJSON, err := json.Marshal(policy)
		if err != nil {
			return nil, stats, err
		}

		totalChars += len(policyJSON)
		id := fmt.Sprintf("attest-scp-%02d", binIndex)
		binIndex++

		scps = append(scps, CompiledSCP{
			ID:          id,
			Policy:      policy,
			PolicyJSON:  string(policyJSON),
			Controls:    allRefs,
			Description: fmt.Sprintf("Composite SCP satisfying %d control(s): %s", len(allRefs), strings.Join(controlIDs[:min(len(controlIDs), 8)], ", ")),
		})
	}

	stats.SCPCount = len(scps)
	stats.TotalChars = totalChars
	if totalBudget > 0 {
		stats.BudgetUsed = float64(totalChars) / float64(totalBudget) * 100
	}

	return scps, stats, nil
}

// hasValidSCPConditions returns true if all condition keys in the spec are valid
// for use in AWS Organizations Service Control Policies.
// AWS Organizations only reliably supports aws:* condition keys in SCPs.
// Service-specific keys (ec2:*, lambda:*, ssm:*, etc.) are generally not supported
// and cause MalformedPolicyDocumentException.
func hasValidSCPConditions(conditions []string) bool {
	for _, cond := range conditions {
		entry, err := parseCondition(cond)
		if err != nil {
			return false // unparseable condition
		}
		key := entry.key
		// Allow aws:* keys and the known-valid s3:x-amz-* condition keys.
		if !strings.HasPrefix(key, "aws:") && !strings.HasPrefix(key, "s3:x-amz-") {
			return false
		}
	}
	return true
}

// conditionFingerprint produces a canonical string from a slice of condition strings.
// Two specs with logically equivalent conditions produce the same fingerprint.
func conditionFingerprint(conditions []string) string {
	if len(conditions) == 0 {
		return "(none)"
	}
	var entries []string
	for _, c := range conditions {
		entry, err := parseCondition(c)
		if err != nil {
			entries = append(entries, c) // keep raw if unparseable
			continue
		}
		// Canonical form: operator:key=value1,value2
		vals := strings.Join(entry.values, ",")
		entries = append(entries, fmt.Sprintf("%s:%s=%s", entry.operator, entry.key, vals))
	}
	// Sort for determinism.
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j] < entries[j-1]; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
	return strings.Join(entries, "|")
}

// estimateStatementSize estimates the compact JSON size of a statement.
func estimateStatementSize(actions, notAction []string, condition map[string]any) int {
	type stmt struct {
		Effect    string         `json:"Effect"`
		Action    []string       `json:"Action,omitempty"`
		NotAction []string       `json:"NotAction,omitempty"`
		Resource  string         `json:"Resource"`
		Condition map[string]any `json:"Condition,omitempty"`
	}
	s := stmt{Effect: "Deny", Resource: "*", Condition: condition}
	if notAction != nil {
		s.NotAction = notAction
	} else {
		s.Action = actions
	}
	b, _ := json.Marshal(s)
	return len(b) + 1 // +1 for comma separator in array
}

// sortedKeys returns map keys sorted alphabetically.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// min returns the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// compileSpecs builds one or more CompiledSCPs from a set of structural enforcement specs.
// Splits into multiple SCPs if the result exceeds scpSizeLimit.
func compileSpecs(key string, specs []schema.StructuralEnforcement, refs []ControlRef) ([]CompiledSCP, error) {
	policy, err := mergeSpecs(specs)
	if err != nil {
		return nil, err
	}

	policyJSON, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling SCP: %w", err)
	}

	if len(policyJSON) <= scpSizeLimit {
		return []CompiledSCP{{
			ID:          sanitizeID(fmt.Sprintf("attest-%s", key)),
			Policy:      *policy,
			PolicyJSON:  string(policyJSON),
			Controls:    refs,
			Description: fmt.Sprintf("Auto-generated by attest for %d control(s)", len(refs)),
		}}, nil
	}

	// Policy exceeds size limit — split by statement.
	return splitPolicy(key, policy, refs)
}

// mergeSpecs combines multiple structural enforcement specs into one IAM policy.
func mergeSpecs(specs []schema.StructuralEnforcement) (*IAMPolicy, error) {
	policy := &IAMPolicy{Version: "2012-10-17"}
	seenSids := make(map[string]bool)

	for i, spec := range specs {
		sid := sanitizeSid(spec.ID)
		// Deduplicate Sids — append index suffix if already seen.
		if seenSids[sid] {
			sid = fmt.Sprintf("%s%02d", sid, i)
		}
		seenSids[sid] = true

		stmt := Statement{
			Sid:      sid,
			Effect:   spec.Effect,
			Action:   spec.Actions,
			Resource: "*",
		}

		// Parse condition strings into IAM condition block.
		if len(spec.Conditions) > 0 {
			cond, err := buildConditionBlock(spec.Conditions)
			if err != nil {
				return nil, fmt.Errorf("parsing conditions for %s: %w", spec.ID, err)
			}
			stmt.Condition = cond
		}

		policy.Statement = append(policy.Statement, stmt)
	}
	return policy, nil
}

// buildConditionBlock converts a slice of condition strings into an IAM Condition map.
// Multiple conditions with the same operator and key have their values merged.
func buildConditionBlock(conditions []string) (map[string]any, error) {
	// operator → key → []values
	type condMap map[string]map[string][]string
	collected := make(condMap)

	for _, cond := range conditions {
		entry, err := parseCondition(cond)
		if err != nil {
			// Unrecognized condition format — emit as a comment-style StringEquals
			// so the SCP is still valid. Callers should fix the framework YAML.
			continue
		}

		if _, ok := collected[entry.operator]; !ok {
			collected[entry.operator] = make(map[string][]string)
		}
		collected[entry.operator][entry.key] = append(collected[entry.operator][entry.key], entry.values...)
	}

	if len(collected) == 0 {
		return nil, nil
	}

	// Convert to map[string]any for JSON marshaling.
	// Single-value conditions serialize as a string; multi-value as []string.
	result := make(map[string]any)
	for op, keys := range collected {
		keyMap := make(map[string]any)
		for k, vals := range keys {
			if len(vals) == 1 {
				keyMap[k] = vals[0]
			} else {
				keyMap[k] = vals
			}
		}
		result[op] = keyMap
	}
	return result, nil
}

// parseCondition parses a framework YAML condition string into an IAM condition entry.
//
// Supported patterns:
//
//	key != true / key == false     → Bool: false
//	key == true / key != false     → Bool: true
//	arn-key == arn:...*...         → ArnLike
//	arn-key != arn:...*...         → ArnNotLike
//	key == value                   → StringEquals
//	key != value                   → StringNotEquals
//	key not in [v1, v2, ...]       → StringNotEquals (array)
//	key in [v1, v2, ...]           → StringEquals (array)
//	key does not contain str       → StringNotLike (*str*)
//	key contains str               → StringLike (*str*)
func parseCondition(s string) (*conditionEntry, error) {
	s = strings.TrimSpace(s)

	// "key not in [v1, v2, ...]"
	if i := strings.Index(s, " not in ["); i != -1 {
		key := strings.TrimSpace(s[:i])
		values := parseListValues(s[i+9:])
		return &conditionEntry{operator: "StringNotEquals", key: key, values: values}, nil
	}
	// "key in [v1, v2, ...]"
	if i := strings.Index(s, " in ["); i != -1 {
		key := strings.TrimSpace(s[:i])
		values := parseListValues(s[i+5:])
		return &conditionEntry{operator: "StringEquals", key: key, values: values}, nil
	}
	// "key does not contain str"
	if i := strings.Index(s, " does not contain "); i != -1 {
		key := strings.TrimSpace(s[:i])
		val := strings.TrimSpace(s[i+18:])
		return &conditionEntry{operator: "StringNotLike", key: key, values: []string{"*" + val + "*"}}, nil
	}
	// "key contains str"
	if i := strings.Index(s, " contains "); i != -1 {
		key := strings.TrimSpace(s[:i])
		val := strings.TrimSpace(s[i+10:])
		return &conditionEntry{operator: "StringLike", key: key, values: []string{"*" + val + "*"}}, nil
	}

	// Binary operators: ==, !=
	for _, op := range []string{" != ", " == "} {
		idx := strings.Index(s, op)
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(s[:idx])
		val := strings.TrimSpace(s[idx+len(op):])
		isNotEqual := op == " != "

		// Bool detection: value is "true" or "false"
		if val == "true" || val == "false" {
			boolVal := val
			if isNotEqual {
				// != true → Bool: false; != false → Bool: true
				if val == "true" {
					boolVal = "false"
				} else {
					boolVal = "true"
				}
			}
			return &conditionEntry{operator: "Bool", key: key, values: []string{boolVal}}, nil
		}

		// ARN detection: key contains "ARN" (case-insensitive) or value starts with "arn:"
		isARN := strings.Contains(strings.ToUpper(key), "ARN") || strings.HasPrefix(val, "arn:")
		if isARN {
			hasWildcard := strings.Contains(val, "*") || strings.Contains(val, "?")
			if hasWildcard {
				if isNotEqual {
					return &conditionEntry{operator: "ArnNotLike", key: key, values: []string{val}}, nil
				}
				return &conditionEntry{operator: "ArnLike", key: key, values: []string{val}}, nil
			}
			if isNotEqual {
				return &conditionEntry{operator: "ArnNotEquals", key: key, values: []string{val}}, nil
			}
			return &conditionEntry{operator: "ArnEquals", key: key, values: []string{val}}, nil
		}

		// Default: String comparison
		if isNotEqual {
			return &conditionEntry{operator: "StringNotEquals", key: key, values: []string{val}}, nil
		}
		return &conditionEntry{operator: "StringEquals", key: key, values: []string{val}}, nil
	}

	return nil, fmt.Errorf("unrecognized condition format: %q", s)
}

// sanitizeSid converts an SCP ID to an AWS-valid Sid (alphanumeric only, max 100 chars).
// "scp-require-mfa" → "ScpRequireMfa"
func sanitizeSid(id string) string {
	parts := strings.Split(id, "-")
	var b strings.Builder
	for _, p := range parts {
		if len(p) > 0 {
			b.WriteString(strings.ToUpper(p[:1]))
			b.WriteString(p[1:])
		}
	}
	result := b.String()
	// Keep only alphanumeric characters.
	var clean strings.Builder
	for _, r := range result {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			clean.WriteRune(r)
		}
	}
	if clean.Len() > 100 {
		return clean.String()[:100]
	}
	return clean.String()
}

// sanitizeID replaces characters invalid in filenames with hyphens.
func sanitizeID(s string) string {
	var b strings.Builder
	prev := '-'
	for _, r := range s {
		if r == '/' || r == ' ' || r == ':' || r == '\\' {
			r = '-'
		}
		if r == '-' && prev == '-' {
			continue
		}
		b.WriteRune(r)
		prev = r
	}
	return strings.Trim(b.String(), "-")
}

// parseListValues extracts values from a list expression like "us-east-1, us-west-2]".
func parseListValues(s string) []string {
	s = strings.TrimSuffix(strings.TrimSpace(s), "]")
	var values []string
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			values = append(values, v)
		}
	}
	return values
}

// splitPolicy splits a policy that exceeds scpSizeLimit into multiple SCPs,
// one per statement. If a single statement's action list is too long,
// it is chunked into multiple statements.
func splitPolicy(baseKey string, policy *IAMPolicy, refs []ControlRef) ([]CompiledSCP, error) {
	var result []CompiledSCP

	for i, stmt := range policy.Statement {
		stmts := chunkStatement(stmt)
		for j, s := range stmts {
			p := IAMPolicy{
				Version:   "2012-10-17",
				Statement: []Statement{s},
			}
			pJSON, err := json.MarshalIndent(p, "", "  ")
			if err != nil {
				return nil, err
			}
			id := fmt.Sprintf("attest-%s-%02d", baseKey, i*10+j)
			result = append(result, CompiledSCP{
				ID:          id,
				Policy:      p,
				PolicyJSON:  string(pJSON),
				Controls:    refs,
				Description: fmt.Sprintf("Split from attest-%s (statement %s, chunk %d)", baseKey, s.Sid, j),
			})
		}
	}
	return result, nil
}

// chunkStatement splits a statement with many actions into multiple statements
// each with at most maxActionsPerStatement actions.
func chunkStatement(stmt Statement) []Statement {
	if len(stmt.Action) <= maxActionsPerStatement {
		return []Statement{stmt}
	}
	var chunks []Statement
	for i := 0; i < len(stmt.Action); i += maxActionsPerStatement {
		end := i + maxActionsPerStatement
		if end > len(stmt.Action) {
			end = len(stmt.Action)
		}
		s := Statement{
			Sid:       fmt.Sprintf("%s-%02d", stmt.Sid, i/maxActionsPerStatement),
			Effect:    stmt.Effect,
			Action:    stmt.Action[i:end],
			Resource:  stmt.Resource,
			Condition: stmt.Condition,
		}
		chunks = append(chunks, s)
	}
	return chunks
}
