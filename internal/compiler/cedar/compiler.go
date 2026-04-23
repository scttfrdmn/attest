// Package cedar compiles framework controls into Cedar policies for
// runtime operational enforcement. While SCPs provide structural boundaries,
// Cedar policies evaluate context-dependent conditions at decision time:
// data classification, destination attributes, temporal constraints, and
// principal qualifications.
package cedar

import (
	"fmt"
	"sort"
	"strings"

	"github.com/provabl/attest/internal/framework"
	"github.com/provabl/attest/pkg/schema"
)

// CompiledCedarPolicy pairs a generated Cedar policy with crosswalk metadata.
type CompiledCedarPolicy struct {
	ID          string
	PolicyText  string       // Cedar policy language text
	Entities    EntitySchema // Cedar entity types and attributes
	Controls    []ControlRef
	Description string
}

// ControlRef traces a Cedar policy back to its framework control.
type ControlRef struct {
	FrameworkID string
	ControlID   string
}

// EntitySchema describes the Cedar entity types needed by a policy.
type EntitySchema struct {
	Types   []EntityType
	Actions []ActionDef
}

// EntityType is a Cedar entity type (e.g., DataObject, DestinationBucket, Principal).
type EntityType struct {
	Name       string
	Attributes map[string]string // attr name → Cedar type: "Bool", "String", "Long", "Set<String>"
}

// ActionDef is a Cedar action with its applicable entity types.
type ActionDef struct {
	Name      string
	AppliesTo []string // entity type names
}

// Compiler generates Cedar policies and schema from resolved controls.
type Compiler struct{}

// NewCompiler creates a Cedar policy compiler.
func NewCompiler() *Compiler { return &Compiler{} }

// Compile generates Cedar policies from the resolved control set.
func (c *Compiler) Compile(rcs *framework.ResolvedControlSet) ([]CompiledCedarPolicy, error) {
	var policies []CompiledCedarPolicy

	for key, controls := range rcs.Controls {
		var specs []schema.OperationalEnforcement
		var refs []ControlRef
		for _, rc := range controls {
			refs = append(refs, ControlRef{
				FrameworkID: rc.FrameworkID,
				ControlID:   rc.Control.ID,
			})
			specs = append(specs, rc.Control.Operational...)
		}

		if len(specs) == 0 {
			continue
		}

		for _, spec := range specs {
			policyText, entities := compileCedarSpec(spec)
			policies = append(policies, CompiledCedarPolicy{
				ID:          sanitizeID(fmt.Sprintf("attest-%s-%s", key, spec.ID)),
				PolicyText:  policyText,
				Entities:    entities,
				Controls:    refs,
				Description: spec.Description,
			})
		}
	}
	return policies, nil
}

// BuildSchema generates a Cedar human-readable schema (.cedarschema) from all
// operational enforcement specs in the resolved control set. The schema defines
// the entity types and actions referenced across all compiled policies.
func (c *Compiler) BuildSchema(rcs *framework.ResolvedControlSet) string {
	// Collect all entity types and actions across all controls.
	entityDefs := make(map[string]map[string]string) // entity name → attr → Cedar type
	actionDefs := make(map[string][]string)           // action name → principal+resource types

	for _, controls := range rcs.Controls {
		for _, rc := range controls {
			for _, spec := range rc.Control.Operational {
				// Collect entity types.
				for _, entityName := range spec.Entities {
					if _, ok := entityDefs[entityName]; !ok {
						entityDefs[entityName] = make(map[string]string)
					}
					if attrs, ok := spec.Attributes[entityName]; ok {
						for _, attr := range attrs {
							entityDefs[entityName][attr] = inferCedarType(attr)
						}
					}
				}

				// Infer actions from Cedar policy text or spec description.
				for _, actionName := range extractActions(spec) {
					if _, ok := actionDefs[actionName]; !ok {
						actionDefs[actionName] = spec.Entities
					}
				}
			}
		}
	}

	// Add temporal context entity if any control uses temporal constraints.
	for _, controls := range rcs.Controls {
		for _, rc := range controls {
			for _, spec := range rc.Control.Operational {
				if spec.Temporal != nil {
					if _, ok := entityDefs["context"]; !ok {
						entityDefs["context"] = make(map[string]string)
					}
					entityDefs["context"]["current_time"] = "Long"
					entityDefs["context"]["hour"] = "Long"
					entityDefs["context"]["day_of_week"] = "Long"
				}
			}
		}
	}

	var b strings.Builder
	b.WriteString("// Cedar schema for attest SRE compliance policies\n")
	b.WriteString("// Auto-generated — do not edit manually\n\n")

	// Emit entity types in deterministic order.
	entityNames := sortedKeys(entityDefs)
	for _, name := range entityNames {
		attrs := entityDefs[name]
		b.WriteString(fmt.Sprintf("entity %s {\n", toCedarEntityName(name)))
		attrNames := sortedKeys(attrs)
		for _, attr := range attrNames {
			b.WriteString(fmt.Sprintf("  %s: %s,\n", attr, attrs[attr]))
		}
		b.WriteString("}\n\n")
	}

	// Emit action declarations.
	actionNames := sortedKeys(actionDefs)
	for _, name := range actionNames {
		entities := actionDefs[name]
		principalTypes, resourceTypes := splitEntityRoles(entities)
		b.WriteString(fmt.Sprintf("action %q appliesTo {\n", name))
		if len(principalTypes) > 0 {
			b.WriteString(fmt.Sprintf("  principal: [%s],\n", strings.Join(principalTypes, ", ")))
		}
		if len(resourceTypes) > 0 {
			b.WriteString(fmt.Sprintf("  resource: [%s],\n", strings.Join(resourceTypes, ", ")))
		}
		b.WriteString("}\n\n")
	}

	return b.String()
}

// sanitizeCedarComment strips characters that would escape a Cedar line comment.
// A newline in a description terminates the // comment and allows injecting
// arbitrary Cedar policy statements on subsequent lines.
func sanitizeCedarComment(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// isValidCedarIdentifier reports whether name is a safe Cedar identifier.
// Rejects anything that could break out of an identifier context in generated policy text.
func isValidCedarIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// compileCedarSpec translates an operational enforcement spec into Cedar policy text.
func compileCedarSpec(spec schema.OperationalEnforcement) (string, EntitySchema) {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("// %s\n", sanitizeCedarComment(spec.Description)))
	b.WriteString(fmt.Sprintf("// Auto-generated by attest — policy %s\n\n", sanitizeCedarComment(spec.ID)))

	if spec.CedarPolicy != "" {
		b.WriteString(spec.CedarPolicy)
	} else {
		b.WriteString(generateFromSpec(spec))
	}

	entities := buildEntitySchema(spec)
	return b.String(), entities
}

// generateFromSpec creates a Cedar forbid-unless policy from entity and attribute declarations.
func generateFromSpec(spec schema.OperationalEnforcement) string {
	var b strings.Builder
	b.WriteString("forbid (\n  principal,\n  action,\n  resource\n)\nunless {\n")

	var conditions []string

	// Entity attribute conditions.
	for _, entityName := range spec.Entities {
		if !isValidCedarIdentifier(entityName) {
			continue // skip — invalid names would produce syntactically broken policy
		}
		attrs := spec.Attributes[entityName]
		for _, attr := range attrs {
			if !isValidCedarIdentifier(attr) {
				continue
			}
			cedarType := inferCedarType(attr)
			if cedarType == "Bool" {
				conditions = append(conditions, fmt.Sprintf("  %s.%s == true", entityName, attr))
			} else {
				// Non-bool attributes require explicit allow logic; emit a placeholder.
				conditions = append(conditions, fmt.Sprintf("  %s.%s != \"\"", entityName, attr))
			}
		}
	}

	// Temporal constraint conditions.
	if spec.Temporal != nil {
		switch spec.Temporal.ConditionType {
		case "expiry":
			// Training/certification expiry: check that expiry timestamp is in the future.
			conditions = append(conditions, "  context.current_time < principal.training_expiry")
		case "event":
			// Event-based: active IRB protocol or similar event must be present.
			conditions = append(conditions, "  principal.irb_active == true")
		case "schedule":
			// Schedule-based: within defined time window (placeholder — customize per policy).
			conditions = append(conditions, "  context.hour >= 0 && context.hour < 24")
		}
	}

	if len(conditions) > 0 {
		b.WriteString(strings.Join(conditions, " &&\n"))
	} else {
		b.WriteString("  true")
	}
	b.WriteString("\n};\n")
	return b.String()
}

// buildEntitySchema constructs the EntitySchema for a single operational spec.
func buildEntitySchema(spec schema.OperationalEnforcement) EntitySchema {
	es := EntitySchema{}
	for _, entityName := range spec.Entities {
		et := EntityType{
			Name:       entityName,
			Attributes: make(map[string]string),
		}
		if attrs, ok := spec.Attributes[entityName]; ok {
			for _, attr := range attrs {
				et.Attributes[attr] = inferCedarType(attr)
			}
		}
		es.Types = append(es.Types, et)
	}
	return es
}

// inferCedarType maps an attribute name to a Cedar type based on naming conventions.
func inferCedarType(attr string) string {
	lower := strings.ToLower(attr)

	// Long (numeric) indicators.
	for _, keyword := range []string{"expiry", "timestamp", "count", "level", "length", "hour", "day", "time"} {
		if strings.Contains(lower, keyword) {
			return "Long"
		}
	}

	// Set indicators.
	for _, keyword := range []string{"protocols", "membership", "classes", "groups", "tags"} {
		if strings.Contains(lower, keyword) {
			return "Set<String>"
		}
	}

	// String indicators.
	for _, keyword := range []string{"type", "id", "name", "arn", "region", "role", "scope", "key", "endpoint", "algorithm", "classification", "status", "path"} {
		if strings.Contains(lower, keyword) {
			return "String"
		}
	}

	// Default to Bool for binary flags (e.g., mfa_enabled, training_current, authorized).
	return "Bool"
}

// extractActions pulls action names from a Cedar policy's action clauses.
func extractActions(spec schema.OperationalEnforcement) []string {
	if spec.CedarPolicy == "" {
		return nil
	}
	var actions []string
	lines := strings.Split(spec.CedarPolicy, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "action ==") {
			action := strings.TrimPrefix(line, "action == Action::\"")
			action = strings.TrimSuffix(action, "\",")
			action = strings.TrimSuffix(action, "\"")
			if action != "" {
				actions = append(actions, action)
			}
		}
	}
	return actions
}

// toCedarEntityName converts a snake_case entity name to PascalCase for Cedar.
func toCedarEntityName(name string) string {
	parts := strings.Split(name, "_")
	var result strings.Builder
	for _, p := range parts {
		if len(p) > 0 {
			result.WriteString(strings.ToUpper(p[:1]))
			result.WriteString(p[1:])
		}
	}
	return result.String()
}

// splitEntityRoles heuristically assigns entity roles: the first entity
// is the principal, the rest are resources.
func splitEntityRoles(entities []string) (principals, resources []string) {
	for i, e := range entities {
		name := toCedarEntityName(e)
		if i == 0 {
			principals = append(principals, name)
		} else {
			resources = append(resources, name)
		}
	}
	return
}

// sanitizeID replaces characters that are invalid in filenames with hyphens
// and collapses consecutive hyphens.
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

// sortedKeys returns the keys of a map[string]T sorted alphabetically.
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
