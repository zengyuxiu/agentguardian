package rules

import (
	"errors"
	"fmt"
	"regexp"
)

var ruleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func ValidateRuleset(rs Ruleset) error {
	rs = rs.Normalized()

	if rs.Version <= 0 {
		return fmt.Errorf("invalid ruleset version: %d", rs.Version)
	}

	var errs []error
	seen := make(map[string]string, len(rs.Rules))
	for idx, rule := range rs.Rules {
		if err := validateRule(rule); err != nil {
			errs = append(errs, fmt.Errorf("rule[%d]: %w", idx, err))
			continue
		}

		if prev, ok := seen[rule.ID]; ok {
			errs = append(errs, fmt.Errorf("rule[%d]: duplicate id %q already defined in %s", idx, rule.ID, prev))
			continue
		}

		source := "ruleset"
		if rule.Source != "" {
			source = rule.Source
		}
		seen[rule.ID] = source
	}

	return errors.Join(errs...)
}

func validateRule(rule Rule) error {
	rule = rule.normalized()

	if rule.ID == "" {
		return errors.New("missing id")
	}
	if !ruleIDPattern.MatchString(rule.ID) {
		return fmt.Errorf("invalid id %q", rule.ID)
	}
	if rule.Match.Path == "" {
		return fmt.Errorf("rule %q: missing match.path", rule.ID)
	}

	selectorCount := 0
	if rule.Match.PID != nil {
		selectorCount++
	}
	if rule.Match.Comm != "" {
		selectorCount++
	}
	if rule.Match.Exe != "" {
		selectorCount++
	}
	if selectorCount == 0 {
		return fmt.Errorf("rule %q: one of match.pid, match.comm, or match.exe is required", rule.ID)
	}
	if selectorCount > 1 {
		return fmt.Errorf("rule %q: only one of match.pid, match.comm, or match.exe may be set", rule.ID)
	}

	switch rule.Action.Type {
	case ActionHide:
		if rule.Action.Find != "" || rule.Action.Replace != "" {
			return fmt.Errorf("rule %q: hide action must not set find/replace", rule.ID)
		}
	case ActionRewrite:
		if rule.Action.Find == "" {
			return fmt.Errorf("rule %q: rewrite action requires action.find", rule.ID)
		}
		if rule.Action.Replace == "" {
			return fmt.Errorf("rule %q: rewrite action requires action.replace", rule.ID)
		}
		if len(rule.Action.Find) != len(rule.Action.Replace) {
			return fmt.Errorf("rule %q: action.find and action.replace must have the same length", rule.ID)
		}
	default:
		return fmt.Errorf("rule %q: unsupported action type %q", rule.ID, rule.Action.Type)
	}

	return nil
}
