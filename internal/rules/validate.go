package rules

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"

	agentebpf "github.com/zengyuxiu/agentguardian/internal/ebpf"
)

var ruleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type ValidationReport struct {
	Warnings []string
}

func ValidateRuleset(rs Ruleset) error {
	_, err := ValidateRulesetReport(rs)
	return err
}

func ValidateRulesetReport(rs Ruleset) (ValidationReport, error) {
	rs = rs.Normalized()
	report := ValidationReport{}

	if rs.Version <= 0 {
		return report, fmt.Errorf("invalid ruleset version: %d", rs.Version)
	}

	var errs []error
	seen := make(map[string]string, len(rs.Rules))
	for idx, rule := range rs.Rules {
		warnings, err := validateRule(rule)
		report.Warnings = append(report.Warnings, warnings...)
		if err != nil {
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

	report.Warnings = dedupeStrings(report.Warnings)
	return report, errors.Join(errs...)
}

func validateRule(rule Rule) ([]string, error) {
	rule = rule.normalized()
	var warnings []string

	if rule.ID == "" {
		return warnings, errors.New("missing id")
	}
	if !ruleIDPattern.MatchString(rule.ID) {
		return warnings, fmt.Errorf("invalid id %q", rule.ID)
	}
	if rule.Match.Path == "" {
		return warnings, fmt.Errorf("rule %q: missing match.path", rule.ID)
	}
	if !filepath.IsAbs(rule.Match.Path) {
		return warnings, fmt.Errorf("rule %q: match.path must be an absolute path", rule.ID)
	}
	if len(rule.Match.Path) >= agentebpf.MaxPathLen {
		return warnings, fmt.Errorf("rule %q: match.path length must be less than %d bytes", rule.ID, agentebpf.MaxPathLen)
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
		return warnings, fmt.Errorf("rule %q: one of match.pid, match.comm, or match.exe is required", rule.ID)
	}
	if selectorCount > 1 {
		return warnings, fmt.Errorf("rule %q: only one of match.pid, match.comm, or match.exe may be set", rule.ID)
	}
	if rule.Match.PID != nil && *rule.Match.PID == 0 {
		return warnings, fmt.Errorf("rule %q: match.pid must be greater than zero", rule.ID)
	}
	if rule.Match.Comm != "" && len(rule.Match.Comm) >= agentebpf.MaxCommLen {
		return warnings, fmt.Errorf("rule %q: match.comm length must be less than %d bytes", rule.ID, agentebpf.MaxCommLen)
	}
	if rule.Match.Exe != "" && !filepath.IsAbs(rule.Match.Exe) {
		return warnings, fmt.Errorf("rule %q: match.exe must be an absolute path", rule.ID)
	}

	switch rule.Action.Type {
	case ActionHide:
		if rule.Action.Find != "" || rule.Action.Replace != "" {
			return warnings, fmt.Errorf("rule %q: hide action must not set find/replace", rule.ID)
		}
	case ActionRewrite:
		if rule.Action.Find == "" {
			return warnings, fmt.Errorf("rule %q: rewrite action requires action.find", rule.ID)
		}
		if rule.Action.Replace == "" {
			return warnings, fmt.Errorf("rule %q: rewrite action requires action.replace", rule.ID)
		}
		if len(rule.Action.Find) != len(rule.Action.Replace) {
			return warnings, fmt.Errorf("rule %q: action.find and action.replace must have the same length", rule.ID)
		}
		if len(rule.Action.Find) > agentebpf.MaxTextLen {
			return warnings, fmt.Errorf("rule %q: action.find length must be at most %d bytes", rule.ID, agentebpf.MaxTextLen)
		}
	default:
		return warnings, fmt.Errorf("rule %q: unsupported action type %q", rule.ID, rule.Action.Type)
	}

	return warnings, nil
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
