package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadPath(path string) (Ruleset, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Ruleset{}, err
	}

	if info.IsDir() {
		return LoadDir(path)
	}
	return LoadFile(path)
}

func LoadFile(path string) (Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Ruleset{}, err
	}

	rs, err := parseRulesYAML(data)
	if err != nil {
		return Ruleset{}, fmt.Errorf("parse %s: %w", path, err)
	}

	rs = rs.Normalized()
	for i := range rs.Rules {
		rs.Rules[i].Source = path
	}

	if err := ValidateRuleset(rs); err != nil {
		return Ruleset{}, fmt.Errorf("validate %s: %w", path, err)
	}

	return rs, nil
}

func LoadDir(dir string) (Ruleset, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Ruleset{}, err
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !isYAMLFile(entry.Name()) {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	out := Ruleset{
		Version: DefaultVersion,
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		rs, err := LoadFile(path)
		if err != nil {
			return Ruleset{}, err
		}
		out.Rules = append(out.Rules, rs.Rules...)
	}

	if err := ValidateRuleset(out); err != nil {
		return Ruleset{}, fmt.Errorf("validate merged ruleset from %s: %w", dir, err)
	}

	return out, nil
}

func parseRulesYAML(data []byte) (Ruleset, error) {
	var ruleset Ruleset
	if err := yaml.Unmarshal(data, &ruleset); err == nil && len(ruleset.Rules) > 0 {
		return ruleset, nil
	}

	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err == nil && looksLikeRule(rule) {
		return Ruleset{
			Version: DefaultVersion,
			Rules:   []Rule{rule},
		}, nil
	}

	var yamlType any
	if err := yaml.Unmarshal(data, &yamlType); err != nil {
		return Ruleset{}, err
	}

	return Ruleset{}, errors.New("yaml must be either a single rule object or a ruleset with a non-empty rules list")
}

func looksLikeRule(rule Rule) bool {
	rule = rule.normalized()
	return rule.ID != "" || rule.Match.Path != "" || rule.Action.Type != ""
}

func isYAMLFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}
