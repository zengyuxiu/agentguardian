package rules

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultVersion = 1

type Ruleset struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type Rule struct {
	ID       string     `yaml:"id"`
	Enabled  bool       `yaml:"enabled"`
	Priority int        `yaml:"priority"`
	Match    MatchSpec  `yaml:"match"`
	Action   ActionSpec `yaml:"action"`
	Comment  string     `yaml:"comment,omitempty"`
	Source   string     `yaml:"-"`
}

type MatchSpec struct {
	Path string  `yaml:"path"`
	PID  *uint32 `yaml:"pid,omitempty"`
	Comm string  `yaml:"comm,omitempty"`
	Exe  string  `yaml:"exe,omitempty"`
}

type ActionSpec struct {
	Type    ActionType `yaml:"type"`
	Find    string     `yaml:"find,omitempty"`
	Replace string     `yaml:"replace,omitempty"`
}

type ActionType string

const (
	ActionHide    ActionType = "hide"
	ActionRewrite ActionType = "rewrite"
)

func (r *Rule) UnmarshalYAML(value *yaml.Node) error {
	type rawRule Rule

	aux := rawRule{
		Enabled: true,
	}
	if err := value.Decode(&aux); err != nil {
		return err
	}

	*r = Rule(aux)
	return nil
}

func (rs Ruleset) Normalized() Ruleset {
	out := Ruleset{
		Version: rs.Version,
		Rules:   make([]Rule, len(rs.Rules)),
	}
	if out.Version == 0 {
		out.Version = DefaultVersion
	}

	for i, rule := range rs.Rules {
		out.Rules[i] = rule.normalized()
	}

	return out
}

func (r Rule) normalized() Rule {
	out := r
	out.ID = strings.TrimSpace(out.ID)
	out.Comment = strings.TrimSpace(out.Comment)

	out.Match.Path = strings.TrimSpace(out.Match.Path)
	out.Match.Comm = strings.TrimSpace(out.Match.Comm)
	out.Match.Exe = strings.TrimSpace(out.Match.Exe)

	out.Action.Type = ActionType(strings.TrimSpace(string(out.Action.Type)))
	out.Action.Find = strings.TrimSpace(out.Action.Find)
	out.Action.Replace = strings.TrimSpace(out.Action.Replace)

	return out
}

func (r Rule) String() string {
	if r.ID == "" {
		return "<unnamed rule>"
	}
	if r.Source == "" {
		return r.ID
	}
	return fmt.Sprintf("%s (%s)", r.ID, r.Source)
}
