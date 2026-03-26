package control

import (
	"time"

	"github.com/zengyuxiu/agentguardian/internal/rules"
)

type Scope string

const (
	ScopePermanent Scope = "permanent"
	ScopeRuntime   Scope = "runtime"
)

type RulesetState struct {
	Scope               Scope     `json:"scope"`
	Path                string    `json:"path"`
	Loaded              bool      `json:"loaded"`
	Valid               bool      `json:"valid"`
	Version             int       `json:"version"`
	RuleCount           int       `json:"rule_count"`
	PIDPolicyCount      int       `json:"pid_policy_count,omitempty"`
	CommPolicyCount     int       `json:"comm_policy_count,omitempty"`
	Generation          uint64    `json:"generation,omitempty"`
	RequiresProcessSync bool      `json:"requires_process_sync"`
	Warnings            []string  `json:"warnings,omitempty"`
	UpdatedAt           time.Time `json:"updated_at,omitempty"`
	Error               string    `json:"error,omitempty"`
}

type StatusResponse struct {
	ConfigDir string       `json:"config_dir"`
	RulesDir  string       `json:"rules_dir"`
	Socket    string       `json:"socket"`
	Runtime   RulesetState `json:"runtime"`
	Permanent RulesetState `json:"permanent"`
}

type ValidateResponse struct {
	Scope   Scope        `json:"scope"`
	State   RulesetState `json:"state"`
	Message string       `json:"message,omitempty"`
}

type ReloadResponse struct {
	Message   string       `json:"message"`
	Runtime   RulesetState `json:"runtime"`
	Permanent RulesetState `json:"permanent"`
}

type ApplyRuntimeRequest struct {
	Ruleset rules.Ruleset `json:"ruleset"`
}

type ApplyResponse struct {
	Scope     Scope        `json:"scope"`
	Message   string       `json:"message"`
	Runtime   RulesetState `json:"runtime"`
	Permanent RulesetState `json:"permanent"`
}

type SaveResponse struct {
	Message   string       `json:"message"`
	Runtime   RulesetState `json:"runtime"`
	Permanent RulesetState `json:"permanent"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
