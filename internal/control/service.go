package control

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zengyuxiu/agentguardian/internal/rules"
)

type CompiledApplier interface {
	ApplyCompiled(compiled rules.Compiled) error
}

type Service struct {
	mu           sync.RWMutex
	configDir    string
	rulesDir     string
	socketPath   string
	syncInterval time.Duration
	applier      CompiledApplier

	runtimeRuleset  rules.Ruleset
	runtimeCompiled rules.Compiled
	runtimeLoaded   bool
	runtimeUpdated  time.Time
	runtimeError    string
	runtimeWarnings []string
	generation      uint64

	syncRevision uint64
	syncCancel   context.CancelFunc
}

func NewService(configDir, socketPath string, syncInterval time.Duration, applier CompiledApplier) *Service {
	return &Service{
		configDir:    configDir,
		rulesDir:     filepath.Join(configDir, "rules.d"),
		socketPath:   socketPath,
		syncInterval: syncInterval,
		applier:      applier,
	}
}

func (s *Service) EnsureLayout() error {
	if err := os.MkdirAll(s.rulesDir, 0o755); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Dir(s.socketPath), 0o755)
}

func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.syncCancel != nil {
		s.syncCancel()
		s.syncCancel = nil
	}
}

func (s *Service) Status() StatusResponse {
	permanent := s.inspectPermanent()

	s.mu.RLock()
	runtime := s.runtimeStateLocked()
	s.mu.RUnlock()

	return StatusResponse{
		ConfigDir: s.configDir,
		RulesDir:  s.rulesDir,
		Socket:    s.socketPath,
		Runtime:   runtime,
		Permanent: permanent,
	}
}

func (s *Service) Validate(scope Scope) ValidateResponse {
	switch scope {
	case ScopePermanent:
		state := s.inspectPermanent()
		resp := ValidateResponse{
			Scope: scope,
			State: state,
		}
		if state.Valid {
			resp.Message = "permanent ruleset is valid"
		}
		return resp
	case ScopeRuntime:
		s.mu.RLock()
		state := s.runtimeStateLocked()
		s.mu.RUnlock()

		resp := ValidateResponse{
			Scope: scope,
			State: state,
		}
		if state.Valid {
			resp.Message = "runtime ruleset is valid"
		}
		return resp
	default:
		return ValidateResponse{
			Scope: scope,
			State: RulesetState{
				Scope: scope,
				Path:  s.rulesDir,
				Valid: false,
				Error: fmt.Sprintf("unsupported scope %q", scope),
			},
		}
	}
}

func (s *Service) Reload() (ReloadResponse, error) {
	permanentRuleset, compiled, permanentState, err := s.loadAndCompilePermanent()
	if err != nil {
		return ReloadResponse{
			Message:   "reload failed",
			Runtime:   s.runtimeState(),
			Permanent: permanentState,
		}, err
	}

	runtimeState, err := s.applyRuntime(permanentRuleset, compiled, permanentState.Warnings)
	if err != nil {
		return ReloadResponse{
			Message:   "reload failed",
			Runtime:   s.runtimeState(),
			Permanent: permanentState,
		}, err
	}

	return ReloadResponse{
		Message:   "reload applied permanent ruleset to runtime",
		Runtime:   runtimeState,
		Permanent: permanentState,
	}, nil
}

func (s *Service) ApplyRuntime(rs rules.Ruleset) (ApplyResponse, error) {
	rs = rs.Normalized()

	compiled, report, err := rules.CompileWithReport(rs, rules.CompileOptions{})
	if err != nil {
		return ApplyResponse{
			Scope:     ScopeRuntime,
			Message:   "apply failed",
			Runtime:   s.runtimeState(),
			Permanent: s.inspectPermanent(),
		}, err
	}

	runtimeState, err := s.applyRuntime(rs, compiled, report.Warnings)
	if err != nil {
		return ApplyResponse{
			Scope:     ScopeRuntime,
			Message:   "apply failed",
			Runtime:   s.runtimeState(),
			Permanent: s.inspectPermanent(),
		}, err
	}

	return ApplyResponse{
		Scope:     ScopeRuntime,
		Message:   "runtime ruleset applied",
		Runtime:   runtimeState,
		Permanent: s.inspectPermanent(),
	}, nil
}

func (s *Service) inspectPermanent() RulesetState {
	_, _, state, _ := s.loadAndCompilePermanent()
	return state
}

func (s *Service) loadAndCompilePermanent() (rules.Ruleset, rules.Compiled, RulesetState, error) {
	rs, err := rules.LoadDir(s.rulesDir)
	state := RulesetState{
		Scope: ScopePermanent,
		Path:  s.rulesDir,
	}
	if err != nil {
		state.Valid = false
		state.Error = err.Error()
		return rules.Ruleset{}, rules.Compiled{}, state, err
	}

	compiled, report, err := rules.CompileWithReport(rs, rules.CompileOptions{})
	state.Loaded = true
	state.Valid = err == nil
	state.Version = rs.Version
	state.RuleCount = len(rs.Rules)
	state.PIDPolicyCount = len(compiled.PIDPolicies)
	state.CommPolicyCount = len(compiled.CommPolicies)
	state.RequiresProcessSync = rules.NeedsProcessScan(rs)
	state.Warnings = report.Warnings
	if err != nil {
		state.Error = err.Error()
		return rs, rules.Compiled{}, state, err
	}

	return rs, compiled, state, nil
}

func (s *Service) runtimeState() RulesetState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runtimeStateLocked()
}

func (s *Service) runtimeStateLocked() RulesetState {
	state := RulesetState{
		Scope: ScopeRuntime,
		Path:  s.rulesDir,
	}
	if !s.runtimeLoaded {
		state.Valid = false
		if s.runtimeError != "" {
			state.Error = s.runtimeError
		}
		return state
	}

	state.Loaded = true
	state.Valid = s.runtimeError == ""
	state.Version = s.runtimeRuleset.Version
	state.RuleCount = len(s.runtimeRuleset.Rules)
	state.PIDPolicyCount = len(s.runtimeCompiled.PIDPolicies)
	state.CommPolicyCount = len(s.runtimeCompiled.CommPolicies)
	state.RequiresProcessSync = rules.NeedsProcessScan(s.runtimeRuleset)
	state.Warnings = s.runtimeWarnings
	state.Generation = s.generation
	state.UpdatedAt = s.runtimeUpdated
	state.Error = s.runtimeError

	return state
}

func (s *Service) restartSyncLocked(rs rules.Ruleset) {
	s.syncRevision++
	revision := s.syncRevision

	if s.syncCancel != nil {
		s.syncCancel()
		s.syncCancel = nil
	}
	if !rules.NeedsProcessScan(rs) {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.syncCancel = cancel

	go s.syncLoop(ctx, revision, rs)
}

func (s *Service) syncLoop(ctx context.Context, revision uint64, rs rules.Ruleset) {
	ticker := time.NewTicker(s.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		compiled, report, err := rules.CompileWithReport(rs, rules.CompileOptions{})
		if err != nil {
			s.setRuntimeError(err)
			continue
		}

		s.mu.RLock()
		same := compiledEqual(s.runtimeCompiled, compiled)
		currentRevision := s.syncRevision
		s.mu.RUnlock()
		if same || currentRevision != revision {
			continue
		}

		if err := s.applier.ApplyCompiled(compiled); err != nil {
			s.setRuntimeError(err)
			continue
		}

		s.mu.Lock()
		if s.syncRevision != revision {
			s.mu.Unlock()
			continue
		}
		s.runtimeCompiled = compiled
		s.runtimeUpdated = time.Now()
		s.runtimeError = ""
		s.runtimeWarnings = report.Warnings
		s.generation++
		s.mu.Unlock()
	}
}

func (s *Service) setRuntimeError(err error) {
	if err == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.runtimeError = err.Error()
}

func (s *Service) applyRuntime(rs rules.Ruleset, compiled rules.Compiled, warnings []string) (RulesetState, error) {
	if err := s.applier.ApplyCompiled(compiled); err != nil {
		s.mu.Lock()
		s.runtimeError = err.Error()
		s.mu.Unlock()
		return RulesetState{}, err
	}

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.runtimeRuleset = rs
	s.runtimeCompiled = compiled
	s.runtimeLoaded = true
	s.runtimeUpdated = now
	s.runtimeError = ""
	s.runtimeWarnings = append([]string{}, warnings...)
	s.generation++
	s.restartSyncLocked(rs)

	return s.runtimeStateLocked(), nil
}

func compiledEqual(a, b rules.Compiled) bool {
	if len(a.PIDPolicies) != len(b.PIDPolicies) || len(a.CommPolicies) != len(b.CommPolicies) {
		return false
	}

	for pid, policy := range a.PIDPolicies {
		if other, ok := b.PIDPolicies[pid]; !ok || other != policy {
			return false
		}
	}
	for key, policy := range a.CommPolicies {
		if other, ok := b.CommPolicies[key]; !ok || other != policy {
			return false
		}
	}

	return true
}

func ParseScope(value string) (Scope, error) {
	switch Scope(value) {
	case ScopePermanent:
		return ScopePermanent, nil
	case ScopeRuntime:
		return ScopeRuntime, nil
	default:
		return "", fmt.Errorf("unsupported scope %q", value)
	}
}
