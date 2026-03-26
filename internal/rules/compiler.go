package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	agentebpf "github.com/zengyuxiu/agentguardian/internal/ebpf"

	cebpf "github.com/cilium/ebpf"
)

type ProcessInfo struct {
	PID uint32
	Exe string
}

type CompileOptions struct {
	Processes []ProcessInfo
}

type Compiled struct {
	PIDPolicies  map[uint32]agentebpf.Policy
	CommPolicies map[agentebpf.CommKey]agentebpf.Policy
}

type CompileReport struct {
	Warnings []string
}

type compiledCandidate struct {
	policy      agentebpf.Policy
	rule        Rule
	specificity int
}

const (
	selectorComm = 1
	selectorExe  = 2
	selectorPID  = 3
)

func Compile(rs Ruleset, opts CompileOptions) (Compiled, error) {
	compiled, _, err := CompileWithReport(rs, opts)
	return compiled, err
}

func CompileWithReport(rs Ruleset, opts CompileOptions) (Compiled, CompileReport, error) {
	rs = rs.Normalized()
	validationReport, err := ValidateRulesetReport(rs)
	if err != nil {
		return Compiled{}, CompileReport{Warnings: validationReport.Warnings}, err
	}

	processes := opts.Processes
	if needsProcessScan(rs) && processes == nil {
		var err error
		processes, err = listProcessesFromProc()
		if err != nil {
			return Compiled{}, CompileReport{Warnings: validationReport.Warnings}, fmt.Errorf("list processes: %w", err)
		}
	}

	out := Compiled{
		PIDPolicies:  make(map[uint32]agentebpf.Policy),
		CommPolicies: make(map[agentebpf.CommKey]agentebpf.Policy),
	}
	report := CompileReport{
		Warnings: append([]string{}, validationReport.Warnings...),
	}

	pidCandidates := make(map[uint32]compiledCandidate)
	commCandidates := make(map[agentebpf.CommKey]compiledCandidate)
	for _, rule := range rs.Rules {
		if !rule.Enabled {
			continue
		}

		policy, err := buildPolicy(rule)
		if err != nil {
			return Compiled{}, report, err
		}

		switch {
		case rule.Match.PID != nil:
			pid := *rule.Match.PID
			candidate := compiledCandidate{
				policy:      policy,
				rule:        rule,
				specificity: selectorPID,
			}
			if current, ok := pidCandidates[pid]; !ok || shouldReplace(current, candidate) {
				if ok {
					report.Warnings = append(report.Warnings, describeReplacementWarning(current.rule, candidate.rule, fmt.Sprintf("pid %d", pid)))
				}
				pidCandidates[pid] = candidate
			} else {
				report.Warnings = append(report.Warnings, describeReplacementWarning(candidate.rule, current.rule, fmt.Sprintf("pid %d", pid)))
			}
		case rule.Match.Comm != "":
			key := agentebpf.NewCommKey(rule.Match.Comm)
			candidate := compiledCandidate{
				policy:      policy,
				rule:        rule,
				specificity: selectorComm,
			}
			if current, ok := commCandidates[key]; !ok || shouldReplace(current, candidate) {
				if ok {
					report.Warnings = append(report.Warnings, describeReplacementWarning(current.rule, candidate.rule, fmt.Sprintf("comm %q", rule.Match.Comm)))
				}
				commCandidates[key] = candidate
			} else {
				report.Warnings = append(report.Warnings, describeReplacementWarning(candidate.rule, current.rule, fmt.Sprintf("comm %q", rule.Match.Comm)))
			}
		case rule.Match.Exe != "":
			targetExe := canonicalizePath(rule.Match.Exe)
			candidate := compiledCandidate{
				policy:      policy,
				rule:        rule,
				specificity: selectorExe,
			}
			matched := 0
			for _, process := range processes {
				if canonicalizePath(process.Exe) != targetExe {
					continue
				}
				matched++
				if current, ok := pidCandidates[process.PID]; !ok || shouldReplace(current, candidate) {
					if ok {
						report.Warnings = append(report.Warnings, describeReplacementWarning(current.rule, candidate.rule, fmt.Sprintf("pid %d from exe %q", process.PID, rule.Match.Exe)))
					}
					pidCandidates[process.PID] = candidate
				} else {
					report.Warnings = append(report.Warnings, describeReplacementWarning(candidate.rule, current.rule, fmt.Sprintf("pid %d from exe %q", process.PID, rule.Match.Exe)))
				}
			}
			if matched == 0 {
				report.Warnings = append(report.Warnings, fmt.Sprintf("rule %q: match.exe %q matched no running processes during compilation", rule.ID, rule.Match.Exe))
			}
		default:
			return Compiled{}, report, fmt.Errorf("rule %q: compiler found no selector", rule.ID)
		}
	}

	for pid, candidate := range pidCandidates {
		out.PIDPolicies[pid] = candidate.policy
	}
	for key, candidate := range commCandidates {
		out.CommPolicies[key] = candidate.policy
	}

	report.Warnings = dedupeStrings(report.Warnings)
	return out, report, nil
}

func ApplyCompiled(policyMap, commPolicyMap *cebpf.Map, compiled Compiled) error {
	if err := replacePIDPolicies(policyMap, compiled.PIDPolicies); err != nil {
		return err
	}
	if err := replaceCommPolicies(commPolicyMap, compiled.CommPolicies); err != nil {
		return err
	}
	return nil
}

func buildPolicy(rule Rule) (agentebpf.Policy, error) {
	switch rule.Action.Type {
	case ActionHide:
		return agentebpf.NewPolicy(agentebpf.ActionHide, rule.Match.Path, "", ""), nil
	case ActionRewrite:
		if rule.Action.Find == "" {
			return agentebpf.Policy{}, fmt.Errorf("rule %q: rewrite action requires action.find", rule.ID)
		}
		if rule.Action.Replace == "" {
			return agentebpf.Policy{}, fmt.Errorf("rule %q: rewrite action requires action.replace", rule.ID)
		}
		if len(rule.Action.Find) != len(rule.Action.Replace) {
			return agentebpf.Policy{}, fmt.Errorf("rule %q: action.find and action.replace must have the same length", rule.ID)
		}
		return agentebpf.NewPolicy(agentebpf.ActionRewrite, rule.Match.Path, rule.Action.Find, rule.Action.Replace), nil
	default:
		return agentebpf.Policy{}, fmt.Errorf("rule %q: unsupported action type %q", rule.ID, rule.Action.Type)
	}
}

func shouldReplace(current, next compiledCandidate) bool {
	if next.specificity != current.specificity {
		return next.specificity > current.specificity
	}
	if next.rule.Priority != current.rule.Priority {
		return next.rule.Priority < current.rule.Priority
	}
	if next.rule.Action.Type != current.rule.Action.Type {
		return next.rule.Action.Type == ActionHide
	}
	return next.rule.ID < current.rule.ID
}

func needsProcessScan(rs Ruleset) bool {
	for _, rule := range rs.Rules {
		if rule.Enabled && rule.Match.Exe != "" {
			return true
		}
	}
	return false
}

func NeedsProcessScan(rs Ruleset) bool {
	return needsProcessScan(rs)
}

func replacePIDPolicies(m *cebpf.Map, policies map[uint32]agentebpf.Policy) error {
	existing, err := collectPIDKeys(m)
	if err != nil {
		return err
	}

	for pid, policy := range policies {
		if err := m.Put(pid, policy); err != nil {
			return err
		}
	}

	for pid := range existing {
		if _, ok := policies[pid]; ok {
			continue
		}
		if err := m.Delete(pid); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
			return err
		}
	}

	return nil
}

func replaceCommPolicies(m *cebpf.Map, policies map[agentebpf.CommKey]agentebpf.Policy) error {
	existing, err := collectCommKeys(m)
	if err != nil {
		return err
	}

	for key, policy := range policies {
		if err := m.Put(key, policy); err != nil {
			return err
		}
	}

	for key := range existing {
		if _, ok := policies[key]; ok {
			continue
		}
		if err := m.Delete(key); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
			return err
		}
	}

	return nil
}

func collectPIDKeys(m *cebpf.Map) (map[uint32]struct{}, error) {
	iter := m.Iterate()
	out := make(map[uint32]struct{})

	var (
		key   uint32
		value agentebpf.Policy
	)
	for iter.Next(&key, &value) {
		out[key] = struct{}{}
	}

	return out, iter.Err()
}

func collectCommKeys(m *cebpf.Map) (map[agentebpf.CommKey]struct{}, error) {
	iter := m.Iterate()
	out := make(map[agentebpf.CommKey]struct{})

	var (
		key   agentebpf.CommKey
		value agentebpf.Policy
	)
	for iter.Next(&key, &value) {
		out[key] = struct{}{}
	}

	return out, iter.Err()
}

func listProcessesFromProc() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	processes := make([]ProcessInfo, 0, len(entries))
	for _, entry := range entries {
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		exe, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}

		processes = append(processes, ProcessInfo{
			PID: uint32(pid64),
			Exe: exe,
		})
	}

	sort.Slice(processes, func(i, j int) bool {
		if processes[i].PID != processes[j].PID {
			return processes[i].PID < processes[j].PID
		}
		return processes[i].Exe < processes[j].Exe
	})

	return processes, nil
}

func canonicalizePath(path string) string {
	if path == "" {
		return ""
	}

	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved
	}
	return path
}

func describeReplacementWarning(discarded Rule, kept Rule, target string) string {
	return fmt.Sprintf("rule %q is shadowed by rule %q for %s", discarded.ID, kept.ID, target)
}
