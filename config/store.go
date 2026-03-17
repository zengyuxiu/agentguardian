package config

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	agentebpf "github.com/zengyuxiu/agentguardian/internal/ebpf"

	cebpf "github.com/cilium/ebpf"
)

func Apply(policyMap *cebpf.Map, commPolicyMap *cebpf.Map, cfg Config) error {
	if cfg.RewriteRequested() {
		rewritePolicy, err := buildRewritePolicy(cfg)
		if err != nil {
			return err
		}

		if cfg.ShouldApplyRewritePID() {
			if err := policyMap.Put(uint32(cfg.RewritePID), rewritePolicy); err != nil {
				return err
			}
		}

		if err := applyCommPolicies(commPolicyMap, splitCommaList(cfg.RewriteComms), rewritePolicy); err != nil {
			return err
		}
	}

	if cfg.HidePID != 0 {
		hidePolicy := agentebpf.NewPolicy(agentebpf.ActionHide, cfg.TargetPath, "", "")
		if err := policyMap.Put(uint32(cfg.HidePID), hidePolicy); err != nil {
			return err
		}
	}

	hidePolicy := agentebpf.NewPolicy(agentebpf.ActionHide, cfg.TargetPath, "", "")
	if err := applyCommPolicies(commPolicyMap, splitCommaList(cfg.HideComms), hidePolicy); err != nil {
		return err
	}

	return nil
}

func SyncExecutablePolicies(ctx context.Context, policyMap *cebpf.Map, cfg Config) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	last := make(map[uint32]struct{})
	for {
		current, err := buildExecutablePolicies(cfg)
		if err != nil {
			log.Printf("building executable policies: %v", err)
		} else if err := reconcileExecutablePolicies(policyMap, current, last, cfg); err != nil {
			log.Printf("syncing executable policies: %v", err)
		} else {
			last = policyKeys(current)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func buildRewritePolicy(cfg Config) (agentebpf.Policy, error) {
	if cfg.FindText == "" {
		return agentebpf.Policy{}, errors.New("rewrite config requires -find")
	}
	if cfg.ReplaceText == "" {
		return agentebpf.Policy{}, errors.New("rewrite config requires -replace")
	}
	if len(cfg.FindText) != len(cfg.ReplaceText) {
		return agentebpf.Policy{}, errors.New("-find and -replace must have the same length")
	}

	return agentebpf.NewPolicy(agentebpf.ActionRewrite, cfg.TargetPath, cfg.FindText, cfg.ReplaceText), nil
}

func applyCommPolicies(m *cebpf.Map, comms []string, policy agentebpf.Policy) error {
	for _, comm := range comms {
		if err := m.Put(agentebpf.NewCommKey(comm), policy); err != nil {
			return err
		}
	}

	return nil
}

func buildExecutablePolicies(cfg Config) (map[uint32]agentebpf.Policy, error) {
	rewriteSet := buildPathSet(cfg.RewriteExes)
	hideSet := buildPathSet(cfg.HideExes)
	if len(rewriteSet) == 0 && len(hideSet) == 0 {
		return map[uint32]agentebpf.Policy{}, nil
	}

	var rewritePolicy agentebpf.Policy
	if len(rewriteSet) > 0 {
		var err error
		rewritePolicy, err = buildRewritePolicy(cfg)
		if err != nil {
			return nil, err
		}
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	policies := make(map[uint32]agentebpf.Policy)
	for _, entry := range entries {
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		exe, err := os.Readlink("/proc/" + entry.Name() + "/exe")
		if err != nil {
			continue
		}

		exe = canonicalizePath(exe)
		pid := uint32(pid64)

		if _, ok := rewriteSet[exe]; ok {
			policies[pid] = rewritePolicy
		}
		if _, ok := hideSet[exe]; ok {
			policies[pid] = agentebpf.NewPolicy(agentebpf.ActionHide, cfg.TargetPath, "", "")
		}
	}

	return policies, nil
}

func reconcileExecutablePolicies(m *cebpf.Map, current map[uint32]agentebpf.Policy, last map[uint32]struct{}, cfg Config) error {
	for pid, policy := range current {
		if err := m.Put(pid, policy); err != nil {
			return err
		}
	}

	for pid := range last {
		if _, ok := current[pid]; ok || isStaticPID(cfg, pid) {
			continue
		}
		if err := m.Delete(pid); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
			return err
		}
	}

	return nil
}

func policyKeys(policies map[uint32]agentebpf.Policy) map[uint32]struct{} {
	keys := make(map[uint32]struct{}, len(policies))
	for pid := range policies {
		keys[pid] = struct{}{}
	}
	return keys
}

func isStaticPID(cfg Config, pid uint32) bool {
	return uint32(cfg.EffectiveRewritePID()) == pid || uint32(cfg.HidePID) == pid
}

func buildPathSet(value string) map[string]struct{} {
	items := splitCommaList(value)
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		out[canonicalizePath(item)] = struct{}{}
	}
	return out
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

func splitCommaList(value string) []string {
	if value == "" {
		return nil
	}

	raw := strings.Split(value, ",")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, item)
	}

	return out
}
