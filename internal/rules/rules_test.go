package rules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	agentebpf "github.com/zengyuxiu/agentguardian/internal/ebpf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestLoadFileSingleRule(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rule.yaml")
	writeFile(t, path, `
id: rewrite-cat-token
match:
  path: /tmp/ag-test.txt
  comm: cat
action:
  type: rewrite
  find: secret
  replace: public
`)

	rs, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}

	if rs.Version != DefaultVersion {
		t.Fatalf("LoadFile() version = %d, want %d", rs.Version, DefaultVersion)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("LoadFile() rule count = %d, want 1", len(rs.Rules))
	}

	rule := rs.Rules[0]
	if !rule.Enabled {
		t.Fatal("LoadFile() should default enabled to true")
	}
	if rule.Source != path {
		t.Fatalf("LoadFile() source = %q, want %q", rule.Source, path)
	}
	if rule.Action.Type != ActionRewrite {
		t.Fatalf("LoadFile() action = %q, want %q", rule.Action.Type, ActionRewrite)
	}
}

func TestLoadFileRuleset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "ruleset.yaml")
	writeFile(t, path, `
version: 3
rules:
  - id: hide-claude-passwd
    enabled: false
    priority: 10
    match:
      path: /etc/passwd
      exe: /opt/claude/bin/claude
    action:
      type: hide
`)

	rs, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}

	if rs.Version != 3 {
		t.Fatalf("LoadFile() version = %d, want 3", rs.Version)
	}
	if got := rs.Rules[0].Enabled; got {
		t.Fatalf("LoadFile() enabled = %v, want false", got)
	}
}

func TestLoadDirMergesRulesInLexicalOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "100-second.yaml"), `
id: second
match:
  path: /tmp/second
  comm: cat
action:
  type: hide
`)
	writeFile(t, filepath.Join(dir, "010-first.yaml"), `
id: first
match:
  path: /tmp/first
  comm: cat
action:
  type: hide
`)
	writeFile(t, filepath.Join(dir, "README.txt"), `ignored`)

	rs, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}

	if len(rs.Rules) != 2 {
		t.Fatalf("LoadDir() rule count = %d, want 2", len(rs.Rules))
	}
	if rs.Rules[0].ID != "first" || rs.Rules[1].ID != "second" {
		t.Fatalf("LoadDir() order = [%s %s], want [first second]", rs.Rules[0].ID, rs.Rules[1].ID)
	}
}

func TestValidateRulesetRejectsInvalidRule(t *testing.T) {
	t.Parallel()

	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID: "bad",
				Match: MatchSpec{
					Path: "/tmp/x",
					Comm: "cat",
				},
				Action: ActionSpec{
					Type:    ActionRewrite,
					Find:    "a",
					Replace: "bb",
				},
			},
		},
	}

	err := ValidateRuleset(rs)
	if err == nil {
		t.Fatal("ValidateRuleset() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "must have the same length") {
		t.Fatalf("ValidateRuleset() error = %v, want length validation", err)
	}
}

func TestValidateRulesetRejectsMultipleSelectors(t *testing.T) {
	t.Parallel()

	pid := uint32(42)
	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID: "bad-selectors",
				Match: MatchSpec{
					Path: "/tmp/x",
					PID:  &pid,
					Comm: "cat",
				},
				Action: ActionSpec{
					Type: ActionHide,
				},
			},
		},
	}

	err := ValidateRuleset(rs)
	if err == nil {
		t.Fatal("ValidateRuleset() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "only one of match.pid, match.comm, or match.exe may be set") {
		t.Fatalf("ValidateRuleset() error = %v, want selector validation", err)
	}
}

func TestValidateRulesetRejectsRelativePath(t *testing.T) {
	t.Parallel()

	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID: "relative-path",
				Match: MatchSpec{
					Path: "tmp/x",
					Comm: "cat",
				},
				Action: ActionSpec{
					Type: ActionHide,
				},
			},
		},
	}

	err := ValidateRuleset(rs)
	if err == nil {
		t.Fatal("ValidateRuleset() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "must be an absolute path") {
		t.Fatalf("ValidateRuleset() error = %v, want absolute path validation", err)
	}
}

func TestValidateRulesetRejectsOversizedRewrite(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", agentebpf.MaxTextLen+1)
	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID: "oversized-rewrite",
				Match: MatchSpec{
					Path: "/tmp/x",
					Comm: "cat",
				},
				Action: ActionSpec{
					Type:    ActionRewrite,
					Find:    long,
					Replace: long,
				},
			},
		},
	}

	err := ValidateRuleset(rs)
	if err == nil {
		t.Fatal("ValidateRuleset() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "at most") {
		t.Fatalf("ValidateRuleset() error = %v, want max text length validation", err)
	}
}

func TestLoadDirRejectsDuplicateIDs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "010-a.yaml"), `
id: duplicate
match:
  path: /tmp/a
  comm: cat
action:
  type: hide
`)
	writeFile(t, filepath.Join(dir, "020-b.yaml"), `
id: duplicate
match:
  path: /tmp/b
  comm: less
action:
  type: hide
`)

	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("LoadDir() error = %v, want duplicate id error", err)
	}
}

func TestLoadDirAllowsEmptyRulesDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rs, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}

	if rs.Version != DefaultVersion {
		t.Fatalf("LoadDir() version = %d, want %d", rs.Version, DefaultVersion)
	}
	if len(rs.Rules) != 0 {
		t.Fatalf("LoadDir() rule count = %d, want 0", len(rs.Rules))
	}
}

func TestSaveDirRoundTripsRuleset(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "rules.d")
	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID: "hide-cat",
				Match: MatchSpec{
					Path: "/tmp/secret",
					Comm: "cat",
				},
				Action: ActionSpec{
					Type: ActionHide,
				},
			},
		},
	}

	if err := SaveDir(dir, rs); err != nil {
		t.Fatalf("SaveDir() error = %v", err)
	}

	savedPath := filepath.Join(dir, GeneratedRulesetFilename)
	if _, err := os.Stat(savedPath); err != nil {
		t.Fatalf("saved ruleset file stat error = %v", err)
	}

	loaded, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}
	if loaded.Version != rs.Version {
		t.Fatalf("LoadDir() version = %d, want %d", loaded.Version, rs.Version)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].ID != "hide-cat" {
		t.Fatalf("LoadDir() rules = %#v, want single saved rule", loaded.Rules)
	}
}

func TestSaveDirReplacesExistingYAMLFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "010-old.yaml"), `
id: old
match:
  path: /tmp/old
  comm: cat
action:
  type: hide
`)

	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID: "new",
				Match: MatchSpec{
					Path: "/tmp/new",
					Comm: "cat",
				},
				Action: ActionSpec{
					Type: ActionHide,
				},
			},
		},
	}

	if err := SaveDir(dir, rs); err != nil {
		t.Fatalf("SaveDir() error = %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != GeneratedRulesetFilename {
		t.Fatalf("rules.d entries = %#v, want only %q", entries, GeneratedRulesetFilename)
	}
}

func TestCompileCommRule(t *testing.T) {
	t.Parallel()

	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID:      "rewrite-cat-token",
				Enabled: true,
				Match: MatchSpec{
					Path: "/tmp/ag-test.txt",
					Comm: "cat",
				},
				Action: ActionSpec{
					Type:    ActionRewrite,
					Find:    "secret",
					Replace: "public",
				},
			},
		},
	}

	compiled, err := Compile(rs, CompileOptions{})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	if len(compiled.PIDPolicies) != 0 {
		t.Fatalf("Compile() pid policies = %d, want 0", len(compiled.PIDPolicies))
	}
	if len(compiled.CommPolicies) != 1 {
		t.Fatalf("Compile() comm policies = %d, want 1", len(compiled.CommPolicies))
	}

	policy, ok := compiled.CommPolicies[agentebpf.NewCommKey("cat")]
	if !ok {
		t.Fatal("Compile() missing comm policy for cat")
	}
	if policy.Action != agentebpf.ActionRewrite {
		t.Fatalf("Compile() action = %d, want %d", policy.Action, agentebpf.ActionRewrite)
	}
}

func TestCompilePIDRuleBeatsExeRule(t *testing.T) {
	t.Parallel()

	pid := uint32(200)
	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID:       "exe-hide",
				Enabled:  true,
				Priority: 1,
				Match: MatchSpec{
					Path: "/tmp/target",
					Exe:  "/usr/bin/cat",
				},
				Action: ActionSpec{
					Type: ActionHide,
				},
			},
			{
				ID:       "pid-rewrite",
				Enabled:  true,
				Priority: 100,
				Match: MatchSpec{
					Path: "/tmp/target",
					PID:  &pid,
				},
				Action: ActionSpec{
					Type:    ActionRewrite,
					Find:    "secret",
					Replace: "public",
				},
			},
		},
	}

	compiled, err := Compile(rs, CompileOptions{
		Processes: []ProcessInfo{
			{PID: pid, Exe: "/usr/bin/cat"},
		},
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	policy, ok := compiled.PIDPolicies[pid]
	if !ok {
		t.Fatalf("Compile() missing pid policy for %d", pid)
	}
	if policy.Action != agentebpf.ActionRewrite {
		t.Fatalf("Compile() action = %d, want %d", policy.Action, agentebpf.ActionRewrite)
	}
}

func TestCompileHideWinsWhenSpecificityAndPriorityMatch(t *testing.T) {
	t.Parallel()

	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID:       "rewrite-cat",
				Enabled:  true,
				Priority: 50,
				Match: MatchSpec{
					Path: "/tmp/target",
					Comm: "cat",
				},
				Action: ActionSpec{
					Type:    ActionRewrite,
					Find:    "secret",
					Replace: "public",
				},
			},
			{
				ID:       "hide-cat",
				Enabled:  true,
				Priority: 50,
				Match: MatchSpec{
					Path: "/tmp/target",
					Comm: "cat",
				},
				Action: ActionSpec{
					Type: ActionHide,
				},
			},
		},
	}

	compiled, err := Compile(rs, CompileOptions{})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	policy := compiled.CommPolicies[agentebpf.NewCommKey("cat")]
	if policy.Action != agentebpf.ActionHide {
		t.Fatalf("Compile() action = %d, want %d", policy.Action, agentebpf.ActionHide)
	}
}

func TestCompileWithReportWarnsWhenExeMatchesNoProcesses(t *testing.T) {
	t.Parallel()

	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID:      "exe-hide",
				Enabled: true,
				Match: MatchSpec{
					Path: "/tmp/target",
					Exe:  "/usr/bin/missing",
				},
				Action: ActionSpec{
					Type: ActionHide,
				},
			},
		},
	}

	compiled, report, err := CompileWithReport(rs, CompileOptions{Processes: []ProcessInfo{}})
	if err != nil {
		t.Fatalf("CompileWithReport() error = %v", err)
	}
	if len(compiled.PIDPolicies) != 0 {
		t.Fatalf("CompileWithReport() pid policies = %d, want 0", len(compiled.PIDPolicies))
	}
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "matched no running processes") {
		t.Fatalf("CompileWithReport() warnings = %#v, want exe no match warning", report.Warnings)
	}
}

func TestCompileWithReportWarnsWhenRuleIsShadowed(t *testing.T) {
	t.Parallel()

	rs := Ruleset{
		Version: DefaultVersion,
		Rules: []Rule{
			{
				ID:       "rewrite-cat",
				Enabled:  true,
				Priority: 50,
				Match: MatchSpec{
					Path: "/tmp/target",
					Comm: "cat",
				},
				Action: ActionSpec{
					Type:    ActionRewrite,
					Find:    "secret",
					Replace: "public",
				},
			},
			{
				ID:       "hide-cat",
				Enabled:  true,
				Priority: 50,
				Match: MatchSpec{
					Path: "/tmp/target",
					Comm: "cat",
				},
				Action: ActionSpec{
					Type: ActionHide,
				},
			},
		},
	}

	_, report, err := CompileWithReport(rs, CompileOptions{})
	if err != nil {
		t.Fatalf("CompileWithReport() error = %v", err)
	}
	if len(report.Warnings) == 0 {
		t.Fatal("CompileWithReport() warnings = nil, want shadow warning")
	}
	if !strings.Contains(report.Warnings[0], "shadowed") {
		t.Fatalf("CompileWithReport() warnings = %#v, want shadow warning", report.Warnings)
	}
}

func TestApplyCompiledReplacesExistingMapContents(t *testing.T) {
	t.Parallel()

	maybeRaiseMemlock(t)

	policyMap := newHashMap[uint32, agentebpf.Policy](t, 32)
	defer policyMap.Close()

	commMap := newHashMap[agentebpf.CommKey, agentebpf.Policy](t, 32)
	defer commMap.Close()

	if err := policyMap.Put(uint32(7), agentebpf.NewPolicy(agentebpf.ActionHide, "/tmp/old", "", "")); err != nil {
		t.Fatalf("seed policy map: %v", err)
	}
	if err := commMap.Put(agentebpf.NewCommKey("old"), agentebpf.NewPolicy(agentebpf.ActionHide, "/tmp/old", "", "")); err != nil {
		t.Fatalf("seed comm map: %v", err)
	}

	compiled := Compiled{
		PIDPolicies: map[uint32]agentebpf.Policy{
			42: agentebpf.NewPolicy(agentebpf.ActionRewrite, "/tmp/new", "secret", "public"),
		},
		CommPolicies: map[agentebpf.CommKey]agentebpf.Policy{
			agentebpf.NewCommKey("cat"): agentebpf.NewPolicy(agentebpf.ActionHide, "/tmp/new", "", ""),
		},
	}

	if err := ApplyCompiled(policyMap, commMap, compiled); err != nil {
		t.Fatalf("ApplyCompiled() error = %v", err)
	}

	var pidPolicy agentebpf.Policy
	if err := policyMap.Lookup(uint32(42), &pidPolicy); err != nil {
		t.Fatalf("lookup new pid policy: %v", err)
	}
	if pidPolicy.Action != agentebpf.ActionRewrite {
		t.Fatalf("pid policy action = %d, want %d", pidPolicy.Action, agentebpf.ActionRewrite)
	}
	if err := policyMap.Lookup(uint32(7), &pidPolicy); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("lookup old pid policy error = %v, want %v", err, ebpf.ErrKeyNotExist)
	}

	var commPolicy agentebpf.Policy
	if err := commMap.Lookup(agentebpf.NewCommKey("cat"), &commPolicy); err != nil {
		t.Fatalf("lookup new comm policy: %v", err)
	}
	if commPolicy.Action != agentebpf.ActionHide {
		t.Fatalf("comm policy action = %d, want %d", commPolicy.Action, agentebpf.ActionHide)
	}
	if err := commMap.Lookup(agentebpf.NewCommKey("old"), &commPolicy); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("lookup old comm policy error = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(strings.TrimLeft(content, "\n")), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func maybeRaiseMemlock(t *testing.T) {
	t.Helper()

	err := rlimit.RemoveMemlock()
	if err == nil || errors.Is(err, syscall.EPERM) {
		return
	}
	t.Fatalf("RemoveMemlock() error = %v", err)
}

func newHashMap[K comparable, V any](t *testing.T, maxEntries uint32) *ebpf.Map {
	t.Helper()

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(*new(K))),
		ValueSize:  uint32(unsafe.Sizeof(*new(V))),
		MaxEntries: maxEntries,
	})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "MEMLOCK") {
			t.Skipf("NewMap() unavailable in current environment: %v", err)
		}
		t.Fatalf("NewMap() error = %v", err)
	}
	return m
}
