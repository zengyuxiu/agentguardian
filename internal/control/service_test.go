package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zengyuxiu/agentguardian/internal/rules"
)

type fakeApplier struct {
	applied []rules.Compiled
	err     error
}

func (f *fakeApplier) ApplyCompiled(compiled rules.Compiled) error {
	if f.err != nil {
		return f.err
	}
	f.applied = append(f.applied, compiled)
	return nil
}

func TestServiceReloadLoadsPermanentIntoRuntime(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	rulesDir := filepath.Join(configDir, "rules.d")
	if err := writeRuleFile(filepath.Join(rulesDir, "010-rule.yaml"), `
id: hide-cat
match:
  path: /tmp/secret
  comm: cat
action:
  type: hide
`); err != nil {
		t.Fatalf("write rule file: %v", err)
	}

	applier := &fakeApplier{}
	service := NewService(configDir, filepath.Join(configDir, "agentguardd.sock"), 10*time.Millisecond, applier)
	if err := service.EnsureLayout(); err != nil {
		t.Fatalf("EnsureLayout() error = %v", err)
	}
	defer service.Close()

	resp, err := service.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	if len(applier.applied) != 1 {
		t.Fatalf("ApplyCompiled() count = %d, want 1", len(applier.applied))
	}
	if !resp.Runtime.Loaded || !resp.Runtime.Valid {
		t.Fatalf("runtime state = %+v, want loaded+valid", resp.Runtime)
	}
	if resp.Runtime.Generation != 1 {
		t.Fatalf("runtime generation = %d, want 1", resp.Runtime.Generation)
	}
	if resp.Permanent.RuleCount != 1 {
		t.Fatalf("permanent rule count = %d, want 1", resp.Permanent.RuleCount)
	}
}

func TestServiceValidatePermanentReportsErrors(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	rulesDir := filepath.Join(configDir, "rules.d")
	if err := writeRuleFile(filepath.Join(rulesDir, "010-invalid.yaml"), `
id: bad
match:
  path: /tmp/secret
  comm: cat
action:
  type: rewrite
  find: short
  replace: longer
`); err != nil {
		t.Fatalf("write rule file: %v", err)
	}

	service := NewService(configDir, filepath.Join(configDir, "agentguardd.sock"), 10*time.Millisecond, &fakeApplier{})
	if err := service.EnsureLayout(); err != nil {
		t.Fatalf("EnsureLayout() error = %v", err)
	}
	defer service.Close()

	resp := service.Validate(ScopePermanent)
	if resp.State.Valid {
		t.Fatalf("Validate() state = %+v, want invalid", resp.State)
	}
	if !strings.Contains(resp.State.Error, "same length") {
		t.Fatalf("Validate() error = %q, want rewrite length error", resp.State.Error)
	}
}

func TestServiceStatusSeparatesRuntimeAndPermanent(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	service := NewService(configDir, filepath.Join(configDir, "agentguardd.sock"), 10*time.Millisecond, &fakeApplier{})
	if err := service.EnsureLayout(); err != nil {
		t.Fatalf("EnsureLayout() error = %v", err)
	}
	defer service.Close()

	status := service.Status()
	if status.Permanent.Path != filepath.Join(configDir, "rules.d") {
		t.Fatalf("permanent path = %q, want %q", status.Permanent.Path, filepath.Join(configDir, "rules.d"))
	}
	if status.Runtime.Loaded {
		t.Fatalf("runtime loaded = %v, want false", status.Runtime.Loaded)
	}
	if !status.Permanent.Valid {
		t.Fatalf("permanent valid = %v, want true for empty rules.d", status.Permanent.Valid)
	}
}

func writeRuleFile(path string, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimLeft(body, "\n")), 0o644)
}
