package ebpf

import "testing"

func TestDefaultSecurityProfileIncludesExpectedRules(t *testing.T) {
	profile := DefaultSecurityProfile()

	if profile.ExecMode != EnforceAudit {
		t.Fatalf("ExecMode = %d, want %d", profile.ExecMode, EnforceAudit)
	}

	required := map[string]bool{
		"bpf":               false,
		"ptrace":            false,
		"process_vm_readv":  false,
		"process_vm_writev": false,
		"perf_event_open":   false,
		"init_module":       false,
		"mount":             false,
		"setns":             false,
		"unshare":           false,
		"io_uring_setup":    false,
	}

	for _, rule := range profile.Syscalls {
		if _, ok := required[rule.Name]; ok {
			required[rule.Name] = true
		}
		if rule.Mode != EnforceAudit {
			t.Fatalf("rule %q mode = %d, want %d", rule.Name, rule.Mode, EnforceAudit)
		}
	}

	for name, found := range required {
		if !found {
			t.Fatalf("required syscall rule %q missing", name)
		}
	}
}

func TestCompileSecurityProfileBuildsScopedRules(t *testing.T) {
	pid := uint32(1234)
	profile := SecurityProfile{
		ExecMode: EnforceAudit,
		Syscalls: []NamedSyscallRule{
			{
				Name:      "ptrace",
				SyscallNR: 101,
				Mode:      EnforceAudit,
				Scope: SyscallScope{
					PID: &pid,
				},
			},
			{
				Name:      "bpf",
				SyscallNR: 321,
				Mode:      EnforceDeny,
				Scope: SyscallScope{
					Comm: "bash",
				},
			},
			{
				Name:      "mount",
				SyscallNR: 165,
				Mode:      EnforceAudit,
			},
		},
	}

	compiled, err := compileSecurityProfile(profile)
	if err != nil {
		t.Fatalf("compileSecurityProfile() error = %v", err)
	}

	if len(compiled.globalRules) != 1 {
		t.Fatalf("globalRules len = %d, want 1", len(compiled.globalRules))
	}
	if len(compiled.pidRules) != 1 {
		t.Fatalf("pidRules len = %d, want 1", len(compiled.pidRules))
	}
	if len(compiled.commRules) != 1 {
		t.Fatalf("commRules len = %d, want 1", len(compiled.commRules))
	}
	if compiled.pidRules[0].PID != pid {
		t.Fatalf("pidRules[0].PID = %d, want %d", compiled.pidRules[0].PID, pid)
	}
	if compiled.commRules[0].Comm != "bash" {
		t.Fatalf("commRules[0].Comm = %q, want %q", compiled.commRules[0].Comm, "bash")
	}
}
