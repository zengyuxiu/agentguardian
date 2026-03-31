package ebpf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	cebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	EnforceAllow = 0
	EnforceAudit = 1
	EnforceDeny  = 2
)

type SyscallScope struct {
	PID  *uint32
	Comm string
	Exe  string
}

type NamedSyscallRule struct {
	Name      string
	SyscallNR uint32
	Mode      uint32
	Scope     SyscallScope
}

type SecurityProfile struct {
	ExecMode uint32
	Syscalls []NamedSyscallRule
}

type compiledSecurityProfile struct {
	globalRules []NamedSyscallRule
	pidRules    []compiledScopedSyscallRule
	commRules   []compiledScopedSyscallRule
}

type compiledScopedSyscallRule struct {
	Name      string
	SyscallNR uint32
	Mode      uint32
	PID       uint32
	Comm      string
}

type processInfo struct {
	pid uint32
	exe string
}

func SetExecMode(m *cebpf.Map, mode uint32) error {
	if m == nil {
		return fmt.Errorf("exec policy map is nil")
	}

	key := uint32(0)
	return m.Put(key, mode)
}

func PutSyscallRule(m *cebpf.Map, syscallNR uint32, mode uint32) error {
	if m == nil {
		return fmt.Errorf("syscall rules map is nil")
	}

	rule := SyscallRule{
		SyscallNr: syscallNR,
		Mode:      mode,
	}
	return m.Put(syscallNR, rule)
}

func PutScopedSyscallPIDRule(m *cebpf.Map, pid uint32, syscallNR uint32, mode uint32) error {
	if m == nil {
		return fmt.Errorf("syscall pid rules map is nil")
	}

	key := NewSyscallPIDKey(pid, syscallNR)
	rule := SyscallRule{
		SyscallNr: syscallNR,
		Mode:      mode,
	}
	return m.Put(key, rule)
}

func PutScopedSyscallCommRule(m *cebpf.Map, comm string, syscallNR uint32, mode uint32) error {
	if m == nil {
		return fmt.Errorf("syscall comm rules map is nil")
	}

	key := NewSyscallCommKey(comm, syscallNR)
	rule := SyscallRule{
		SyscallNr: syscallNR,
		Mode:      mode,
	}
	return m.Put(key, rule)
}

func DeleteSyscallRule(m *cebpf.Map, syscallNR uint32) error {
	if m == nil {
		return fmt.Errorf("syscall rules map is nil")
	}

	return m.Delete(syscallNR)
}

func ReplaceSyscallRules(m *cebpf.Map, rules []NamedSyscallRule) error {
	if m == nil {
		return fmt.Errorf("syscall rules map is nil")
	}

	current, err := collectSyscallRuleKeys(m)
	if err != nil {
		return err
	}

	next := make(map[uint32]struct{}, len(rules))
	for _, rule := range rules {
		if err := PutSyscallRule(m, rule.SyscallNR, rule.Mode); err != nil {
			return err
		}
		next[rule.SyscallNR] = struct{}{}
	}

	for syscallNR := range current {
		if _, ok := next[syscallNR]; ok {
			continue
		}
		if err := DeleteSyscallRule(m, syscallNR); err != nil {
			return err
		}
	}

	return nil
}

func ReplaceScopedSyscallPIDRules(m *cebpf.Map, rules []compiledScopedSyscallRule) error {
	if m == nil {
		return fmt.Errorf("syscall pid rules map is nil")
	}

	current, err := collectSyscallPIDRuleKeys(m)
	if err != nil {
		return err
	}

	next := make(map[SyscallPIDKey]struct{}, len(rules))
	for _, rule := range rules {
		if err := PutScopedSyscallPIDRule(m, rule.PID, rule.SyscallNR, rule.Mode); err != nil {
			return err
		}
		next[NewSyscallPIDKey(rule.PID, rule.SyscallNR)] = struct{}{}
	}

	for key := range current {
		if _, ok := next[key]; ok {
			continue
		}
		if err := m.Delete(key); err != nil {
			return err
		}
	}

	return nil
}

func ReplaceScopedSyscallCommRules(m *cebpf.Map, rules []compiledScopedSyscallRule) error {
	if m == nil {
		return fmt.Errorf("syscall comm rules map is nil")
	}

	current, err := collectSyscallCommRuleKeys(m)
	if err != nil {
		return err
	}

	next := make(map[SyscallCommKey]struct{}, len(rules))
	for _, rule := range rules {
		if err := PutScopedSyscallCommRule(m, rule.Comm, rule.SyscallNR, rule.Mode); err != nil {
			return err
		}
		next[NewSyscallCommKey(rule.Comm, rule.SyscallNR)] = struct{}{}
	}

	for key := range current {
		if _, ok := next[key]; ok {
			continue
		}
		if err := m.Delete(key); err != nil {
			return err
		}
	}

	return nil
}

func ApplySecurityProfile(globalMap, pidMap, commMap, execPolicyMap *cebpf.Map, profile SecurityProfile) error {
	compiled, err := compileSecurityProfile(profile)
	if err != nil {
		return err
	}

	if err := ReplaceSyscallRules(globalMap, compiled.globalRules); err != nil {
		return err
	}
	if err := ReplaceScopedSyscallPIDRules(pidMap, compiled.pidRules); err != nil {
		return err
	}
	if err := ReplaceScopedSyscallCommRules(commMap, compiled.commRules); err != nil {
		return err
	}
	return SetExecMode(execPolicyMap, profile.ExecMode)
}

func SyncSecurityProfile(ctx context.Context, globalMap, pidMap, commMap, execPolicyMap *cebpf.Map, profile SecurityProfile, interval time.Duration) {
	if !profile.NeedsProcessScan() {
		<-ctx.Done()
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if err := ApplySecurityProfile(globalMap, pidMap, commMap, execPolicyMap, profile); err != nil {
			continue
		}
	}
}

func (p SecurityProfile) NeedsProcessScan() bool {
	for _, rule := range p.Syscalls {
		if rule.Scope.Exe != "" {
			return true
		}
	}
	return false
}

func DefaultSecurityProfile() SecurityProfile {
	return SecurityProfile{
		ExecMode: EnforceAudit,
		Syscalls: []NamedSyscallRule{
			dangerousSyscall("bpf", unix.SYS_BPF, EnforceAudit),
			dangerousSyscall("ptrace", unix.SYS_PTRACE, EnforceAudit),
			dangerousSyscall("process_vm_readv", unix.SYS_PROCESS_VM_READV, EnforceAudit),
			dangerousSyscall("process_vm_writev", unix.SYS_PROCESS_VM_WRITEV, EnforceAudit),
			dangerousSyscall("perf_event_open", unix.SYS_PERF_EVENT_OPEN, EnforceAudit),
			dangerousSyscall("open_by_handle_at", unix.SYS_OPEN_BY_HANDLE_AT, EnforceAudit),
			dangerousSyscall("name_to_handle_at", unix.SYS_NAME_TO_HANDLE_AT, EnforceAudit),
			dangerousSyscall("init_module", unix.SYS_INIT_MODULE, EnforceAudit),
			dangerousSyscall("finit_module", unix.SYS_FINIT_MODULE, EnforceAudit),
			dangerousSyscall("delete_module", unix.SYS_DELETE_MODULE, EnforceAudit),
			dangerousSyscall("kexec_load", unix.SYS_KEXEC_LOAD, EnforceAudit),
			dangerousSyscall("mount", unix.SYS_MOUNT, EnforceAudit),
			dangerousSyscall("umount2", unix.SYS_UMOUNT2, EnforceAudit),
			dangerousSyscall("pivot_root", unix.SYS_PIVOT_ROOT, EnforceAudit),
			dangerousSyscall("open_tree", unix.SYS_OPEN_TREE, EnforceAudit),
			dangerousSyscall("move_mount", unix.SYS_MOVE_MOUNT, EnforceAudit),
			dangerousSyscall("fsopen", unix.SYS_FSOPEN, EnforceAudit),
			dangerousSyscall("fsconfig", unix.SYS_FSCONFIG, EnforceAudit),
			dangerousSyscall("fsmount", unix.SYS_FSMOUNT, EnforceAudit),
			dangerousSyscall("fspick", unix.SYS_FSPICK, EnforceAudit),
			dangerousSyscall("setns", unix.SYS_SETNS, EnforceAudit),
			dangerousSyscall("unshare", unix.SYS_UNSHARE, EnforceAudit),
			dangerousSyscall("fanotify_init", unix.SYS_FANOTIFY_INIT, EnforceAudit),
			dangerousSyscall("fanotify_mark", unix.SYS_FANOTIFY_MARK, EnforceAudit),
			dangerousSyscall("swapon", unix.SYS_SWAPON, EnforceAudit),
			dangerousSyscall("swapoff", unix.SYS_SWAPOFF, EnforceAudit),
			dangerousSyscall("reboot", unix.SYS_REBOOT, EnforceAudit),
			dangerousSyscall("add_key", unix.SYS_ADD_KEY, EnforceAudit),
			dangerousSyscall("request_key", unix.SYS_REQUEST_KEY, EnforceAudit),
			dangerousSyscall("keyctl", unix.SYS_KEYCTL, EnforceAudit),
			dangerousSyscall("io_uring_setup", unix.SYS_IO_URING_SETUP, EnforceAudit),
		},
	}
}

func SyscallName(syscallNR uint32) string {
	if name, ok := syscallNames[syscallNR]; ok {
		return name
	}
	return fmt.Sprintf("syscall:%d", syscallNR)
}

func dangerousSyscall(name string, syscallNR uintptr, mode uint32) NamedSyscallRule {
	rule := NamedSyscallRule{
		Name:      name,
		SyscallNR: uint32(syscallNR),
		Mode:      mode,
	}
	syscallNames[rule.SyscallNR] = rule.Name
	return rule
}

func compileSecurityProfile(profile SecurityProfile) (compiledSecurityProfile, error) {
	processes, err := listProcesses()
	if err != nil {
		return compiledSecurityProfile{}, err
	}

	compiled := compiledSecurityProfile{
		globalRules: make([]NamedSyscallRule, 0, len(profile.Syscalls)),
	}
	for _, rule := range profile.Syscalls {
		switch {
		case rule.Scope.PID != nil:
			compiled.pidRules = append(compiled.pidRules, compiledScopedSyscallRule{
				Name:      rule.Name,
				SyscallNR: rule.SyscallNR,
				Mode:      rule.Mode,
				PID:       *rule.Scope.PID,
			})
		case rule.Scope.Comm != "":
			compiled.commRules = append(compiled.commRules, compiledScopedSyscallRule{
				Name:      rule.Name,
				SyscallNR: rule.SyscallNR,
				Mode:      rule.Mode,
				Comm:      rule.Scope.Comm,
			})
		case rule.Scope.Exe != "":
			targetExe := canonicalizePath(rule.Scope.Exe)
			for _, process := range processes {
				if canonicalizePath(process.exe) != targetExe {
					continue
				}
				compiled.pidRules = append(compiled.pidRules, compiledScopedSyscallRule{
					Name:      rule.Name,
					SyscallNR: rule.SyscallNR,
					Mode:      rule.Mode,
					PID:       process.pid,
				})
			}
		default:
			compiled.globalRules = append(compiled.globalRules, rule)
		}
	}

	return compiled, nil
}

func listProcesses() ([]processInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	processes := make([]processInfo, 0, len(entries))
	for _, entry := range entries {
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		exe, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}

		processes = append(processes, processInfo{
			pid: uint32(pid64),
			exe: exe,
		})
	}

	sort.Slice(processes, func(i, j int) bool {
		if processes[i].pid != processes[j].pid {
			return processes[i].pid < processes[j].pid
		}
		return processes[i].exe < processes[j].exe
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

func collectSyscallRuleKeys(m *cebpf.Map) (map[uint32]struct{}, error) {
	iter := m.Iterate()
	out := make(map[uint32]struct{})

	var (
		key   uint32
		value SyscallRule
	)
	for iter.Next(&key, &value) {
		out[key] = struct{}{}
	}

	return out, iter.Err()
}

func collectSyscallPIDRuleKeys(m *cebpf.Map) (map[SyscallPIDKey]struct{}, error) {
	iter := m.Iterate()
	out := make(map[SyscallPIDKey]struct{})

	var (
		key   SyscallPIDKey
		value SyscallRule
	)
	for iter.Next(&key, &value) {
		out[key] = struct{}{}
	}

	return out, iter.Err()
}

func collectSyscallCommRuleKeys(m *cebpf.Map) (map[SyscallCommKey]struct{}, error) {
	iter := m.Iterate()
	out := make(map[SyscallCommKey]struct{})

	var (
		key   SyscallCommKey
		value SyscallRule
	)
	for iter.Next(&key, &value) {
		out[key] = struct{}{}
	}

	return out, iter.Err()
}

var syscallNames = map[uint32]string{}
