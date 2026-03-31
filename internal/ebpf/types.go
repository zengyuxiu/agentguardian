package ebpf

const (
	ActionPass    = 0
	ActionAudit   = 1
	ActionHide    = 2
	ActionRewrite = 3

	OpOpen    = 1
	OpBlock   = 2
	OpRewrite = 3
	OpExec    = 4
	OpSyscall = 5

	MaxPathLen = 64
	MaxTextLen = 64
	MaxCommLen = 16
)

type Event = agentguardianEvent
type Policy = agentguardianPolicy
type CommKey = agentguardianCommKey
type SyscallRule = agentguardianSyscallRule
type SyscallPIDKey = agentguardianSyscallPidKey
type SyscallCommKey = agentguardianSyscallCommKey

func NewPolicy(action uint8, path string, find string, replace string) Policy {
	var policy Policy

	policy.Action = action
	copyStringToInt8(policy.TargetPath[:], path)
	copyStringToInt8(policy.Find[:], find)
	copyStringToInt8(policy.Replace[:], replace)

	textLen := len(find)
	if textLen > len(policy.Find) {
		textLen = len(policy.Find)
	}
	if textLen > len(policy.Replace) {
		textLen = len(policy.Replace)
	}
	policy.TextLen = uint32(textLen)

	return policy
}

func NewCommKey(comm string) CommKey {
	var key CommKey
	copyStringToInt8(key.Comm[:], comm)
	return key
}

func NewSyscallPIDKey(pid uint32, syscallNR uint32) SyscallPIDKey {
	return SyscallPIDKey{
		Pid:       pid,
		SyscallNr: syscallNR,
	}
}

func NewSyscallCommKey(comm string, syscallNR uint32) SyscallCommKey {
	var key SyscallCommKey
	copyStringToInt8(key.Comm[:], comm)
	key.SyscallNr = syscallNR
	return key
}

func ActionName(action uint32) string {
	switch action {
	case ActionAudit:
		return "audit"
	case ActionHide:
		return "hide"
	case ActionRewrite:
		return "rewrite"
	default:
		return "pass"
	}
}

func OpName(op uint32) string {
	switch op {
	case OpOpen:
		return "open"
	case OpBlock:
		return "block"
	case OpRewrite:
		return "rewrite"
	case OpExec:
		return "exec"
	case OpSyscall:
		return "syscall"
	default:
		return "unknown"
	}
}

func Int8SliceToString(src []int8) string {
	end := 0
	for end < len(src) && src[end] != 0 {
		end++
	}

	buf := make([]byte, end)
	for i := 0; i < end; i++ {
		buf[i] = byte(src[i])
	}

	return string(buf)
}

func copyStringToInt8(dst []int8, src string) {
	limit := len(dst)
	if limit == 0 {
		return
	}

	if len(src) >= limit {
		limit--
	} else {
		limit = len(src)
	}

	for i := 0; i < limit; i++ {
		dst[i] = int8(src[i])
	}
}
