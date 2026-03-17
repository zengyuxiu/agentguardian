package ebpf

//go:generate ./generate.sh
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags "$BPF_CFLAGS" -type event -type policy -type comm_key agentguardian agentguardian.bpf.c -- -I.
