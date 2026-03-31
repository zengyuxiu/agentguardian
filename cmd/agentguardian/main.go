package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zengyuxiu/agentguardian/config"
	bpf "github.com/zengyuxiu/agentguardian/internal/ebpf"
	"github.com/zengyuxiu/agentguardian/internal/rules"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	cfg, err := config.ParseFlags(os.Args[1:], uint(os.Getpid()))
	if err != nil {
		log.Fatal(err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		if !errors.Is(err, syscall.EPERM) {
			log.Fatal(err)
		}
		log.Printf("warning: unable to raise memlock rlimit, continuing: %v", err)
	}

	runtime, err := bpf.Load()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			log.Printf("closing runtime: %v", err)
		}
	}()

	securityProfile := bpf.DefaultSecurityProfile()
	if err := bpf.ApplySecurityProfile(runtime.SyscallRulesMap(), runtime.SyscallPIDRulesMap(), runtime.SyscallCommRulesMap(), runtime.ExecPolicyMap(), securityProfile); err != nil {
		log.Fatalf("installing security profile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-stopper
		cancel()
		_ = runtime.StopReading()
	}()

	go bpf.SyncSecurityProfile(
		ctx,
		runtime.SyscallRulesMap(),
		runtime.SyscallPIDRulesMap(),
		runtime.SyscallCommRulesMap(),
		runtime.ExecPolicyMap(),
		securityProfile,
		500*time.Millisecond,
	)

	if cfg.RulesPath != "" {
		rs, err := rules.LoadPath(cfg.RulesPath)
		if err != nil {
			log.Fatalf("loading ruleset: %v", err)
		}

		compiled, err := rules.Compile(rs, rules.CompileOptions{})
		if err != nil {
			log.Fatalf("compiling ruleset: %v", err)
		}
		if err := rules.ApplyCompiled(runtime.PolicyMap(), runtime.CommPolicyMap(), compiled); err != nil {
			log.Fatalf("installing compiled ruleset: %v", err)
		}

		go rules.SyncCompiledPolicies(ctx, runtime.PolicyMap(), runtime.CommPolicyMap(), rs, 500*time.Millisecond)

		log.Printf(
			"AgentGuardian active: rules=%q version=%d rule-count=%d pid-policies=%d comm-policies=%d exec-mode=%d syscall-rules=%d",
			cfg.RulesPath,
			rs.Version,
			len(rs.Rules),
			len(compiled.PIDPolicies),
			len(compiled.CommPolicies),
			securityProfile.ExecMode,
			len(securityProfile.Syscalls),
		)
	} else {
		if err := config.Apply(runtime.PolicyMap(), runtime.CommPolicyMap(), cfg); err != nil {
			log.Fatalf("installing policies: %v", err)
		}

		go config.SyncExecutablePolicies(ctx, runtime.PolicyMap(), cfg)

		log.Printf(
			"AgentGuardian active: path=%q rewrite-pid=%d hide-pid=%d rewrite-comm=%q hide-comm=%q rewrite-exe=%q hide-exe=%q find=%q replace=%q exec-mode=%d syscall-rules=%d",
			cfg.TargetPath,
			cfg.EffectiveRewritePID(),
			cfg.HidePID,
			cfg.RewriteComms,
			cfg.HideComms,
			cfg.RewriteExes,
			cfg.HideExes,
			cfg.FindText,
			cfg.ReplaceText,
			securityProfile.ExecMode,
			len(securityProfile.Syscalls),
		)
	}

	for {
		event, err := runtime.ReadEvent()
		if err != nil {
			if bpf.IsClosed(err) {
				return
			}
			log.Printf("reading ringbuf: %v", err)
			continue
		}

		log.Printf(
			"op=%s action=%s pid=%d tid=%d ret=%d aux=%d comm=%s path=%s",
			bpf.OpName(event.Op),
			bpf.ActionName(event.Action),
			event.Pid,
			event.Tid,
			event.Ret,
			event.Aux,
			bpf.Int8SliceToString(event.Comm[:]),
			bpf.Int8SliceToString(event.Path[:]),
		)
		if event.Op == bpf.OpSyscall {
			log.Printf("syscall-rule matched: nr=%d name=%s pid=%d comm=%s", event.Aux, bpf.SyscallName(event.Aux), event.Pid, bpf.Int8SliceToString(event.Comm[:]))
		}
	}
}
