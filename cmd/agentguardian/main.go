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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-stopper
		cancel()
		_ = runtime.StopReading()
	}()

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
			"AgentGuardian active: rules=%q version=%d rule-count=%d pid-policies=%d comm-policies=%d",
			cfg.RulesPath,
			rs.Version,
			len(rs.Rules),
			len(compiled.PIDPolicies),
			len(compiled.CommPolicies),
		)
	} else {
		if err := config.Apply(runtime.PolicyMap(), runtime.CommPolicyMap(), cfg); err != nil {
			log.Fatalf("installing policies: %v", err)
		}

		go config.SyncExecutablePolicies(ctx, runtime.PolicyMap(), cfg)

		log.Printf(
			"AgentGuardian active: path=%q rewrite-pid=%d hide-pid=%d rewrite-comm=%q hide-comm=%q rewrite-exe=%q hide-exe=%q find=%q replace=%q",
			cfg.TargetPath,
			cfg.EffectiveRewritePID(),
			cfg.HidePID,
			cfg.RewriteComms,
			cfg.HideComms,
			cfg.RewriteExes,
			cfg.HideExes,
			cfg.FindText,
			cfg.ReplaceText,
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
			"op=%s action=%s pid=%d tid=%d ret=%d comm=%s path=%s",
			bpf.OpName(event.Op),
			bpf.ActionName(event.Action),
			event.Pid,
			event.Tid,
			event.Ret,
			bpf.Int8SliceToString(event.Comm[:]),
			bpf.Int8SliceToString(event.Path[:]),
		)
	}
}
