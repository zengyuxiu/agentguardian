package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/zengyuxiu/agentguardian/config"
	bpf "github.com/zengyuxiu/agentguardian/internal/ebpf"

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

	if err := config.Apply(runtime.PolicyMap(), runtime.CommPolicyMap(), cfg); err != nil {
		log.Fatalf("installing policies: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-stopper
		cancel()
		_ = runtime.StopReading()
	}()

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
