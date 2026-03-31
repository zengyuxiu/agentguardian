package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zengyuxiu/agentguardian/internal/control"
	bpf "github.com/zengyuxiu/agentguardian/internal/ebpf"
	"github.com/zengyuxiu/agentguardian/internal/rules"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

type mapApplier struct {
	policyMap     *ebpf.Map
	commPolicyMap *ebpf.Map
}

func (a mapApplier) ApplyCompiled(compiled rules.Compiled) error {
	return rules.ApplyCompiled(a.policyMap, a.commPolicyMap, compiled)
}

func main() {
	var (
		configDir    = flag.String("config-dir", "/etc/agentguardian", "configuration directory containing rules.d")
		socketPath   = flag.String("socket", "/run/agentguardian/agentguardd.sock", "unix socket path for the control API")
		syncInterval = flag.Duration("sync-interval", 500*time.Millisecond, "interval for re-expanding executable rules into pid policies")
	)
	flag.Parse()

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

	securityProfile := bpf.DefaultSecurityProfile()
	if err := bpf.ApplySecurityProfile(runtime.SyscallRulesMap(), runtime.SyscallPIDRulesMap(), runtime.SyscallCommRulesMap(), runtime.ExecPolicyMap(), securityProfile); err != nil {
		log.Fatalf("installing security profile: %v", err)
	}
	go bpf.SyncSecurityProfile(
		ctx,
		runtime.SyscallRulesMap(),
		runtime.SyscallPIDRulesMap(),
		runtime.SyscallCommRulesMap(),
		runtime.ExecPolicyMap(),
		securityProfile,
		500*time.Millisecond,
	)

	service := control.NewService(*configDir, *socketPath, *syncInterval, mapApplier{
		policyMap:     runtime.PolicyMap(),
		commPolicyMap: runtime.CommPolicyMap(),
	})
	if err := service.EnsureLayout(); err != nil {
		log.Fatalf("preparing control plane layout: %v", err)
	}
	defer service.Close()

	if err := os.Remove(*socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("removing stale socket: %v", err)
	}

	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("listening on unix socket: %v", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(*socketPath)
	}()

	if resp, err := service.Reload(); err != nil {
		log.Printf("initial reload failed: %v", err)
	} else {
		log.Printf(
			"agentguardd active: config-dir=%q rules-dir=%q socket=%q generation=%d rules=%d exec-mode=%d syscall-rules=%d",
			*configDir,
			resp.Permanent.Path,
			*socketPath,
			resp.Runtime.Generation,
			resp.Runtime.RuleCount,
			securityProfile.ExecMode,
			len(securityProfile.Syscalls),
		)
	}

	server := &http.Server{
		Handler: control.NewHandler(service),
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	go readEvents(runtime)

	select {
	case <-stopper:
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("serving control API: %v", err)
		}
	}

	cancel()
	service.Close()
	_ = runtime.StopReading()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutting down control API: %v", err)
	}
}

func readEvents(runtime *bpf.Runtime) {
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
