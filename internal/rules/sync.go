package rules

import (
	"context"
	"log"
	"time"

	cebpf "github.com/cilium/ebpf"
)

func SyncCompiledPolicies(ctx context.Context, policyMap, commPolicyMap *cebpf.Map, rs Ruleset, interval time.Duration) {
	if !needsProcessScan(rs) {
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

		compiled, err := Compile(rs, CompileOptions{})
		if err != nil {
			log.Printf("compiling ruleset: %v", err)
			continue
		}
		if err := ApplyCompiled(policyMap, commPolicyMap, compiled); err != nil {
			log.Printf("applying compiled ruleset: %v", err)
		}
	}
}
