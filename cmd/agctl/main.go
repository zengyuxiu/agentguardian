package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/zengyuxiu/agentguardian/internal/control"
)

func main() {
	var socketPath string
	root := flag.NewFlagSet("agctl", flag.ExitOnError)
	root.StringVar(&socketPath, "socket", "/run/agentguardian/agentguardd.sock", "unix socket path for agentguardd")
	root.Parse(os.Args[1:])

	args := root.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	client := control.NewClient(socketPath)
	ctx := context.Background()

	switch args[0] {
	case "status":
		resp, err := client.Status(ctx)
		if err != nil {
			log.Fatal(err)
		}
		printJSON(resp)
	case "validate":
		validateCmd := flag.NewFlagSet("validate", flag.ExitOnError)
		scope := validateCmd.String("scope", string(control.ScopePermanent), "validation scope: permanent or runtime")
		validateCmd.Parse(args[1:])

		resp, err := client.Validate(ctx, control.Scope(*scope))
		if err != nil {
			log.Fatal(err)
		}
		printJSON(resp)
		if !resp.State.Valid {
			os.Exit(1)
		}
	case "reload":
		resp, err := client.Reload(ctx)
		if err != nil {
			log.Fatal(err)
		}
		printJSON(resp)
	default:
		usage()
		os.Exit(2)
	}
}

func printJSON(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  agctl [-socket /path/to/agentguardd.sock] status
  agctl [-socket /path/to/agentguardd.sock] validate [-scope permanent|runtime]
  agctl [-socket /path/to/agentguardd.sock] reload`)
}
