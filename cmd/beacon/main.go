// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Command beacon is the governed alert path on a host: it raises alerts from
// the container runtime, accepts alerts over authenticated HTTP, applies one
// policy (dedup, storm suppression, correlation, routing), and delivers
// through courier with an at-least-once guarantee.
//
// main does nothing but build Deps and hand off to daemon.Run, so the running
// binary and the wiring tests exercise the same entrypoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	_ "time/tzdata" // embed the IANA tz database so timezone: loads on distroless

	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/daemon"
	"github.com/tagwright/beacon/internal/delivery"
	"github.com/tagwright/beacon/internal/history"
	"github.com/tagwright/beacon/internal/policy"
	"github.com/tagwright/beacon/internal/routing"
	"github.com/tagwright/beacon/internal/routing/tools"
	"github.com/tagwright/beacon/internal/spool"
	"github.com/tagwright/core/runtime"
)

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "beacon:", err)
		os.Exit(1)
	}
}

// dispatch routes a routing subcommand to internal/routing/tools, or runs the
// daemon. It stays thin: the tool logic lives in the tools package so it runs
// without the daemon socket and is tested there.
func dispatch(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "explain":
			return tools.Explain(args[1:], os.Stdout, os.Stdin)
		case "lint":
			return tools.Lint(args[1:], os.Stdout)
		case "replay":
			return tools.Replay(args[1:], os.Stdout)
		case "scaffold":
			return tools.Scaffold(args[1:], os.Stdout)
		}
	}
	return run(args)
}

func run(args []string) error {
	fs := flag.NewFlagSet("beacon", flag.ContinueOnError)
	configPath := fs.String("config", envOr("BEACON_CONFIG", "/etc/beacon/beacon.yml"), "path to the beacon config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	clk := clock.Real{}

	deliverer, err := delivery.New(cfg.Channels, secretResolver, logger)
	if err != nil {
		return err
	}
	sp, err := spool.New(cfg.Spool.Dir, cfg.Spool.MaxAge, clk)
	if err != nil {
		return err
	}

	// Build the routing engine (leaves are the channel names, the tree is the
	// rulesets, the timezone the clock for time matching) and the bounded
	// history store replay reads from.
	loc, err := cfg.Location()
	if err != nil {
		return err
	}
	leafNames := make([]string, 0, len(cfg.Channels))
	for name := range cfg.Channels {
		leafNames = append(leafNames, name)
	}
	router := routing.New(cfg.Rulesets, leafNames, loc)
	hist, err := history.New(cfg.HistoryDir(), cfg.History.MaxAge, cfg.History.MaxCount, clk)
	if err != nil {
		return err
	}

	engine := policy.New(deliverer, sp, clk, policy.Config{
		DedupWindow:       cfg.Dedup.Window,
		CorrelationWindow: cfg.Dedup.CorrelationWindow,
		MaxAttempts:       cfg.Delivery.MaxAttempts,
		InitialBackoff:    cfg.Delivery.InitialBackoff,
		MaxBackoff:        cfg.Delivery.MaxBackoff,
		Router:            router,
		History:           hist,
		NotifyOnResolved:  cfg.NotifyOnResolved,
		WatchDefault:      cfg.WatchDefault(),
		IngestDefault:     cfg.IngestDefault(),
	}, logger)

	var rt runtime.Runtime
	if cfg.Watch.Enabled {
		switch cfg.Watch.Runtime {
		case "podman":
			rt = runtime.NewPodman(cfg.Watch.Socket)
		default:
			rt = runtime.NewDocker(cfg.Watch.Socket)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return daemon.Run(ctx, daemon.Deps{
		Config:  cfg,
		Runtime: rt,
		Engine:  engine,
		Resolve: secretResolver,
		Clock:   clk,
		Logger:  logger,
	})
}

// secretResolver resolves a named secret to its value. Stage 1 reads from
// /run/secrets/<name> (the SOPS-decrypted secrets dir the deploy stack mounts)
// or a BEACON_SECRET_<name> environment variable, matching the suite's
// injection model. It is intentionally minimal here.
func secretResolver(name string) (string, error) {
	if v, ok := os.LookupEnv("BEACON_SECRET_" + name); ok {
		return v, nil
	}
	b, err := os.ReadFile("/run/secrets/" + name)
	if err != nil {
		return "", fmt.Errorf("beacon: resolve secret %q: %w", name, err)
	}
	return string(b), nil
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
