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

	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/daemon"
	"github.com/tagwright/beacon/internal/delivery"
	"github.com/tagwright/beacon/internal/policy"
	"github.com/tagwright/beacon/internal/spool"
	"github.com/tagwright/core/runtime"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "beacon:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", envOr("BEACON_CONFIG", "/etc/beacon/beacon.yml"), "path to the beacon config file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	clk := clock.Real{}

	deliverer, err := delivery.New(cfg.Channels, cfg.DefaultChannel, secretResolver)
	if err != nil {
		return err
	}
	sp, err := spool.New(cfg.Spool.Dir, cfg.Spool.MaxAge, clk)
	if err != nil {
		return err
	}
	engine := policy.New(deliverer, sp, clk, policy.Config{
		DedupWindow:       cfg.Dedup.Window,
		CorrelationWindow: cfg.Dedup.CorrelationWindow,
		MaxAttempts:       cfg.Delivery.MaxAttempts,
		InitialBackoff:    cfg.Delivery.InitialBackoff,
		MaxBackoff:        cfg.Delivery.MaxBackoff,
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
