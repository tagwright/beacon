// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package daemon holds beacon's production entrypoint seam: Run(ctx, Deps),
// which main wraps in a few lines. Deps carries the collaborators as interfaces
// so a wiring test drives the real Run against the shared core runtime fake and
// a capturing engine, closing the built-but-not-wired gap the suite's testing
// standard exists to prevent.
package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/ingest"
	"github.com/tagwright/beacon/internal/policy"
	"github.com/tagwright/beacon/internal/watch"
	"github.com/tagwright/core/runtime"
	"github.com/tagwright/courier"
)

// Deps is everything Run needs, injected so tests can substitute fakes. The
// runtime is core's (the shared runtimetest fake stands in for it); the engine
// is the governed delivery path (a capturing fake stands in for it).
type Deps struct {
	// Config is the loaded deployment config.
	Config config.Config
	// Runtime is the core container-runtime handle for the watch path. It
	// may be nil when the watch path is disabled.
	Runtime runtime.Runtime
	// Engine is the single governed delivery path both ingress paths feed.
	Engine policy.Engine
	// Resolve resolves a named secret to its value (courier's model), used
	// to inject the ingest signing key. Nil disables secret-backed auth.
	Resolve courier.SecretResolver
	// Clock is the time source for the ingest replay guard. Nil uses real time.
	Clock clock.Clock
	// Logger is the structured logger. Nil uses slog.Default().
	Logger *slog.Logger
}

// backgroundRunner is the optional surface a production Engine exposes to run
// the spool replayer and the suppression digester. A capturing test fake need
// not implement it.
type backgroundRunner interface {
	RunReplayer(ctx context.Context, interval time.Duration)
	RunDigester(ctx context.Context, interval time.Duration)
}

// Run starts the enabled ingress paths and the delivery background loops, feeds
// every alert into the one governed delivery path, and blocks until ctx is
// cancelled. It is the production entrypoint; main does nothing but build Deps
// and call it.
func Run(ctx context.Context, deps Deps) error {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clk := deps.Clock
	if clk == nil {
		clk = clock.Real{}
	}

	emit := func(ctx context.Context, a alert.Alert) error {
		return deps.Engine.Process(ctx, a)
	}

	// Delivery background loops: spool replay (at-least-once recovery) and the
	// periodic suppression digest. Only a production Engine exposes them.
	if runner, ok := deps.Engine.(backgroundRunner); ok {
		go runner.RunReplayer(ctx, deps.Config.Spool.RetryInterval)
		go runner.RunDigester(ctx, deps.Config.Dedup.DigestInterval)
		logger.Info("beacon: delivery loops started (spool replay, digest)")
	}

	errCh := make(chan error, 2)
	started := 0

	if deps.Config.Watch.Enabled {
		if deps.Runtime == nil {
			logger.Error("beacon: watch enabled but no runtime provided")
		} else {
			started++
			src := watch.New(deps.Runtime, deps.Config.Watch.DefaultChannel, logger)
			go func() { errCh <- src.Run(ctx, emit) }()
			logger.Info("beacon: watch path started", "runtime", deps.Config.Watch.Runtime)
		}
	}

	if deps.Config.Ingest.Enabled {
		auth, err := buildAuth(deps.Config.Ingest, deps.Resolve)
		if err != nil {
			return err
		}
		started++
		srv := ingest.NewServer(ingest.Options{
			Auth:           auth,
			Emit:           emit,
			DefaultChannel: deps.Config.Ingest.DefaultChannel,
			MaxSkew:        deps.Config.Ingest.MaxSkew,
			Clock:          clk,
			Logger:         logger,
		})
		go func() { errCh <- serveIngest(ctx, deps.Config.Ingest.Listen, srv, logger) }()
		logger.Info("beacon: ingest path started", "listen", deps.Config.Ingest.Listen, "auth", deps.Config.Ingest.AuthMode)
	}

	if started == 0 {
		logger.Error("beacon: no ingress path enabled")
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}
