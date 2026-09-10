// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package daemon holds beacon's production entrypoint seam: run(ctx, Deps),
// which main wraps in under ten lines. Deps carries the collaborators as
// interfaces so a wiring test drives the real run() against the shared core
// runtime fake and a capturing engine, closing the built-but-not-wired gap the
// suite's testing standard exists to prevent.
package daemon

import (
	"context"
	"log/slog"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/ingest"
	"github.com/tagwright/beacon/internal/policy"
	"github.com/tagwright/beacon/internal/watch"
	"github.com/tagwright/core/runtime"
)

// Deps is everything run() needs, injected so tests can substitute fakes. The
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
	// Logger is the structured logger. Nil uses slog.Default().
	Logger *slog.Logger
}

// Run starts the enabled ingress paths, feeds every alert they raise into the
// one governed delivery path, and blocks until ctx is cancelled. It is the
// production entrypoint; main does nothing but build Deps and call it.
func Run(ctx context.Context, deps Deps) error {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	emit := func(ctx context.Context, a alert.Alert) error {
		return deps.Engine.Process(ctx, a)
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
		started++
		srv := ingest.NewServer(ingest.Options{
			Auth:           buildAuth(deps.Config.Ingest),
			Emit:           emit,
			DefaultChannel: deps.Config.Ingest.DefaultChannel,
			Logger:         logger,
		})
		go func() { errCh <- serveIngest(ctx, deps.Config.Ingest.Listen, srv, logger) }()
		logger.Info("beacon: ingest path started", "listen", deps.Config.Ingest.Listen)
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
