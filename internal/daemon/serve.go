// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/ingest"
)

// buildAuth selects the ingest authenticator for the configured mode.
//
// Stage 1: "none" is the explicit opt-in unauthenticated listener. "hmac" is
// the default and pins the X-Beacon-Signature contract, but secret injection
// is not wired yet, so the HMAC key is empty and a later stage resolves it by
// injection (courier's SecretResolver) before this is a real guard.
func buildAuth(cfg config.IngestConfig) ingest.Authenticator {
	if cfg.AuthMode == "none" {
		return ingest.NoAuth{}
	}
	// TODO(stage-2): resolve cfg.SignSecret by injection into the key.
	return ingest.NewHMACAuth(nil, cfg.MaxSkew)
}

// serveIngest runs the ingest HTTP server until ctx is cancelled, then shuts
// it down gracefully.
func serveIngest(ctx context.Context, listen string, srv *ingest.Server, logger *slog.Logger) error {
	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	err := httpSrv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
