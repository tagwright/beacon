// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/ingest"
	"github.com/tagwright/courier"
)

// buildAuth selects the ingest authenticator for the configured mode. "none"
// is the explicit opt-in unauthenticated listener for a closed network. "hmac"
// (the default) resolves the named signing secret by injection (courier's
// model) and verifies the X-Beacon-Signature contract; a missing or empty
// secret is a hard configuration error, never a silently open listener.
func buildAuth(cfg config.IngestConfig, resolve courier.SecretResolver) (ingest.Authenticator, error) {
	if cfg.AuthMode == "none" {
		return ingest.NoAuth{}, nil
	}
	if cfg.SignSecret == "" {
		return nil, fmt.Errorf("beacon: ingest auth_mode hmac requires sign_secret to name a signing secret")
	}
	if resolve == nil {
		return nil, fmt.Errorf("beacon: ingest auth_mode hmac requires a secret resolver")
	}
	key, err := resolve(cfg.SignSecret)
	if err != nil {
		return nil, fmt.Errorf("beacon: resolve ingest sign_secret %q: %w", cfg.SignSecret, err)
	}
	if key == "" {
		return nil, fmt.Errorf("beacon: ingest sign_secret %q resolved empty", cfg.SignSecret)
	}
	return ingest.NewHMACAuth([]byte(key)), nil
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
