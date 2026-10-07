// Command pageservice is the main HTTP entry point for the
// user-content platform's page service. It serves the public
// /r/:slug endpoint on a dedicated user-content origin, plus a
// draft-preview endpoint for the dashboard.
//
// Run with: go run ./cmd/pageservice
//
// Configuration is loaded via pageservice.GetConfig
// (BEAVER_PAGESERVICE_* env vars). Override the prefix with
// pageservice.WithPrefix("…") for multi-instance deployments.
//
// Two listeners, deliberately:
//
//   - ADDR serves the public, credential-free user-content origin:
//     /r/:slug, /preview/:slug and /report. Nothing there writes.
//   - ADMIN_ADDR serves the editor-facing write API (/api/save)
//     and requires a bearer token. It is disabled unless both
//     ADMIN_ADDR and SAVE_TOKEN are set, and it must never be
//     exposed to the public internet.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice"
	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/drafts"
	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/handlers"
	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/middleware"
	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/storage"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

// shutdownTimeout bounds how long in-flight requests get to finish
// after a termination signal.
const shutdownTimeout = 15 * time.Second

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := pageservice.GetConfig()
	if err != nil {
		return err
	}

	signer, err := drafts.NewSigner([]byte(cfg.DraftSecret), 0)
	if err != nil {
		return err
	}

	profile := profiles.ProfileFullPage()
	if cfg.DashboardHost != "" {
		profile.CSP.FrameAncestors = "'self' https://" + cfg.DashboardHost
	}

	srv, err := handlers.NewServer(storage.NewMemoryStore(), signer, profile, cfg.PublicHost)
	if err != nil {
		return err
	}

	// Public listener: read-only routes, host-gated, with any
	// inbound credentials stripped.
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("/r/", srv.HandleRender)
	publicMux.HandleFunc("/preview/", srv.HandlePreview)
	publicMux.HandleFunc("/report", srv.HandleReport)
	publicHandler := middleware.HostGate(srv.AllowedHosts...)(middleware.StripCredentials()(publicMux))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	servers := []*http.Server{newHTTPServer(cfg, cfg.Addr, publicHandler)}
	log.Printf("page service listening on %s (hosts: %v)", cfg.Addr, srv.AllowedHosts)

	// Admin listener: the write API, behind a bearer token.
	if cfg.AdminAddr != "" {
		srv.Authorizer = bearerAuthorizer(cfg.SaveToken)
		adminMux := http.NewServeMux()
		adminMux.HandleFunc("/api/save", srv.HandleSave)
		servers = append(servers, newHTTPServer(cfg, cfg.AdminAddr, adminMux))
		log.Printf("write API listening on %s (bearer token required)", cfg.AdminAddr)
	} else {
		log.Printf("write API disabled (set ADMIN_ADDR and SAVE_TOKEN to enable)")
	}

	errCh := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *http.Server) {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}(s)
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Printf("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	var firstErr error
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// newHTTPServer builds a listener with the configured timeouts.
// ReadHeaderTimeout is set explicitly as well as ReadTimeout so a
// slow-header client cannot hold a connection open.
func newHTTPServer(cfg *pageservice.Config, addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
}

// bearerAuthorizer accepts a save only when the request carries
// the configured token in an Authorization: Bearer header. The
// comparison is constant time so the token cannot be recovered a
// byte at a time.
func bearerAuthorizer(token string) handlers.SaveAuthorizer {
	want := []byte(token)
	return handlers.SaveAuthorizerFunc(func(r *http.Request, _ handlers.SaveRequest) error {
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			return handlers.ErrUnauthorized
		}
		return nil
	})
}
