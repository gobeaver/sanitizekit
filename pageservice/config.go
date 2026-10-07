package pageservice

import (
	"fmt"
	"time"

	"github.com/gobeaver/configkit"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/drafts"
)

// EnvPrefix is the default environment prefix for this package.
// With configkit's default prefix ("BEAVER_"), the package reads
// BEAVER_PAGESERVICE_ADDR, BEAVER_PAGESERVICE_PUBLIC_HOST, etc.
const EnvPrefix = configkit.DefaultPrefix + "PAGESERVICE_"

// Config is the package configuration for the page service.
//
// Tags carry no prefix: the prefix is applied by the loader so the
// same struct can back several independently-configured instances
// via pageservice.WithPrefix.
type Config struct {
	// Addr is the listen address (e.g. ":8080"). Default ":8080".
	Addr string `env:"ADDR" envDefault:":8080"`

	// PublicHost is the user-content hostname (e.g. "pages.go-beaver.com").
	// Required. The Host gate uses this to allow only public routes.
	PublicHost string `env:"PUBLIC_HOST,required" envDefault:"go-beaver.com"`

	// DashboardHost is the dashboard origin allowed in
	// CSP frame-ancestors. Defaults to "dashboard.go-beaver.com".
	DashboardHost string `env:"DASHBOARD_HOST" envDefault:"go-beaver.com"`

	// ReadTimeout bounds incoming request reads. Default 10s.
	ReadTimeout time.Duration `env:"READ_TIMEOUT" envDefault:"10s"`

	// WriteTimeout bounds response writes. Default 10s.
	WriteTimeout time.Duration `env:"WRITE_TIMEOUT" envDefault:"10s"`

	// IdleTimeout bounds keep-alive idle. Default 60s.
	IdleTimeout time.Duration `env:"IDLE_TIMEOUT" envDefault:"60s"`

	// DraftSecret is the HMAC key for signed draft preview tokens.
	// Required in production; fail-fast at startup if missing.
	// Must be at least drafts.MinKeyLen bytes.
	DraftSecret string `env:"DRAFT_SECRET,required"`

	// AdminAddr is the listen address for the editor-facing write
	// API (POST /api/save). It is deliberately a second listener:
	// the public address serves a credential-free origin, and a
	// write endpoint has no business being reachable there.
	//
	// Empty (the default) disables the write API entirely.
	AdminAddr string `env:"ADMIN_ADDR" envDefault:""`

	// SaveToken is the bearer token the editor must present on
	// POST /api/save. It is required whenever AdminAddr is set;
	// without it the write API stays disabled.
	SaveToken string `env:"SAVE_TOKEN" envDefault:""`
}

// Validate checks the invariants GetConfig cannot express in
// struct tags. It is called by GetConfig.
func (c *Config) Validate() error {
	if len(c.DraftSecret) < drafts.MinKeyLen {
		return fmt.Errorf(
			"pageservice: DRAFT_SECRET must be at least %d bytes, got %d",
			drafts.MinKeyLen, len(c.DraftSecret))
	}
	if c.AdminAddr != "" && c.SaveToken == "" {
		return fmt.Errorf("pageservice: ADMIN_ADDR is set but SAVE_TOKEN is empty; refusing to expose an unauthenticated write API")
	}
	if c.AdminAddr != "" && c.AdminAddr == c.Addr {
		return fmt.Errorf("pageservice: ADMIN_ADDR must differ from ADDR; the write API must not share the public listener")
	}
	if c.SaveToken != "" && len(c.SaveToken) < MinSaveTokenLen {
		return fmt.Errorf("pageservice: SAVE_TOKEN must be at least %d characters", MinSaveTokenLen)
	}
	return nil
}

// MinSaveTokenLen is the shortest bearer token accepted for the
// write API.
const MinSaveTokenLen = 24

// GetConfig loads Config from the environment.
//
// With no options it uses EnvPrefix. Passing any option replaces
// that default, so callers who want a different prefix pass
// configkit.WithPrefix themselves.
func GetConfig(opts ...configkit.Option) (*Config, error) {
	if len(opts) == 0 {
		opts = []configkit.Option{configkit.WithPrefix(EnvPrefix)}
	}
	cfg := &Config{}
	if err := configkit.Load(cfg, opts...); err != nil {
		return nil, fmt.Errorf("pageservice: load config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Builder creates Config instances bound to a custom environment
// prefix. Useful when the same binary serves multiple user-content
// hosts with different secrets.
type Builder struct {
	prefix string
}

// WithPrefix returns a Builder that reads <prefix>ADDR,
// <prefix>PUBLIC_HOST, etc. The prefix replaces EnvPrefix entirely.
func WithPrefix(prefix string) *Builder {
	return &Builder{prefix: prefix}
}

// Config returns the Config loaded from the builder's prefix.
func (b *Builder) Config() (*Config, error) {
	return GetConfig(configkit.WithPrefix(b.prefix))
}
