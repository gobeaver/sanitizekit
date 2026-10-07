// Package config loads a sanitization Profile from the
// environment.
//
// It is deliberately a separate package from usercontent: the
// sanitizer is the security core, and keeping configuration —
// and its third-party dependency — out of it means a consumer
// that only sanitizes inherits nothing but golang.org/x/net/html.
package config

import (
	"fmt"

	"github.com/gobeaver/configkit"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
)

// EnvPrefix is the default environment prefix for this package.
// With configkit's default prefix ("BEAVER_"), the package reads
// BEAVER_USERCONTENT_MAX_HTML_BYTES, BEAVER_USERCONTENT_PROFILE, etc.
const EnvPrefix = configkit.DefaultPrefix + "USERCONTENT_"

// Config is the package configuration loaded from the environment.
//
// Tags carry no prefix: the prefix is applied by the loader so the
// same struct can back several independently-configured instances
// via usercontent.WithPrefix.
//
// Every optional field has an envDefault so the zero-config path
// is safe. The profile name is required: a missing name is a
// startup failure, not a silent fallback.
type Config struct {
	// Profile is the starting Profile name to load from
	// profiles.ProfileFullPage / profiles.ProfileEmbed / etc.
	Profile string `env:"PROFILE" envDefault:"fullpage"`

	// MaxHTMLBytes bounds a single HTML input. Larger inputs are
	// rejected before parsing. Profiles can tighten but never
	// loosen this bound at the usercontent layer.
	MaxHTMLBytes int `env:"MAX_HTML_BYTES" envDefault:"307200"` // 300 KB

	// MaxCSSBytes bounds a single CSS input.
	MaxCSSBytes int `env:"MAX_CSS_BYTES" envDefault:"153600"` // 150 KB

	// MaxDOMDepth bounds the parsed HTML tree depth (DoS guard).
	MaxDOMDepth int `env:"MAX_DOM_DEPTH" envDefault:"40"`

	// MaxDOMNodes bounds the parsed HTML node count (DoS guard).
	MaxDOMNodes int `env:"MAX_DOM_NODES" envDefault:"5000"`

	// AllowDataImages toggles data:image/* acceptance for img/src.
	AllowDataImages bool `env:"ALLOW_DATA_IMAGES" envDefault:"true"`

	// ShellNamespace is the gb-shell-* prefix the page service
	// reserves; user ids/classes that start with it are rewritten
	// or rejected.
	ShellNamespace string `env:"SHELL_NAMESPACE" envDefault:"gb-shell"`

	// StrictNamespaceCollisions toggles whether collisions with
	// ShellNamespace are rejected outright (true) or rewritten
	// to a non-colliding form (false).
	StrictNamespaceCollisions bool `env:"STRICT_NAMESPACE_COLLISIONS" envDefault:"false"`

	// DataNamespacePrefix reserves a data-* namespace for the
	// trusted declarative runtime. data-gb-* by default.
	DataNamespacePrefix string `env:"DATA_NAMESPACE_PREFIX" envDefault:"data-gb"`
}

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
		return nil, fmt.Errorf("config: load config: %w", err)
	}
	return cfg, nil
}

// ToProfile converts the env-loaded Config into a sanitization
// Profile. The profile name selects a starting preset
// ("fullpage" / "embed"); the env-loaded limits and feature
// flags are overlaid on top so the resulting profile can only be
// tighter than the preset, never looser.
func (c *Config) ToProfile() (usercontent.Profile, error) {
	var base usercontent.Profile
	switch c.Profile {
	case "fullpage", "":
		base = usercontent.DefaultFullPageProfile()
	case "embed":
		base = usercontent.DefaultEmbedProfile()
	default:
		return usercontent.Profile{}, fmt.Errorf("%w: unknown profile %q", usercontent.ErrInvalidConfig, c.Profile)
	}
	// Limits are overlaid with min(), and flags only ever in the
	// safe direction. Assigning the env value directly would let
	// configuration *raise* a preset's limit — and since the env
	// defaults are larger than the fullpage preset's, that used to
	// happen with no configuration at all.
	base.MaxHTMLBytes = minInt(base.MaxHTMLBytes, c.MaxHTMLBytes)
	base.MaxCSSBytes = minInt(base.MaxCSSBytes, c.MaxCSSBytes)
	base.MaxDOMDepth = minInt(base.MaxDOMDepth, c.MaxDOMDepth)
	base.MaxDOMNodes = minInt(base.MaxDOMNodes, c.MaxDOMNodes)
	base.AllowDataImages = base.AllowDataImages && c.AllowDataImages
	base.StrictNamespaceCollisions = base.StrictNamespaceCollisions || c.StrictNamespaceCollisions
	base.ShellNamespace = c.ShellNamespace
	base.DataNamespacePrefix = c.DataNamespacePrefix
	return base, nil
}

// minInt returns the smaller of two limits, ignoring a
// non-positive value so an unset field cannot zero out a preset.
func minInt(preset, override int) int {
	if override <= 0 || override > preset {
		return preset
	}
	return override
}

// Builder creates Config instances bound to a custom environment
// prefix. Use it for multi-instance setups (e.g. one sanitizer per
// product under a different prefix).
type Builder struct {
	prefix string
}

// WithPrefix returns a Builder that reads <prefix>PROFILE,
// <prefix>MAX_HTML_BYTES, etc. The prefix replaces EnvPrefix
// entirely; it is not appended to it.
func WithPrefix(prefix string) *Builder {
	return &Builder{prefix: prefix}
}

// Profile returns a Profile loaded from the builder's prefix.
func (b *Builder) Profile() (usercontent.Profile, error) {
	cfg, err := GetConfig(configkit.WithPrefix(b.prefix))
	if err != nil {
		return usercontent.Profile{}, err
	}
	return cfg.ToProfile()
}
