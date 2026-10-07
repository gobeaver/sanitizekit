package config_test

import (
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/config"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

// Config overlays must only ever tighten the preset they start
// from. The env defaults are larger than the fullpage preset's
// limits, so a direct assignment used to widen them by default.
func TestConfigOnlyTightens(t *testing.T) {
	preset := profiles.ProfileFullPage()
	c := &config.Config{
		Profile:         "fullpage",
		MaxHTMLBytes:    preset.MaxHTMLBytes * 4,
		MaxCSSBytes:     preset.MaxCSSBytes * 4,
		MaxDOMDepth:     preset.MaxDOMDepth * 4,
		MaxDOMNodes:     preset.MaxDOMNodes * 4,
		AllowDataImages: true,
	}
	got, err := c.ToProfile()
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxHTMLBytes != preset.MaxHTMLBytes || got.MaxCSSBytes != preset.MaxCSSBytes ||
		got.MaxDOMDepth != preset.MaxDOMDepth || got.MaxDOMNodes != preset.MaxDOMNodes {
		t.Errorf("config widened the preset limits: %+v", got)
	}

	// Tightening still works.
	c.MaxDOMNodes = 10
	got, err = c.ToProfile()
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxDOMNodes != 10 {
		t.Errorf("config could not tighten MaxDOMNodes: got %d", got.MaxDOMNodes)
	}

	// A flag can turn a feature off but never on.
	c.AllowDataImages = false
	if got, _ = c.ToProfile(); got.AllowDataImages {
		t.Error("AllowDataImages=false did not disable data images")
	}
}
