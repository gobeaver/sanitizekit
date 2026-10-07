package profiles

import (
	"testing"
)

func TestProfiles(t *testing.T) {
	fp := ProfileFullPage()
	if fp.Name == "" {
		t.Error("ProfileFullPage name empty")
	}
	em := ProfileEmbed()
	if em.Name == "" {
		t.Error("ProfileEmbed name empty")
	}
}
