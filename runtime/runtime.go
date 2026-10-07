// Package runtime is the trusted declarative runtime (M5). The
// runtime is the only JavaScript that runs on a user-content
// page. It is hashed at compile time and referenced by the
// CSP's script-src directive — never 'unsafe-inline', never an
// arbitrary URL.
package runtime

import (
	"crypto/sha256"
	"encoding/base64"
)

// Runtime is the JavaScript runtime that interprets the
// data-gb-* attributes. The source is built at build time and
// embedded here as a constant so the server can compute its
// SHA-256 hash for the CSP header.
//
// The implementation is intentionally tiny: motion, countdowns,
// and a gallery/lightbox. It is NOT a generic JavaScript engine
// and MUST NOT be extended to execute arbitrary user code.
const Runtime = `
(function () {
  function $$(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }
  function $ (sel, root) { return (root || document).querySelector(sel); }

  // data-gb-animate="fade-up" — fade up on first reveal.
  $$('[data-gb-animate]').forEach(function (el) {
    var kind = el.getAttribute('data-gb-animate');
    el.style.opacity = '0';
    el.style.transition = 'opacity .8s ease, transform .8s ease';
    el.style.transform = 'translateY(20px)';
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          el.style.opacity = '1';
          el.style.transform = 'none';
          io.unobserve(el);
        }
      });
    });
    io.observe(el);
  });

  // data-gb-countdown="<iso>" — countdown to the given date.
  $$('[data-gb-countdown]').forEach(function (el) {
    var target = new Date(el.getAttribute('data-gb-countdown'));
    function tick() {
      var ms = target.getTime() - Date.now();
      if (ms <= 0) {
        el.textContent = 'today';
        return;
      }
      var d = Math.floor(ms / 86400000);
      var h = Math.floor((ms / 3600000) % 24);
      var m = Math.floor((ms / 60000) % 60);
      var s = Math.floor((ms / 1000) % 60);
      el.textContent = d + 'd ' + h + 'h ' + m + 'm ' + s + 's';
      setTimeout(tick, 1000);
    }
    tick();
  });

  // data-gb-lightbox — clicking <img> inside opens a fullscreen
  // overlay.
  $$('[data-gb-lightbox] img').forEach(function (img) {
    img.style.cursor = 'zoom-in';
    img.addEventListener('click', function () {
      var ov = document.createElement('div');
      ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);display:flex;align-items:center;justify-content:center;cursor:zoom-out;z-index:9999';
      var big = document.createElement('img');
      big.src = img.src;
      big.style.cssText = 'max-width:90vw;max-height:90vh;box-shadow:0 0 40px rgba(0,0,0,0.5)';
      ov.appendChild(big);
      ov.addEventListener('click', function () { document.body.removeChild(ov); });
      document.body.appendChild(ov);
    });
  });
})();
`

// DataGBAttrs returns the list of data-gb-* attributes the
// runtime reacts to. The sanitizer allows any data-gb-* attribute
// (the prefix is in the default profile), so the runtime must
// ignore unknown values.
func DataGBAttrs() []string {
	return []string{
		"data-gb-animate",
		"data-gb-countdown",
		"data-gb-lightbox",
	}
}

// CSPHash returns the CSP source expression for the runtime,
// e.g. "'sha256-XcM0…'". Put it in Profile.CSP.ScriptHashes to
// allow the runtime — and nothing else — to execute:
//
//	p := profiles.ProfileFullPage()
//	p.CSP.ScriptHashes = []string{runtime.CSPHash()}
//
// The hash covers exactly the bytes in Runtime, so it must be
// embedded in the page verbatim, with no surrounding whitespace
// added or removed.
func CSPHash() string {
	sum := sha256.Sum256([]byte(Runtime))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}
