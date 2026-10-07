# Browser differential check

`usercontent.verifyOutputHTML` re-parses sanitized output with
`golang.org/x/net/html` — the same parser that produced it. That is a
correlated check: if x/net/html ever disagrees with a browser about some
input, the sanitizer and its own safety net share the blind spot.

This harness settles it with real engines.

```bash
go run ./cmd/corpusexport -out browsertest/pages
cd browsertest && npm ci && npx playwright install --with-deps
node check.mjs pages
```

Every corpus vector and fuzz seed is sanitized, rendered through the real page
shell, then loaded in Chromium, Firefox and WebKit — **twice**: once with the
production CSP, and once with no CSP at all. The second pass is the important
one. The layers are supposed to hold independently, so a sanitizer failure must
not be masked by a response header.

Each load asserts:

1. **Nothing executes** — `alert`/`confirm`/`prompt`/`print` are hooked, a
   sentinel records any script that runs, `pageerror` is fatal, and a CSP
   violation report is *also* a failure: it proves markup that wanted to
   execute survived sanitization.
2. **Nothing is fetched** — any subresource request at all fails the case. A
   sanitized page is a static document by contract.
3. **No navigation** away from the page.
4. **The live DOM** holds no forbidden element, no `on*` attribute, and no
   `javascript:` / `vbscript:` / `data:text/html` URL — checked against the DOM
   the browser actually built, with C0 controls stripped from URLs the way a
   browser strips them.

`pages/` is generated; it is not committed.
