// Differential browser check for the sanitizer.
//
// The Go-side verification (usercontent.verifyOutputHTML) re-parses
// sanitized output with golang.org/x/net/html — the same parser
// that produced it. If that parser ever disagrees with a browser,
// the sanitizer and its own safety net share the blind spot. This
// harness settles the question with the only authority that counts:
// real engines.
//
// Every page written by `go run ./cmd/corpusexport` is loaded in
// Chromium, Firefox and WebKit, twice:
//
//   - with the production CSP, which is how it ships; and
//   - with NO CSP at all, which isolates the sanitizer. The whole
//     point of the layering is that each layer holds on its own,
//     so a sanitizer failure must not be masked by the header.
//
// In both modes it asserts that:
//   1. no script executes  (alert/confirm/prompt/print hooks, a
//      sentinel, page errors, and CSP violation reports)
//   2. nothing is fetched  (any subresource request at all fails
//      the case; the page is a static document by contract)
//   3. no navigation away from the page is triggered
//   4. the *live* DOM holds no forbidden element, no on* attribute
//      and no javascript:/vbscript:/data:text/html URL
//
// Usage:
//   npm ci && npx playwright install --with-deps
//   node browsertest/check.mjs [pagesDir]

import { chromium, firefox, webkit } from 'playwright';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname, resolve } from 'node:path';

const PAGES_DIR = resolve(process.argv[2] ?? 'browsertest/pages');

const PRODUCTION_CSP =
  "default-src 'none'; script-src 'none'; style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data:; font-src 'self'; media-src 'none'; frame-src 'none'; " +
  "form-action 'none'; base-uri 'none'";

// Elements that must never appear in a sanitized document, checked
// against the DOM the browser actually built.
const FORBIDDEN_ELEMENTS = [
  'script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet',
  'form', 'input', 'button', 'select', 'textarea', 'link', 'meta', 'base',
  'style', 'svg', 'math', 'video', 'audio', 'dialog', 'slot', 'template',
  'noscript', 'noframes', 'noembed', 'marquee', 'details', 'keygen',
  'xmp', 'plaintext', 'listing',
];

// The shell legitimately emits <meta>, <title> and one <style>, so
// the DOM check looks only at the user-content region.
const USER_CONTENT_SELECTOR = 'main.gb-shell-main';

// Installed before any page script runs, so anything that executes
// leaves a mark we can read back.
const SENTINEL = `
  window.__xssFired = [];
  for (const fn of ['alert', 'confirm', 'prompt', 'print']) {
    try { window[fn] = (...a) => { window.__xssFired.push(fn + ':' + a.join(',')); }; } catch (e) {}
  }
  document.addEventListener('securitypolicyviolation', (e) => {
    window.__xssFired.push('csp-blocked:' + e.violatedDirective + ':' + e.blockedURI);
  });
`;

function startServer(dir) {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const name = url.pathname.replace(/^\/+/, '');
    const headers = {
      'Content-Type': extname(name) === '.html' ? 'text/html; charset=utf-8' : 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    };
    // ?nocsp=1 strips the header so the sanitizer is tested alone.
    if (url.searchParams.get('nocsp') !== '1') {
      headers['Content-Security-Policy'] = PRODUCTION_CSP;
    }
    try {
      const body = await readFile(join(dir, name));
      res.writeHead(200, headers);
      res.end(body);
    } catch {
      res.writeHead(404).end('not found');
    }
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ server, port: server.address().port })));
}

async function checkPage(browserName, page, pageURL, entry, mode) {
  const failures = [];
  const note = (msg) =>
    failures.push(
      `[${browserName}/${mode}] ${entry.file} (${entry.source}, input ${JSON.stringify(entry.input)}): ${msg}`,
    );

  const onRequest = (req) => {
    if (req.url() !== pageURL) note(`fetched a subresource: ${req.url()}`);
  };
  const onDialog = async (d) => {
    note(`opened a ${d.type()} dialog: ${d.message()}`);
    await d.dismiss();
  };
  const onPageError = (err) => note(`script ran and threw: ${err.message}`);
  const onFrameNav = (frame) => {
    const u = frame.url();
    if (frame === page.mainFrame() && u !== pageURL && u !== 'about:blank') {
      note(`navigated away to: ${u}`);
    }
  };

  page.on('request', onRequest);
  page.on('dialog', onDialog);
  page.on('pageerror', onPageError);
  page.on('framenavigated', onFrameNav);

  try {
    await page.goto(pageURL, { waitUntil: 'load', timeout: 15000 });
    // Give timers, IntersectionObservers and lazy handlers a moment.
    await page.waitForTimeout(150);

    for (const f of await page.evaluate(() => window.__xssFired ?? [])) {
      // A CSP report proves the header did its job — and equally
      // that markup which wanted to execute survived sanitization.
      note(`execution attempt: ${f}`);
    }

    const domIssues = await page.evaluate(
      ({ forbidden, selector }) => {
        const root = document.querySelector(selector);
        if (!root) return ['user-content region is missing from the document'];
        const out = [];
        // Browsers strip C0 controls and spaces from a URL before
        // resolving its scheme, so strip them before comparing.
        const scheme = (v) => v.replace(/[\u0000-\u0020\u007f]/g, '').toLowerCase();
        for (const el of root.querySelectorAll('*')) {
          const tag = el.tagName.toLowerCase();
          if (forbidden.includes(tag)) out.push(`forbidden element <${tag}>`);
          for (const attr of el.attributes) {
            const name = attr.name.toLowerCase();
            if (name.startsWith('on')) out.push(`event handler ${attr.name} on <${tag}>`);
            if (['href', 'src', 'srcset', 'poster', 'action', 'formaction', 'srcdoc'].includes(name)) {
              const v = scheme(attr.value);
              if (v.startsWith('javascript:') || v.startsWith('vbscript:') || v.startsWith('data:text/html')) {
                out.push(`dangerous URL in ${attr.name} on <${tag}>: ${attr.value}`);
              }
            }
          }
        }
        return out;
      },
      { forbidden: FORBIDDEN_ELEMENTS, selector: USER_CONTENT_SELECTOR },
    );
    for (const d of domIssues) note(d);
  } catch (err) {
    note(`load failed: ${err.message}`);
  } finally {
    page.off('request', onRequest);
    page.off('dialog', onDialog);
    page.off('pageerror', onPageError);
    page.off('framenavigated', onFrameNav);
  }

  return failures;
}

async function main() {
  let manifest;
  try {
    manifest = JSON.parse(await readFile(join(PAGES_DIR, 'manifest.json'), 'utf8'));
  } catch {
    console.error(`No manifest in ${PAGES_DIR}. Run: go run ./cmd/corpusexport -out ${PAGES_DIR}`);
    process.exit(2);
  }
  if (!Array.isArray(manifest) || manifest.length === 0) {
    console.error('manifest is empty; nothing to check');
    process.exit(2);
  }

  const { server, port } = await startServer(PAGES_DIR);
  const baseURL = `http://127.0.0.1:${port}`;
  const failures = [];
  let checked = 0;
  let enginesRun = 0;

  for (const [name, type] of [['chromium', chromium], ['firefox', firefox], ['webkit', webkit]]) {
    let browser;
    try {
      browser = await type.launch();
    } catch (err) {
      console.error(`SKIP ${name}: ${err.message}`);
      continue;
    }
    enginesRun++;
    const context = await browser.newContext();
    await context.addInitScript(SENTINEL);
    const page = await context.newPage();

    for (const [mode, suffix] of [['csp', ''], ['no-csp', '?nocsp=1']]) {
      for (const entry of manifest) {
        failures.push(...(await checkPage(name, page, `${baseURL}/${entry.file}${suffix}`, entry, mode)));
        checked++;
      }
    }
    console.log(`${name}: checked ${manifest.length} pages in both modes`);
    await browser.close();
  }

  server.close();

  if (enginesRun === 0) {
    console.error('no browser engine could be launched; run: npx playwright install --with-deps');
    process.exit(2);
  }
  if (failures.length > 0) {
    console.error(`\n${failures.length} failure(s):\n`);
    for (const f of failures) console.error('  ' + f);
    process.exit(1);
  }
  console.log(`\nOK: ${checked} page loads across ${enginesRun} engine(s); nothing executed, nothing fetched.`);
}

await main();
