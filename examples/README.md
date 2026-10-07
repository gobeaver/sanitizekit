# Examples

Five runnable programs, in the order worth reading them.

```bash
go run ./examples/01-basic
go run ./examples/02-custom-profile
go run ./examples/03-removal-report
go run ./examples/04-http-server      # then open http://localhost:8090
go run ./examples/05-declarative-runtime
```

---

### [01-basic](01-basic) — sanitize HTML and CSS

The smallest thing that works. Build one `Sanitizer` at startup, call it per
request. Shows the three properties you can rely on: the output is inert, an
error always comes with an empty string, and sanitizing is idempotent — which
is what makes it safe to store the output and re-run it through a stricter
policy later.

### [02-custom-profile](02-custom-profile) — write your own policy

A deliberately tiny "comment box" profile, then the more interesting half:
seven attempts to weaken it, all rejected by `New()` at startup with an error
naming the field.

```
allow <script>                  rejected: invalid profile field "AllowedTags": tag script is always forbidden
allow an onclick handler        rejected: invalid profile field "AllowedAttrs": event handler attributes are forbidden
loosen CSP to 'unsafe-inline'   rejected: invalid profile field "CSP.ScriptSrc": only 'none' or hashes are allowed
```

Safety here is not a convention you have to remember. A profile that would
weaken it cannot be constructed.

### [03-removal-report](03-removal-report) — tell the author what happened

Silently deleting someone's markup is a bad experience *and* it hides sanitizer
bugs. Every drop produces a `Removal`; this groups them by kind into the
summary you would show next to a Save button.

### [04-http-server](04-http-server) — the whole path

Accept, authorize, sanitize, store, serve. Note the ordering — nothing
unsanitized ever reaches the store — and that the response headers come from
`Sanitizer.CSPHeaders()`, so policy and headers cannot drift apart.

```bash
go run ./examples/04-http-server
curl -si localhost:8090/r/demo | head    # see the CSP

curl -X POST localhost:8090/save \
  -H "X-Save-Token: example-token-not-for-production" \
  --data-urlencode 'slug=hostile' \
  --data-urlencode 'html=<p>hi</p><script>alert(1)</script>' \
  --data-urlencode 'css=</style><img src=x onerror=alert(1)>{color:red}'
```

### [05-declarative-runtime](05-declarative-runtime) — motion without script

User content never becomes script. The shell ships one small fixed runtime,
allowed by an exact SHA-256 hash in `script-src`, and users opt into its
behaviours with reserved `data-gb-*` attributes. Edit one character of the
runtime and the browser refuses to run it.

---

## A note on the HTTP example

`04-http-server` is a teaching example, not a deployment. It uses a hardcoded
token and an in-memory map. For production use `pageservice/handlers`, which
refuses every save until you supply a `SaveAuthorizer`, and run the write API
on a separate listener from the public one — see the main
[README](../README.md#running-the-service).
