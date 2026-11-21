# pii-mitm-leak-proxy

A small, auditable man-in-the-middle proxy that flags **PII leaking from a web
application to third-party / telemetry hosts**. Built on
[mitmproxy](https://mitmproxy.org/); the detection logic is a pure, unit-tested
function.

It is a **test instrument** run during an authorized security assessment, not a
production component. It complements an authorization-testing engine: that
engine finds broken access control from the outside; this proxy catches the
PII-exfiltration-to-third-parties class (OWASP-adjacent, e.g. sensitive data
sent to analytics/telemetry vendors) that is only visible on the wire.

## How it works

```
client app  ──egress──▶  [ this proxy ]  ──▶  3rd-party / telemetry host
                              │
                              ▼  scans each outbound flow
                         findings.json  (host, masked match, evidence)
```

A finding is raised only when traffic is bound for a **watched** host *and*
contains a sensitive value. First-party API traffic is out of scope here by
design.

## Detection is pattern-first (no real PII at rest)

- **Patterns** (primary): regexes for email, MRN-like ids, national ids, etc.
  Nothing sensitive is stored in config.
- **Known values** (optional, exact): only ever your own **seeded test
  identities** — never real patient/customer data. Storing real PII to "detect
  PII leaks" would itself be a leak.

Matches are **masked** in output (`MR******9`), so `findings.json` holds
evidence, not raw PII.

## Usage

```bash
make doctor     # validate install
make test       # deterministic detector self-test (no mitmproxy needed)
make live       # end-to-end demo through mitmdump (requires mitmproxy)
```

Real engagement (in the client test environment, egress routed through the proxy):

```bash
PROFILE=profile.json PII_OUT=findings.json mitmdump -s addon.py
```

### Container (recommended for deployment)

Bundles a pinned mitmproxy + the addon, so the client needs no local Python
setup. Client data stays out of the image — the profile is mounted, findings and
the CA are volumes:

```bash
make docker-build                      # build the image
make docker-run                        # proxy on :8899, findings in ./out
make docker-run PORT=9123              # …or pick any free port
```

The listen port is parametrised (8080 collides with too many apps), default
**8899**. Override per run with `-e LISTEN_PORT` and the matching `-p`:

```bash
docker run --rm -p 9123:9123 -e LISTEN_PORT=9123 \
  -v "$PWD/profile.json:/app/profile.json:ro" \
  -v "$PWD/out:/data" \
  -v pii_mitm_ca:/root/.mitmproxy \
  pii-mitm-leak-proxy
```

Point the app's `HTTP(S)_PROXY` at the container and trust the CA it writes to
the `pii_mitm_ca` volume in the **test** environment.

For HTTPS interception the client must trust the proxy CA in the **test**
environment (and certificate pinning, if present, must be relaxed there). That
is an access arrangement negotiated as part of scope — not a configuration of
this tool.

## Configuration (`profile.json`)

Per-engagement, **never committed** (see `.gitignore`). See
`profile.example.json`. Keys:

| key | meaning |
|---|---|
| `watchHosts` | third-party/telemetry hosts to inspect (glob allowed) |
| `patterns` | named regexes for generic PII (primary detection) |
| `sensitiveValues` | exact values — seeded test identities only |
| `sensitiveFields` | documentation of what counts as PII for this client |

## Repository hygiene

This repo is generic tooling. It must contain **no** client data: no real
`watchHosts`, no real `sensitiveValues`, no `profile.json`. Those live only in
the per-engagement workspace and are git-ignored.

## Scope & authorization

Run this only against systems you own or are **authorized in writing** to test.
It intercepts TLS, so it is for a controlled assessment environment where CA
trust and any certificate pinning are arranged as part of scope — never against
third parties or production traffic you do not control.

## License

[MIT](LICENSE).
