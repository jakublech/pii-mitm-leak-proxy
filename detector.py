"""PII-in-telemetry leak detector — pure logic, no mitmproxy dependency.

A leak = a sensitive value appears in traffic bound for a *watched* 3rd-party
host. Detection is primarily pattern-based so no real PII is stored at rest;
exact known values are only ever our own seeded test identities.

This is a pure function so it is unit-testable without running a proxy.
"""
import json
import re
import fnmatch


def host_watched(host, watch_hosts):
    return any(fnmatch.fnmatch(host or "", pat) for pat in watch_hosts)


def mask(s):
    s = str(s)
    if len(s) <= 3:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 3) + s[-1]


def scan_flow(host, url, body, profile):
    """Return findings for one outbound flow.

    host: destination hostname; url: full request URL; body: request body text.
    Only flows to a watched host are inspected — first-party API traffic is out
    of scope for this tool (that is the authz engine's job).
    """
    if not host_watched(host, profile.get("watchHosts", [])):
        return []

    haystack = f"{url}\n{body or ''}"
    findings = []
    seen = set()

    # 1) known sensitive values — exact, high confidence.
    #    Only our seeded test identities belong here, never real patient data.
    for val in profile.get("sensitiveValues", []):
        if val and val in haystack:
            m = mask(val)
            key = ("known", m)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "severity": "high",
                    "type": "pii-leak-known-value",
                    "host": host,
                    "match": m,
                    "evidence": "known sensitive value present in body/url",
                })

    # 2) pattern-based — generic PII, nothing sensitive stored at rest.
    for name, pat in profile.get("patterns", {}).items():
        for hit in re.findall(pat, haystack):
            m = mask(hit)
            if ("known", m) in seen:
                continue  # already reported as an exact known value
            key = (name, m)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "severity": "medium",
                "type": f"pii-leak-pattern:{name}",
                "host": host,
                "match": m,
                "evidence": f"pattern '{name}' matched in body/url",
            })

    return findings


def load_profile(path):
    with open(path) as f:
        return json.load(f)
