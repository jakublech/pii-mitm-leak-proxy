"""Deterministic self-test — proves the detector flags PII bound for watched
hosts and stays silent on first-party/clean traffic. Runs without mitmproxy.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detector import scan_flow  # noqa: E402

profile = {
    "watchHosts": ["telemetry.vendor.test", "*.analytics.test"],
    "sensitiveValues": ["MRN-X-999", "Jane Doe"],  # seeded test identities only
    "patterns": {
        "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "mrn": r"MRN-[A-Z]-\d{3,}",
    },
}


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'}  {name}")
    return cond


ok = True

# 1) known value leaked to a watched host -> flagged high
f = scan_flow("telemetry.vendor.test", "https://telemetry.vendor.test/t",
              '{"patient":"Jane Doe"}', profile)
ok &= check("known value -> telemetry: flagged high",
            any(x["type"] == "pii-leak-known-value" for x in f))

# 2) MRN pattern to a wildcard-watched subdomain -> flagged
f = scan_flow("eu.analytics.test", "https://eu.analytics.test/c?u=MRN-A-123", "", profile)
ok &= check("MRN pattern -> analytics: flagged",
            any(x["type"] == "pii-leak-pattern:mrn" for x in f))

# 3) email pattern -> flagged
f = scan_flow("telemetry.vendor.test", "https://telemetry.vendor.test/t",
              "e=jane.doe@x.test", profile)
ok &= check("email pattern -> telemetry: flagged",
            any(x["type"] == "pii-leak-pattern:email" for x in f))

# 4) same PII to a NON-watched first-party host -> silent (out of scope here)
f = scan_flow("api.myclient.test", "https://api.myclient.test/v",
              '{"patient":"Jane Doe"}', profile)
ok &= check("PII -> first-party api: not flagged", f == [])

# 5) clean traffic to a watched host -> silent
f = scan_flow("telemetry.vendor.test", "https://telemetry.vendor.test/t",
              '{"event":"click"}', profile)
ok &= check("clean -> telemetry: not flagged", f == [])

# 6) no duplicate finding when a value matches both known-value and a pattern
f = scan_flow("telemetry.vendor.test", "https://telemetry.vendor.test/t",
              "x=MRN-X-999", {**profile, "patterns": {"mrn": r"MRN-[A-Z]-\d{3,}"}})
ok &= check("known value also matching a pattern -> single finding", len(f) == 1)

print("SELFTEST: PASS" if ok else "SELFTEST: FAIL")
sys.exit(0 if ok else 1)
