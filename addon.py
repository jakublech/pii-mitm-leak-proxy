"""mitmproxy addon — flags outbound PII leaks to watched 3rd-party hosts.

Run (in the client test environment, egress routed through this proxy):
    PROFILE=profile.json PII_OUT=findings.json mitmdump -s addon.py

The heavy lifting (TLS interception) is mitmproxy's; this addon only calls the
pure detector on each flow. Keep this file thin.
"""
import os
import json

from detector import load_profile, scan_flow

PROFILE = os.environ.get("PROFILE", "profile.example.json")
OUT = os.environ.get("PII_OUT", "findings.json")


class PiiLeak:
    def __init__(self):
        self.profile = load_profile(PROFILE)
        self.findings = []

    def request(self, flow):
        try:
            body = flow.request.get_text(strict=False) or ""
        except Exception:
            body = ""
        for f in scan_flow(flow.request.host, flow.request.pretty_url, body, self.profile):
            f["url"] = flow.request.pretty_url
            self.findings.append(f)
        if self.findings:
            self._write()

    def _write(self):
        with open(OUT, "w") as fh:
            json.dump(self.findings, fh, indent=2)


addons = [PiiLeak()]
