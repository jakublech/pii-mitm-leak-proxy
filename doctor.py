"""Validate the install. Hard checks fail; optional tools only warn."""
import sys
import os
import json
import shutil

ROOT = os.path.dirname(os.path.abspath(__file__))


def main():
    hard_ok = True

    if sys.version_info < (3, 8):
        print("FAIL  python >= 3.8 required")
        hard_ok = False
    else:
        print(f"ok    python {sys.version.split()[0]}")

    for rel in ["detector.py", "addon.py", "test/selftest.py", "profile.example.json"]:
        if os.path.exists(os.path.join(ROOT, rel)):
            print(f"ok    {rel}")
        else:
            print(f"FAIL  missing {rel}")
            hard_ok = False

    try:
        json.load(open(os.path.join(ROOT, "profile.example.json")))
        print("ok    profile.example.json parses")
    except Exception as e:
        print(f"FAIL  profile.example.json: {e}")
        hard_ok = False

    if shutil.which("mitmdump"):
        print("ok    mitmdump present — live capture available")
    else:
        print("warn  mitmdump not installed — detector is unit-testable, live capture unavailable")
        print("      install: pipx install mitmproxy  (or pip install mitmproxy)")

    print("DOCTOR: OK" if hard_ok else "DOCTOR: FAIL")
    sys.exit(0 if hard_ok else 1)


main()
