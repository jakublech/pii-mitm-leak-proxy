"""A deliberately leaky 'client app' for the live demo: it POSTs PII to the
telemetry sink *through the proxy*, so the addon can catch it. HTTP only, so no
CA trust is needed for the demo (real targets use HTTPS + our CA)."""
import os
import urllib.request

PROXY = os.environ.get("APP_PROXY", "http://127.0.0.1:8080")
# Demo points at the local sink; the proxy forwards and the addon inspects it.
TELEMETRY = os.environ.get("APP_TELEMETRY", "http://127.0.0.1:9900/collect")

opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": PROXY})
)

body = b'{"event":"view","patient":"Test Identity","mrn":"MRN-X-999"}'
req = urllib.request.Request(TELEMETRY, data=body, headers={"Content-Type": "application/json"})
try:
    opener.open(req, timeout=5).read()
    print("leaky_app: sent PII to telemetry through proxy")
except Exception as e:
    print(f"leaky_app: {e}")
