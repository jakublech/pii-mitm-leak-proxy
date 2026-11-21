# pii-mitm-leak-proxy — MITM PII-leak detector as a container.
# The image bundles a pinned mitmproxy + the addon; the client routes the app's
# egress through it (http(s)_proxy) and trusts the mitmproxy CA in the TEST env.
FROM python:3.12-slim

# Pinned so the interception layer is reproducible across engagements.
RUN pip install --no-cache-dir "mitmproxy>=11,<12"

WORKDIR /app
# Only the generic tooling — no profiles/findings (those are gitignored and
# mounted at runtime). .dockerignore keeps client data out of the image.
COPY detector.py addon.py doctor.py ./

# Profile is provided by the client at runtime (mount or env); findings are
# written to a mounted volume so nothing sensitive stays in the image layer.
ENV PROFILE=/app/profile.json \
    PII_OUT=/data/findings.json

# mitmproxy CA lives here; mount it as a volume so the SAME CA persists across
# restarts (the client trusts it once in the test environment).
VOLUME ["/root/.mitmproxy", "/data"]

EXPOSE 8080

# Long-running proxy (not the demo). Override the flags via `docker run ... args`.
ENTRYPOINT ["mitmdump", "-s", "addon.py"]
CMD ["--listen-host", "0.0.0.0", "--listen-port", "8080"]
