# pii-mitm-leak-proxy — segregated entry points.
PY ?= python3
IMAGE ?= pii-mitm-leak-proxy
PORT ?= 8899

.PHONY: help doctor test live sink clean docker-build docker-run

help:
	@echo "doctor        validate install (python, files, optional mitmproxy)"
	@echo "test          deterministic detector self-test (no mitmproxy needed)"
	@echo "live          end-to-end demo through mitmdump (requires mitmproxy)"
	@echo "docker-build  build the container image"
	@echo "docker-run    run the proxy container on :\$$(PORT) (profile.json + ./out)"
	@echo "clean         remove findings + __pycache__"

doctor:
	@$(PY) doctor.py

test:
	@$(PY) test/selftest.py

# Live demo: sink + proxy(addon) + leaky app over HTTP. Needs mitmproxy.
live:
	@command -v mitmdump >/dev/null 2>&1 || { echo "mitmproxy not installed: pipx install mitmproxy"; exit 2; }
	@$(PY) mock/sink.py & echo $$! > /tmp/pii_sink.pid; sleep 1
	@PROFILE=profile.demo.json PII_OUT=findings.json mitmdump -q -s addon.py --listen-port $(PORT) & echo $$! > /tmp/pii_proxy.pid; sleep 2
	@APP_PROXY=http://127.0.0.1:$(PORT) $(PY) mock/leaky_app.py; sleep 1
	@kill `cat /tmp/pii_proxy.pid` `cat /tmp/pii_sink.pid` 2>/dev/null || true
	@echo "--- findings.json ---"; cat findings.json 2>/dev/null || echo "(none)"

docker-build:
	@docker build -t $(IMAGE) .

# Needs a local profile.json; writes findings to ./out. CA persists in a volume.
docker-run:
	@test -f profile.json || { echo "profile.json missing (copy profile.example.json)"; exit 2; }
	@mkdir -p out
	@docker run --rm -p $(PORT):$(PORT) -e LISTEN_PORT=$(PORT) \
		-v "$(PWD)/profile.json:/app/profile.json:ro" \
		-v "$(PWD)/out:/data" \
		-v pii_mitm_ca:/root/.mitmproxy \
		$(IMAGE)

clean:
	@rm -f findings.json; find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "cleaned"
