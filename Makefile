.PHONY: run scan

# Start (or restart) the dev server on port 8080
run:
	@echo "Starting dev server on :8080 ..."
	@lsof -ti:8080 | xargs -r kill 2>/dev/null || true
	uv run python main.py

# Scan a single target: make scan TARGET=example.com
scan:
	@test -n "$(TARGET)" || (echo "Usage: make scan TARGET=example.com" && exit 1)
	curl -s http://localhost:8080/v1/scan \
		-H 'Content-Type: application/json' \
		-d '{"targets": ["$(TARGET)"]}' | python3 -m json.tool
