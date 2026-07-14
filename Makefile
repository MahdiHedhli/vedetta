# Vedetta Development & SNR Validation Makefile
# Run `make help` for available targets.

.PHONY: help rebuild-backend up down logs clean-tokens \
        simulate-fp simulate-mid simulate-high simulate-mixed simulate-all \
        build-sensor install-sensor sensor-reset \
        test-backend test-sensor

help:
	@echo "Vedetta SNR Improvement Helpers"
	@echo ""
	@echo "Core:"
	@echo "  make rebuild-backend   - Rebuild + restart backend (picks up latest Go changes + recovery logic)"
	@echo "  make up                - Start all services"
	@echo "  make down              - Stop all"
	@echo "  make logs              - Tail backend logs"
	@echo "  make clean-tokens      - Revoke sensor credentials; retained IDs require bound reset codes"
	@echo ""
	@echo "Simulation (for SNR tier validation in Threats view):"
	@echo "  make simulate-fp       - Insert ~80 false-positive-like events (benign updates)"
	@echo "  make simulate-mid      - Insert ~40 mid-warning events (new/IoT + public DNS)"
	@echo "  make simulate-high     - Insert ~30 high-threat events (DGA/tunnel/rebind from new IoT)"
	@echo "  make simulate-mixed    - Balanced mix of all three"
	@echo "  make simulate-all      - Run all three scenarios"
	@echo "  make simulate-real     - Mixed scenario using the current local inventory for device context"
	@echo "  make simulate-real-enrich - Same + send through live Enricher for computed scores, boosts, and tags"
	@echo ""
	@echo "Sensor (native):"
	@echo "  make build-sensor      - Build fresh vedetta-sensor binary to /tmp/vedetta-sensor"
	@echo "  make install-sensor    - Build + sudo install to /usr/local/bin/vedetta-sensor (updates --reset etc.)"
	@echo "  make sensor-reset      - Run the installed sensor with --reset (clears token for re-registration)"
	@echo "  make enable-test-pcap  - Temporary bpf permission hack for real passive DNS testing (prints instructions)"
	@echo "  make start-real-sensor - Start privileged sensor with logging + auto health (use after enable-test-pcap)"
	@echo ""
	@echo "Testing:"
	@echo "  make test-backend      - Run Go tests in backend/"
	@echo "  make test-sensor       - Run Go tests in sensor/"

# --- Docker / Core ---

rebuild-backend:
	docker compose build backend
	docker compose up -d backend
	@echo "Backend rebuilt and restarted. The registration recovery logic is now active."

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f backend

clean-tokens:
	docker compose exec backend sh -c '
		sqlite3 /data/vedetta.db "
			UPDATE api_tokens SET revoked = 1 WHERE scope = \"sensor\" AND revoked = 0;
			UPDATE sensors SET status = \"offline\";
		" && echo "Sensor credentials revoked; identities retained. Use admin-minted reset codes to reconnect existing sensor IDs."
	'

# --- Simulation (inserts into events table for fast UI/SNR testing) ---

SIM := scripts/simulate/simulate

# Build the simulator for the linux/arm64 (or amd64) backend container with CGO_ENABLED=1
# (required for go-sqlite3). Uses the same golang:1.22-alpine + gcc/musl env as the backend builder
# so that -real-context works and produces a fully functional binary that can query the current
# local inventory and insert synthetic test events. Matches the running container platform.
$(SIM): scripts/simulate/main.go
	docker run --rm \
		-v $(CURDIR)/scripts/simulate:/src \
		-w /src \
		golang:1.22-alpine \
		sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o /src/simulate .'

simulate-fp: $(SIM)
	docker cp $(SIM) vedetta-backend:/tmp/simulate
	docker compose exec backend /tmp/simulate -db /data/vedetta.db -count 80 -scenario false_positive
	@echo "false_positive events inserted. Check Threats view (low scores, easily suppressed)."

simulate-mid: $(SIM)
	docker cp $(SIM) vedetta-backend:/tmp/simulate
	docker compose exec backend /tmp/simulate -db /data/vedetta.db -count 40 -scenario mid_warning
	@echo "mid_warning events inserted. Should show moderate scores + device context tags."

simulate-high: $(SIM)
	docker cp $(SIM) vedetta-backend:/tmp/simulate
	docker compose exec backend /tmp/simulate -db /data/vedetta.db -count 30 -scenario high_threat
	@echo "high_threat events inserted. Should score high, especially with new_device / IoT context boosts."

simulate-mixed: $(SIM)
	docker cp $(SIM) vedetta-backend:/tmp/simulate
	docker compose exec backend /tmp/simulate -db /data/vedetta.db -count 100 -scenario mixed
	@echo "Mixed scenario inserted. Good general test set."

simulate-all: simulate-fp simulate-mid simulate-high
	@echo "All SNR test tiers loaded."

# Inventory-context simulation: uses the operator's current local inventory to add
# realistic device context to synthetic events. No inventory data is embedded here.
# This exercises context boosts, quick suppression, and UI filters.
simulate-real: $(SIM)
	docker cp $(SIM) vedetta-backend:/tmp/simulate
	docker compose exec backend /tmp/simulate -db /data/vedetta.db -count 50 -scenario mixed -real-context
	@echo "Synthetic mixed events inserted using the current local inventory for context."
	@echo "Useful for validating device context display, SNR filters, and suppression UX."

# Real-context + full Enricher pipeline: sends events through /api/v1/ingest so the live Enricher computes
# anomaly scores, tags, boosts, and threat descriptions using the current local inventory.
# This produces high-quality scored test data that exercises the entire detection stack (DGA/Beacon/Tunnel/etc + context).
simulate-real-enrich: $(SIM)
	docker cp $(SIM) vedetta-backend:/tmp/simulate
	@echo "Cleaning old simulation test events to keep DB lean for validation..."
	@docker compose exec -T backend sqlite3 /data/vedetta.db "DELETE FROM events WHERE dns_source = 'simulation' AND timestamp < datetime('now', '-2 hours');" 2>/dev/null || true
	docker compose exec backend /tmp/simulate -db /data/vedetta.db -count 30 -scenario mixed -real-context -enrich
	@echo "Inventory-context events sent through the live Enricher for computed scores and boosts."
	@echo "Old test events cleaned; check Threats view and the enriched SNR summary in 'make collection-health' for FP/power validation."

# Robust SQL-based seeding (avoids cgo cross-compile issues with the Go simulator)
seed-snr:
	docker cp scripts/seed-snr-validation.sql vedetta-backend:/tmp/seed-snr.sql
	docker compose exec -T backend sh -c 'sqlite3 /data/vedetta.db < /tmp/seed-snr.sql'
	@frontend_port="$$(./scripts/resolve-host-port.sh VEDETTA_FRONTEND_PORT 3107)" && \
		echo "SNR validation tiers (false_positive / mid_warning / high_threat) seeded. Open http://localhost:$${frontend_port} and filter by context or severity."

# Show current SNR validation data (run after make seed-snr)
# Usage: make show-snr
show-snr:
	@echo "=== SNR Validation Data (run 'make seed-snr' first if empty) ==="
	docker compose exec -T backend sqlite3 /data/vedetta.db < scripts/seed-snr-validation.sql 2>/dev/null | tail -20 || echo "Run: docker compose exec -T backend sqlite3 /data/vedetta.db 'SELECT COUNT(*), ROUND(AVG(anomaly_score),2) FROM events WHERE source_hash LIKE \"sim-%\";'"
	@frontend_port="$$(./scripts/resolve-host-port.sh VEDETTA_FRONTEND_PORT 3107)" && \
		echo "Then open http://localhost:$${frontend_port} and explore the Threats view with the seeded data."

# --- Native Sensor ---

build-sensor:
	cd sensor && go build -o /tmp/vedetta-sensor ./cmd/vedetta-sensor
	@echo "Fresh sensor binary at /tmp/vedetta-sensor (includes --reset). Copy or use 'make install-sensor'."

install-sensor: build-sensor
	sudo cp /tmp/vedetta-sensor /usr/local/bin/vedetta-sensor
	sudo chmod +x /usr/local/bin/vedetta-sensor
	@echo "vedetta-sensor installed to /usr/local/bin. Run with --reset or via the LaunchDaemon/systemd from sensor/deploy/install.sh"

sensor-reset:
	@if [ -x /usr/local/bin/vedetta-sensor ]; then \
		sudo /usr/local/bin/vedetta-sensor --reset; \
	else \
		echo "No installed binary found. Run 'make install-sensor' first."; \
	fi

# Live network capture for local SNR validation (requires sudo for packet capture).
# Use --print-capture-plan to select interfaces for the current host.
sensor-recommend:
	@backend_port="$$(./scripts/resolve-host-port.sh VEDETTA_BACKEND_PORT 8080)" && \
		/tmp/vedetta-sensor --print-capture-plan --core "http://localhost:$${backend_port}"

start-real-capture:
	@set -e; \
		backend_port="$$(./scripts/resolve-host-port.sh VEDETTA_BACKEND_PORT 8080)"; \
		frontend_port="$$(./scripts/resolve-host-port.sh VEDETTA_FRONTEND_PORT 3107)"; \
		echo "=== Starting real sensor capture for SNR validation ==="; \
		echo "Using /tmp/vedetta-sensor (run 'make build-sensor' first if needed)"; \
		echo "This will capture passive DNS + device discovery on your LAN and push to Core."; \
		echo "It requires sudo for packet capture."; \
		echo ""; \
		echo "Recommended command (copy-paste in another terminal):"; \
		echo "  sudo /tmp/vedetta-sensor --core http://localhost:$${backend_port}"; \
		echo ""; \
		echo "Or with explicit interfaces (from --print-capture-plan):"; \
		echo "  sudo /tmp/vedetta-sensor --core http://localhost:$${backend_port} --dns-iface en0 --passive-iface en0"; \
		echo ""; \
		echo "Use --reset first if auth token is stale: sudo /tmp/vedetta-sensor --reset"; \
		echo "Then monitor with: make show-snr  (or watch the Threats view at http://localhost:$${frontend_port})"; \
		echo "To stop: Ctrl-C or pkill vedetta-sensor"

# Quick status for collection health (after sensor is running)
collection-health:
	@docker cp scripts/db-health.sql vedetta-backend:/tmp/db-health.sql 2>/dev/null || true
	@docker compose exec -T backend sh -c 'if [ -f /tmp/db-health.sql ]; then sqlite3 /data/vedetta.db < /tmp/db-health.sql; else cat scripts/db-health.sql | sqlite3 /data/vedetta.db; fi' 2>/dev/null || echo "Run: docker compose exec -T backend sqlite3 /data/vedetta.db < scripts/db-health.sql"
	@echo ""
	@docker compose exec -T backend sqlite3 /data/vedetta.db "SELECT 'Device baseline last update: ' || MAX(last_seen) FROM devices;" 2>/dev/null || echo "Device baseline last update: (could not query)"
	@echo "    (use API for exact age in hours + live/frozen status; see /status collection_health)"
	@echo ""
	@backend_port="$$(./scripts/resolve-host-port.sh VEDETTA_BACKEND_PORT 8080)" && \
		echo "=== For live beacon_tracked_pairs + device stats + baseline age use: curl -s http://localhost:$${backend_port}/api/v1/status | jq '.collection_health' (or python one-liner)"
	@echo "    (includes last_device_update + device_baseline_age_hours to confirm current live vs historical device baseline context)"

# --- Tests ---

test-backend:
	cd backend && go test ./...

test-sensor:
	cd sensor && go test ./...

# Quick health check
status:
	@set -e; \
		backend_port="$$(./scripts/resolve-host-port.sh VEDETTA_BACKEND_PORT 8080)"; \
		frontend_port="$$(./scripts/resolve-host-port.sh VEDETTA_FRONTEND_PORT 3107)"; \
		echo "Dashboard: http://localhost:$${frontend_port}"; \
		echo "Core API:  http://localhost:$${backend_port}"
	@docker compose ps

# Install sensor as privileged macOS LaunchDaemon (recommended for persistent real capture)
# This sets up the sensor to run as root on boot and capture on your LAN.
install-macos-service:
	@echo "==> Installing Vedetta Sensor as macOS LaunchDaemon for real data collection"
	@if [ -z "$(CORE_URL)" ]; then \
		echo "Usage: make install-macos-service CORE_URL=https://vedetta.example.com"; \
		echo "Same-host install: use the Core API URL printed by scripts/gen-env.sh."; \
		exit 1; \
	fi
	@sudo sensor/deploy/install.sh --core "$(CORE_URL)"
	@echo "==> Service installed. Use 'sudo launchctl list | grep vedetta' and 'sudo tail -f /var/log/vedetta-sensor.log' to monitor."

# Temporary hack to allow non-root pcap on macOS for quick real-data testing (INSECURE - reverts on reboot)
# Use this to test passive DNS capture without the full LaunchDaemon.
enable-test-pcap:
	@echo "WARNING: This sets 666 permissions on /dev/bpf* so the current user can capture packets."
	@echo "This is a temporary testing hack only. It is INSECURE and should not be left enabled."
	@echo "Reboot or manually chmod 600 /dev/bpf* to revert."
	@if sudo -n chmod 666 /dev/bpf* 2>/dev/null; then \
		echo "BPF devices are now world-readable (via sudo -n). You can now run the sensor without sudo for real capture."; \
		echo ""; \
		echo "Recommended: start the sensor like this (in this or another terminal):"; \
		echo "  make start-real-sensor"; \
		echo ""; \
		echo "Monitor collected data with: make collection-health"; \
		echo "When done testing, revert with: sudo chmod 600 /dev/bpf*"; \
	else \
		echo "Cannot auto chmod (no passwordless sudo or non-interactive)."; \
		echo "Please run this manually in your terminal (it will prompt for sudo):"; \
		echo "  sudo chmod 666 /dev/bpf*"; \
		echo ""; \
		echo "A non-privileged sensor may already be running for device discovery (ps aux | grep vedetta-sensor)."; \
		echo "After chmod, stop it first if present:"; \
		echo "  pkill vedetta-sensor || true"; \
		echo "Then start the (now privileged) sensor for full passive DNS + devices:"; \
		echo "  make start-real-sensor"; \
		echo "Monitor with: make collection-health"; \
		echo "Revert when done: sudo chmod 600 /dev/bpf*"; \
		exit 0; \
	fi

# Convenience target to (re)start the privileged sensor with logging
# Run this after 'make enable-test-pcap' (or manual chmod 666 /dev/bpf*) to capture real passive DNS
start-real-sensor:
	@if [ ! -x /tmp/vedetta-sensor ]; then \
		echo "Error: /tmp/vedetta-sensor not found or not executable."; \
		echo "Run 'make build-sensor' or 'make install-sensor' first (or copy the binary)."; \
		exit 1; \
	fi
	@echo "Stopping any existing sensor process..."
	@pkill -f vedetta-sensor || true
	@echo "Starting privileged sensor (full passive DNS + device discovery) with logging..."
	@set -e; backend_port="$$(./scripts/resolve-host-port.sh VEDETTA_BACKEND_PORT 8080)"; \
		nohup /tmp/vedetta-sensor --core "http://localhost:$${backend_port}" > /tmp/vedetta-sensor.log 2>&1 &
	@echo "Sensor started in background."
	@echo ""
	@echo "Quick device context snapshot:"
	@docker compose exec -T backend sqlite3 /data/vedetta.db \
		'SELECT "Total: " || COUNT(*) || "  |  IoT: " || SUM(segment="iot") || "  |  New<48h: " || SUM(first_seen > datetime("now","-48 hours")) FROM devices;' \
		2>/dev/null || echo "(could not query device stats yet)"
	@echo ""
	@echo "Full health: make collection-health"
	@echo "Live logs: tail -f /tmp/vedetta-sensor.log"
	@echo ""
	@echo "Stop when done: pkill -f vedetta-sensor"
	@echo "Revert perms (recommended): sudo chmod 600 /dev/bpf*"
