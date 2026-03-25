# Vedetta

**Your network watchtower.** A free and open-source security monitoring platform for home users and small businesses.

Vedetta acts as a lightweight SIEM and network visibility tool that installs in a single Docker command, runs on a Raspberry Pi 4, and requires zero security expertise to operate. Users who opt in contribute anonymized telemetry to a community-powered threat intelligence network — the first such corpus built specifically from home and SMB network data.

## Quick Start

```bash
git clone https://github.com/vedetta-network/vedetta.git
cd vedetta
docker compose up
```

Dashboard: [http://localhost:3000](http://localhost:3000)
API: [http://localhost:8080/api/v1/status](http://localhost:8080/api/v1/status)

## Architecture

```
vedetta/
├── backend/          Go API server
├── frontend/         React + Tailwind dashboard
├── collector/        Fluent Bit log collection & normalization
├── telemetry/        Opt-in anonymized telemetry daemon
├── siem/             SIEM storage layer, schema, migrations
├── threat-network/   Central threat intelligence backend
├── docs/             Architecture & schema documentation
├── deploy/           Docker Compose, Helm (future)
└── docker-compose.yml
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Backend | 8080 | Go API — serves data and static frontend |
| Frontend | 3000 | React dashboard (nginx proxy to backend) |
| Collector | 5140/udp | Fluent Bit — ingests Pi-hole DNS logs and firewall syslog |
| Telemetry | — | Opt-in daemon — PII-stripped event batching to threat network |
| Threat Network | 9090 | Central threat intel backend |

## Hardware Requirements

- Raspberry Pi 4 (4 GB RAM, 32 GB storage) or better
- Docker and Docker Compose

## License

AGPLv3 — see [LICENSE](LICENSE) for details.
