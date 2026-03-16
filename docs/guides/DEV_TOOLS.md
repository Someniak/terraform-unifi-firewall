# Development & Testing Guide

This provider supports two authentication methods and two test backends. This guide covers how to set up and use each combination.

## Authentication Methods

| Method | Provider Fields | When to Use |
|--------|----------------|-------------|
| **API Key** | `api_key` | UniFi OS hardware (Cloud Key, Dream Machine) and the mock server |
| **Username / Password** | `username` + `password` | Self-hosted UniFi Network Application (Docker, bare metal) |

These are mutually exclusive — provide one or the other, not both.

```hcl
# API Key auth
provider "unifi" {
  host     = "https://192.168.1.1/proxy/network/integration"
  api_key  = "your-api-key"
  site_id  = "auto"
  insecure = true
}

# Username / Password auth
provider "unifi" {
  host     = "https://localhost:8443"
  username = "admin"
  password = "testpassword123"
  site_id  = "auto"
  insecure = true
}
```

---

## Test Backends

### 1. Mock API Server (fast, no Docker needed)

A Flask-based mock with a live web dashboard. Accepts both auth methods. Best for rapid development iteration.

**One-time setup:**

```bash
cd devtools/mock-server
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

**Run:**

```bash
# Terminal 1 — start the mock server
cd devtools/mock-server
source .venv/bin/activate
python server.py            # --debug for auto-reload

# Terminal 2 — build and test
make build
source devtools/use-env.sh mock
cd examples
terraform plan
terraform apply -auto-approve
```

- API: http://localhost:5100
- Dashboard: http://localhost:5100/ui (live updates via SSE)
- Auth: `api_key = "mock-key"`

### 2. Integration Environment (real UniFi API, Docker)

A Docker-based UniFi Network Application + MongoDB. Tests against the real API to catch issues the mock can't.

Self-hosted UniFi **does not support API keys** — this environment uses username/password auth.

**Start:**

```bash
make integration-up         # ~2 min on first run
```

This starts the containers, seeds an admin user, and creates test networks.

**Run:**

```bash
make build
source devtools/use-env.sh integration
cd examples
terraform plan
terraform apply -auto-approve
```

**Teardown:**

```bash
make integration-down       # stops containers, removes volumes
```

**Default credentials:**

| Setting  | Value                    |
|----------|--------------------------|
| URL      | `https://localhost:8443` |
| Username | `admin`                  |
| Password | `testpassword123`        |
| Site     | `default`                |

**Test networks created by setup:**

| Name      | VLAN | Subnet          |
|-----------|------|-----------------|
| TestLAN   | 10   | 192.168.10.0/24 |
| TestIoT   | 20   | 192.168.20.0/24 |
| TestGuest | 30   | 192.168.30.0/24 |

---

## Switching Backends

```bash
source devtools/use-env.sh mock          # API key auth → mock server
source devtools/use-env.sh integration   # username/password → Docker UniFi
```

This script:
- Loads the `.env` from the selected backend
- Exports `TF_VAR_*` variables for Terraform
- Sets `TF_CLI_CONFIG_FILE` for dev overrides (skips registry)
- Clears previous auth variables so they don't conflict

**Mock `.env` (`devtools/mock-server/.env`):**
```env
UNIFI_HOST=http://localhost:5100
UNIFI_API_KEY=mock-key
UNIFI_SITE_ID=auto
UNIFI_INSECURE=true
```

**Integration `.env` (`devtools/integration/.env`):**
```env
UNIFI_HOST=https://localhost:8443
UNIFI_USERNAME=admin
UNIFI_PASSWORD=testpassword123
UNIFI_SITE_ID=default
UNIFI_INSECURE=true
```

---

## Troubleshooting

**Integration login fails** — Complete the setup wizard manually at https://localhost:8443 with the default credentials, then re-run `make integration-up`.

**UniFi slow to start** — First boot takes 2-3 minutes. The setup script waits up to ~7.5 minutes.

**Port conflicts** — Edit `devtools/integration/docker-compose.yml` to change host ports.

**Start fresh** — `make integration-down && make integration-up`

---

## File Layout

```
devtools/
├── use-env.sh                  # Switch between backends
├── mock-server/
│   ├── .env                    # Mock connection vars (API key)
│   ├── server.py               # Flask mock API + dashboard
│   └── requirements.txt
└── integration/
    ├── .env                    # Integration connection vars (gitignored)
    ├── docker-compose.yml      # UniFi + MongoDB containers
    ├── init-mongo.js           # MongoDB user creation (first boot)
    ├── setup.sh                # Bootstrap: seed admin, create networks
    └── teardown.sh             # Stop containers, remove volumes
```
