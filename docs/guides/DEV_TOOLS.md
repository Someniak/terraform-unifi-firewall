# Mock UniFi API Server

A Flask-based mock of the UniFi Network API with a live web dashboard for testing the Terraform provider locally.

## Setup

```bash
cd devtools/mock-server
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

## Run

```bash
python server.py
```

- API: http://localhost:5100
- Dashboard: http://localhost:5100/ui
- API key: any non-empty string

Use `--debug` for Flask auto-reload during development.

## Test with Terraform

Terminal 1 — start the mock server:

```bash
cd devtools/mock-server
source .venv/bin/activate
python server.py
```

Terminal 2 — build and run against the mock:

```bash
make build
cd examples
export TF_CLI_CONFIG_FILE=dev_overrides.tfrc
terraform plan
terraform apply -auto-approve
```

Watch the dashboard at http://localhost:5100/ui to see resources appear in realtime.
