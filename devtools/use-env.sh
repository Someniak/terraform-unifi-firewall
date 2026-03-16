#!/usr/bin/env bash
#
# Source this script to configure Terraform for a specific backend.
#
# Usage:
#   source devtools/use-env.sh mock          # mock API server
#   source devtools/use-env.sh integration   # Docker UniFi instance
#
# Then run: cd examples && terraform plan

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

case "${1:-}" in
  mock)
    ENV_FILE="$SCRIPT_DIR/mock-server/.env"
    ;;
  integration)
    ENV_FILE="$SCRIPT_DIR/integration/.env"
    ;;
  *)
    echo "Usage: source devtools/use-env.sh [mock|integration]"
    return 1 2>/dev/null || exit 1
    ;;
esac

if [ ! -f "$ENV_FILE" ]; then
  echo "Error: $ENV_FILE not found"
  return 1 2>/dev/null || exit 1
fi

# Clear previous auth vars
unset TF_VAR_unifi_api_key TF_VAR_unifi_username TF_VAR_unifi_password 2>/dev/null || true

# Load .env and export as TF_VAR_* variables
while IFS='=' read -r key value; do
  # Skip empty lines and comments
  [[ -z "$key" || "$key" =~ ^# ]] && continue
  # Strip whitespace
  key=$(echo "$key" | xargs)
  value=$(echo "$value" | xargs)
  # Convert UNIFI_HOST -> TF_VAR_unifi_host
  tf_var="TF_VAR_$(echo "$key" | tr '[:upper:]' '[:lower:]')"
  export "$tf_var=$value"
done < "$ENV_FILE"

# Set dev_overrides so terraform skips registry
export TF_CLI_CONFIG_FILE="$REPO_ROOT/examples/dev_overrides.tfrc"

echo "Loaded: $ENV_FILE"
echo "Backend: ${1}"
env | grep TF_VAR_ | sort
echo ""
echo "Ready. Run: cd examples && terraform plan"
