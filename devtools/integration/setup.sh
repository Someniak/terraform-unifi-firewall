#!/usr/bin/env bash
#
# Bootstrap script for the UniFi integration test environment.
#
# This script:
#   1. Waits for the UniFi Network Application to become ready
#   2. Seeds MongoDB with an admin user + default site (bypasses wizard)
#   3. Restarts UniFi so it picks up the seeded data
#   4. Logs in via the legacy API and creates test networks
#   5. Outputs connection info and instructions for API key generation
#
# Default credentials:
#   Admin:    admin / testpassword123
#   MongoDB:  unifi / unifitestpass
#   URL:      https://localhost:8443

set -euo pipefail
cd "$(dirname "$0")"

ADMIN_USER="admin"
ADMIN_PASS="testpassword123"
ADMIN_EMAIL="admin@test.local"
MONGO_USER="unifi"
MONGO_PASS="unifitestpass"
UNIFI_URL="https://localhost:8443"
COOKIE_FILE=$(mktemp)

cleanup() {
    rm -f "$COOKIE_FILE"
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

wait_for_url() {
    local url="$1"
    local desc="$2"
    local max_attempts="${3:-60}"
    local attempt=0

    log "Waiting for $desc..."
    while [ $attempt -lt $max_attempts ]; do
        if curl -ks --max-time 5 "$url" > /dev/null 2>&1; then
            log "$desc is ready."
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 5
    done
    log "ERROR: $desc did not become ready after $((max_attempts * 5))s"
    return 1
}

wait_for_mongo() {
    local max_attempts=30
    local attempt=0

    log "Waiting for MongoDB..."
    while [ $attempt -lt $max_attempts ]; do
        if docker exec unifi-db mongosh --quiet --username "$MONGO_USER" --password "$MONGO_PASS" \
            --authenticationDatabase admin --eval "db.runCommand({ping:1})" > /dev/null 2>&1; then
            log "MongoDB is ready."
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    log "ERROR: MongoDB did not become ready"
    return 1
}

api_call() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"

    local args=(-ks -X "$method" -b "$COOKIE_FILE" -c "$COOKIE_FILE"
                -H "Content-Type: application/json")
    if [ -n "$data" ]; then
        args+=(-d "$data")
    fi

    curl "${args[@]}" "${UNIFI_URL}${endpoint}"
}

# --------------------------------------------------------------------------
# Step 1: Wait for containers
# --------------------------------------------------------------------------

log "=== UniFi Integration Environment Setup ==="
log ""

wait_for_mongo

# Wait for UniFi to start (it takes a while on first boot)
wait_for_url "$UNIFI_URL/status" "UniFi Network Application" 90

# --------------------------------------------------------------------------
# Step 2: Seed MongoDB (bypass setup wizard)
# --------------------------------------------------------------------------

log "Checking if admin user already exists..."
ADMIN_EXISTS=$(docker exec unifi-db mongosh --quiet --username "$MONGO_USER" --password "$MONGO_PASS" \
    --authenticationDatabase admin unifi --eval "db.admin.countDocuments({name:'$ADMIN_USER'})" 2>/dev/null || echo "0")

if [ "$ADMIN_EXISTS" = "0" ]; then
    log "Seeding MongoDB with admin user and default site..."

    # Generate SHA-512 password hash
    PASS_HASH=$(python3 -c "
import crypt
print(crypt.crypt('$ADMIN_PASS', '\$6\$rounds=656000\$unifisalt'))
")

    # Seed the database: site + admin + privilege
    docker exec unifi-db mongosh --quiet --username "$MONGO_USER" --password "$MONGO_PASS" \
        --authenticationDatabase admin unifi --eval "
        // Create the default site if it doesn't exist
        if (db.site.countDocuments({attr_hidden_id: 'default'}) === 0) {
            db.site.insertOne({
                name: 'Default',
                desc: 'Default',
                attr_hidden_id: 'default',
                attr_no_delete: true
            });
            print('Created default site');
        }

        // Create the admin user
        var siteDoc = db.site.findOne({attr_hidden_id: 'default'});
        db.admin.insertOne({
            name: '$ADMIN_USER',
            email: '$ADMIN_EMAIL',
            x_shadow: '$PASS_HASH',
            last_site_name: 'default',
            time_created: NumberLong(Math.floor(Date.now() / 1000))
        });
        print('Created admin user');

        // Grant admin privileges on the default site
        var adminDoc = db.admin.findOne({name: '$ADMIN_USER'});
        db.privilege.insertOne({
            admin_id: adminDoc._id.str,
            site_id: siteDoc._id.str,
            role: 'admin',
            permissions: []
        });
        print('Granted admin privileges');
    "

    log "MongoDB seeded. Restarting UniFi to pick up changes..."
    docker restart unifi
    sleep 5
    wait_for_url "$UNIFI_URL/status" "UniFi Network Application (post-restart)" 90
else
    log "Admin user already exists, skipping seed."
fi

# --------------------------------------------------------------------------
# Step 3: Log in via legacy API
# --------------------------------------------------------------------------

log "Logging in as $ADMIN_USER..."
LOGIN_RESULT=$(api_call POST "/api/login" "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")

if echo "$LOGIN_RESULT" | grep -q '"ok":true'; then
    log "Login successful."
else
    log "WARNING: Login may have failed. Response: $LOGIN_RESULT"
    log "The setup wizard may need to be completed manually at: $UNIFI_URL"
    log ""
    log "If the wizard appears, complete it with:"
    log "  Username: $ADMIN_USER"
    log "  Password: $ADMIN_PASS"
    log ""
    log "Then re-run this script."
    exit 1
fi

# --------------------------------------------------------------------------
# Step 4: Create test networks
# --------------------------------------------------------------------------

log "Checking existing networks..."
NETWORKS=$(api_call GET "/api/s/default/rest/networkconf")

create_network() {
    local name="$1"
    local purpose="$2"
    local subnet="$3"
    local vlan="$4"

    if echo "$NETWORKS" | grep -q "\"name\":\"$name\""; then
        log "Network '$name' already exists, skipping."
        return
    fi

    log "Creating network: $name (VLAN $vlan, $subnet)..."
    api_call POST "/api/s/default/rest/networkconf" "{
        \"name\": \"$name\",
        \"purpose\": \"$purpose\",
        \"ip_subnet\": \"$subnet\",
        \"vlan\": $vlan,
        \"vlan_enabled\": true,
        \"dhcpd_enabled\": true,
        \"dhcpd_start\": \"$(echo $subnet | sed 's|0/24|100|')\",
        \"dhcpd_stop\": \"$(echo $subnet | sed 's|0/24|200|')\",
        \"enabled\": true
    }" > /dev/null
}

create_network "TestLAN"  "corporate" "192.168.10.0/24" 10
create_network "TestIoT"  "corporate" "192.168.20.0/24" 20
create_network "TestGuest" "guest"    "192.168.30.0/24" 30

# --------------------------------------------------------------------------
# Step 5: Output connection info
# --------------------------------------------------------------------------

log ""
log "=== Setup Complete ==="
log ""
log "UniFi Network Application: $UNIFI_URL"
log "Admin credentials:         $ADMIN_USER / $ADMIN_PASS"
log ""
log "--- API Key Setup (one-time manual step) ---"
log ""
log "1. Open $UNIFI_URL in your browser"
log "2. Log in with: $ADMIN_USER / $ADMIN_PASS"
log "3. Go to: Settings > System > Advanced"
log "4. Look for 'Integrations' or 'API' section"
log "5. Generate a new API key"
log "6. Save it to devtools/integration/.env as:"
log ""
log "   UNIFI_HOST=$UNIFI_URL"
log "   UNIFI_API_KEY=<your-api-key>"
log "   UNIFI_SITE_ID=default"
log "   UNIFI_INSECURE=true"
log ""

# Write partial .env (user fills in API key)
cat > .env <<EOF
UNIFI_HOST=$UNIFI_URL
UNIFI_API_KEY=
UNIFI_SITE_ID=default
UNIFI_INSECURE=true
EOF

log "A partial .env file has been written to devtools/integration/.env"
log "Fill in the UNIFI_API_KEY after generating it in the UI."
