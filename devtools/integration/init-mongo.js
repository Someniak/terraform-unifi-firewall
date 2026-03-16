// Create the UniFi database user with required roles.
// This script runs automatically on first MongoDB startup.
db.getSiblingDB("admin").createUser({
  user: "unifi",
  pwd: "unifitestpass",
  roles: [
    { db: "admin", role: "dbOwner" },
    { db: "unifi", role: "dbOwner" },
    { db: "unifi_stat", role: "dbOwner" },
  ],
});
