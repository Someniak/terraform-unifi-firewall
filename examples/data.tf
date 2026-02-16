data "unifi_firewall_zone" "staging" {
  name = "Staging"
}

data "unifi_firewall_zone" "server" {
  name = "Server"
}

data "unifi_firewall_zone" "dmz" {
  name = "DMZ"
}

data "unifi_firewall_zone" "storage" {
  name = "Storage"
}

data "unifi_firewall_zone" "management" {
  name = "Management"
}

data "unifi_firewall_zone" "internal_dmz" {
  name = "Internal-DMZ"
}
