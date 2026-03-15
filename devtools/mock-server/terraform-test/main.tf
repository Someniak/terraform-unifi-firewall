terraform {
  required_providers {
    unifi = {
      source  = "someniak/unifi"
      version = "0.5.1"
    }
  }
}

provider "unifi" {
  host     = "http://localhost:5100"
  api_key  = "mock-key"
  site_id  = "auto"
  insecure = true
}

# ---------- Data Sources ----------

data "unifi_firewall_zone" "lan" {
  name = "LAN"
}

data "unifi_firewall_zone" "wan" {
  name = "WAN"
}

data "unifi_firewall_zone" "guest" {
  name = "Guest"
}

data "unifi_network" "default" {
  name = "Default"
}

data "unifi_network" "guest" {
  name = "Guest"
}

# ---------- Firewall Policies ----------

resource "unifi_fw" "allow_lan_to_wan" {
  name    = "Allow LAN to WAN"
  enabled = true

  action {
    type = "ALLOW"
  }

  source {
    zone_id = data.unifi_firewall_zone.lan.id
  }

  destination {
    zone_id = data.unifi_firewall_zone.wan.id
  }

  ip_protocol_scope {
    ip_version = "IPV4_AND_IPV6"
  }

  logging_enabled = false
}

resource "unifi_fw" "block_guest_to_lan" {
  name    = "Block Guest to LAN"
  enabled = true

  action {
    type = "BLOCK"
  }

  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }

  destination {
    zone_id = data.unifi_firewall_zone.lan.id
  }

  ip_protocol_scope {
    ip_version = "IPV4"
  }

  logging_enabled = true
}

resource "unifi_fw" "allow_lan_https" {
  name        = "Allow LAN HTTPS"
  description = "Allow HTTPS traffic from LAN to WAN"
  enabled     = true

  action {
    type                 = "ALLOW"
    allow_return_traffic = true
  }

  source {
    zone_id = data.unifi_firewall_zone.lan.id
  }

  destination {
    zone_id = data.unifi_firewall_zone.wan.id

    traffic_filter {
      port_filter {
        items {
          type  = "PORT_NUMBER"
          value = 443
        }
      }
    }
  }

  ip_protocol_scope {
    ip_version = "IPV4"

    protocol_filter {
      type     = "PROTOCOL"
      protocol = "TCP"
    }
  }

  logging_enabled = false
}

# ---------- DNS Policies ----------

resource "unifi_dns" "local_override" {
  type       = "A_RECORD"
  domain     = "myapp.local"
  enabled    = true
  ttl        = 300
  ip_address = "192.168.1.100"
}

resource "unifi_dns" "cname_record" {
  type    = "CNAME_RECORD"
  domain  = "www.myapp.local"
  enabled = true
  ttl     = 600
  cname   = "myapp.local"
}

# ---------- Outputs ----------

output "lan_zone_id" {
  value = data.unifi_firewall_zone.lan.id
}

output "wan_zone_id" {
  value = data.unifi_firewall_zone.wan.id
}

output "default_network_id" {
  value = data.unifi_network.default.id
}
