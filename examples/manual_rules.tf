data "unifi_firewall_zone" "home" {
  name = "Home"
}

data "unifi_firewall_zone" "mgmt" {
  name = "Management"
}

data "unifi_firewall_zone" "external" {
  name = "External"
}

resource "unifi_firewall_policy" "allow_home_to_mgmt" {
  name    = "Allow Home to Management"
  enabled = true

  action {
    type                 = "ALLOW"
    allow_return_traffic = true
  }
  source {
    zone_id = data.unifi_firewall_zone.home.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.mgmt.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

resource "unifi_firewall_policy" "allow_social" {
  name    = "Allow Social Media"
  enabled = true

  action {
    type                 = "ALLOW"
    allow_return_traffic = false
  }

  source {
    zone_id = data.unifi_firewall_zone.mgmt.id
  }

  destination {
    zone_id = data.unifi_firewall_zone.external.id
    traffic_filter {
      type = "DOMAIN"
      domain_filter {
        items = ["google.com", "facebook.com"]
      }
    }
  }

  ip_protocol_scope {
    ip_version = "IPV4"
  }

  logging_enabled = true
}
