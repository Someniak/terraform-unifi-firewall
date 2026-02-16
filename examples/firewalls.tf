# Example: Advanced Port Filtering with Ranges
resource "unifi_firewall_policy" "advanced_ports" {
  name            = "Advanced Port Filter"
  enabled         = true
  logging_enabled = true

  action = {
    type                 = "ALLOW"
    allow_return_traffic = true
  }

  ip_protocol_scope = {
    ip_version = "IPV4_AND_IPV6"
  }

  source = {
    zone_id = data.unifi_firewall_zone.internal_dmz.id
  }

  destination = {
    zone_id = data.unifi_firewall_zone.staging.id
    traffic_filter = {
      type = "PORT"
      port_filter = {
        type = "PORTS"
        items = [
          {
            type  = "PORT_NUMBER"
            value = 443
          },
          {
            type  = "PORT_NUMBER_RANGE"
            start = 8080
            stop  = 8085
          }
        ]
      }
    }
  }
}

# Example: Network Filtering with Additional MAC check
resource "unifi_firewall_policy" "network_with_mac" {
  name            = "Network and MAC Filter"
  enabled         = true
  logging_enabled = true

  action = {
    type                 = "BLOCK"
    allow_return_traffic = false
  }

  source = {
    zone_id = data.unifi_firewall_zone.internal_dmz.id
    traffic_filter = {
      type = "NETWORK"
      network_filter = {
        items = ["network-uuid-here"] # Example network ID
      }
      mac_address = "00:aa:bb:cc:dd:ee" # Additional MAC filter
    }
  }

  destination = {
    zone_id = data.unifi_firewall_zone.dmz.id
  }

  ip_protocol_scope = {
    ip_version = "IPV4"
  }
}
