# UniFi Firewall Policy Schema Reference

This document provides a detailed breakdown of the `unifi_firewall_policy` resource structure, including all attributes and nested blocks.

## Resource: `unifi_firewall_policy`

The `unifi_firewall_policy` resource allows you to define firewall rules in UniFi.

### Root Attributes

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | The name of the firewall policy. |
| `enabled` | boolean | No | Whether the policy is active. Default: `true`. |
| `description` | string | No | A description of the policy. |
| `logging_enabled` | boolean | No | Whether traffic matching this policy should be logged. |

### Block: `action` (Required)

Defines what happens when traffic matches the policy.

- `type` (string, Required): Action to take. Values: `ALLOW`, `BLOCK`, `REJECT`.
- `allow_return_traffic` (boolean, No): Whether to automatically allow response traffic for established connections.

### Block: `ip_protocol_scope` (Required)

Defines the IP versions and protocols this policy applies to.

- `ip_version` (string, Required): The IP protocol version. Values: `IPV4`, `IPV6`, `IPV4_AND_IPV6`.
- `protocol_filter` (Block, No):
  - `type` (string, No): Values: `NAMED_PROTOCOL`, `PROTOCOL_NUMBER`.
  - `match_opposite` (boolean, No): If true, matches everything *except* the specified protocol.
  - `protocol` (string, No): The protocol name (e.g., `TCP`, `UDP`, `ICMP`) or number if type is `PROTOCOL_NUMBER`.

---

### Blocks: `source` and `destination` (Required)

Define where the traffic comes from and where it is going. Both blocks have the same internal structure.

- `zone_id` (string, Required): The UUID of the firewall zone (e.g., Internal DMZ, External).

#### Sub-Block: `traffic_filter` (Optional)

Used for granular filtering. If omitted, matches all traffic for the specified zone.

- `type` (string, No): The primary filter type. Values: `PORT`, `NETWORK`, `MAC_ADDRESS`, `IP_ADDRESS`, `DOMAIN` (dest only).
- `mac_address` (string, No): An **additional** MAC address filter that can be applied to other filter types (like `PORT` or `NETWORK`).

##### Nested Block: `port_filter`
Requires `type = "PORT"`.
- `type` (string, No): Default: `PORTS`.
- `match_opposite` (boolean, No): If true, matches all ports *except* the ones listed.
- `items` (List of Objects, No):
  - `type` (string, Required): `PORT_NUMBER` or `PORT_NUMBER_RANGE`.
  - `value` (int, No): For `PORT_NUMBER`.
  - `start` (int, No): For `PORT_NUMBER_RANGE`.
  - `stop` (int, No): For `PORT_NUMBER_RANGE`.

##### Nested Block: `ip_address_filter`
Requires `type = "IP_ADDRESS"`.
- `type` (string, No): Default: `ADDRESSES`.
- `match_opposite` (boolean, No): If true, matches all IPs *except* the ones listed.
- `items` (List of strings, No): List of IP addresses or CDR ranges.

##### Nested Block: `network_filter`
Requires `type = "NETWORK"`.
- `type` (string, No): Default: `NETWORKS`.
- `match_opposite` (boolean, No): If true, matches all networks *except* the ones listed.
- `items` (List of strings, No): List of Network UUIDs.

##### Nested Block: `mac_address_filter`
Requires `type = "MAC_ADDRESS"`.
- `type` (string, No): Default: `MAC_ADDRESSES`.
- `match_opposite` (boolean, No): If true, matches all MACs *except* the ones listed.
- `items` (List of strings, No): List of MAC addresses.

##### Nested Block: `domain_filter` (Destination only)
Requires `type = "DOMAIN"`.
- `items` (List of strings, No): List of domain names.

---

## Detailed Example

```hcl
resource "unifi_firewall_policy" "example" {
  name = "Detailed Example Policy"

  action = {
    type = "ALLOW"
  }

  ip_protocol_scope = {
    ip_version = "IPV4_AND_IPV6"
  }

  source = {
    zone_id = data.unifi_firewall_zone.lan.id
    traffic_filter = {
      type = "NETWORK"
      network_filter = {
        items = [data.unifi_network.primary.id]
      }
      # Also only allow this specific device by MAC
      mac_address = "00:11:22:33:44:55"
    }
  }

  destination = {
    zone_id = "External" # Internet
    traffic_filter = {
      type = "PORT"
      port_filter = {
        items = [
          { type = "PORT_NUMBER", value = 80 },
          { type = "PORT_NUMBER", value = 443 },
          { type = "PORT_NUMBER_RANGE", start = 1024, stop = 2048 }
        ]
      }
    }
  }
}
```
