locals {
  raw_rules = yamldecode(file("firewall_rules.yaml"))
  rules     = { for r in local.raw_rules : r.name => r }
}

data "unifi_firewall_zone" "source" {
  for_each = local.rules
  name     = each.value.source
}

data "unifi_firewall_zone" "dest" {
  for_each = local.rules
  name     = each.value.destination
}

resource "unifi_firewall_policy" "rules" {
  for_each = local.rules

  name    = each.key
  enabled = lookup(each.value, "enabled", true)

  action {
    type                 = lookup(each.value, "action", "ALLOW")
    allow_return_traffic = lookup(each.value, "allow_return_traffic", true)
  }

  source {
    zone_id = data.unifi_firewall_zone.source[each.key].id
  }

  destination {
    zone_id = data.unifi_firewall_zone.dest[each.key].id
  }

  ip_protocol_scope {
    ip_version = "IPV4"
  }

  logging_enabled = lookup(each.value, "logging", false)
}
