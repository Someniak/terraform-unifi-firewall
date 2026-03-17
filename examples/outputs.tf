# Zone resource computed values
output "cameras_zone_id" {
  description = "ID of the custom Cameras zone"
  value       = unifi_firewall_zone.cameras.id
}

output "cameras_zone_origin" {
  description = "Origin of the Cameras zone (should be USER_DEFINED)"
  value       = unifi_firewall_zone.cameras.origin
}

output "servers_zone_network_ids" {
  description = "Network IDs assigned to the Servers zone"
  value       = unifi_firewall_zone.servers.network_ids
}

# Data source computed values
output "internal_zone_id" {
  description = "ID of the Internal zone from data source"
  value       = data.unifi_firewall_zone.default.id
}

output "testlan_network_id" {
  description = "ID of the TestLAN network"
  value       = data.unifi_network.testlan.id
}

output "testlan_vlan_id" {
  description = "VLAN ID of the TestLAN network"
  value       = data.unifi_network.testlan.vlan_id
}

output "testiot_vlan_id" {
  description = "VLAN ID of the TestIoT network"
  value       = data.unifi_network.testiot.vlan_id
}

# DNS policy computed values
output "a_record_id" {
  description = "ID of the A record DNS policy"
  value       = unifi_dns.test_a_record.id
}

output "default_ttl_value" {
  description = "Computed TTL when omitted from config"
  value       = unifi_dns.test_default_ttl.ttl
}

# Firewall policy computed values
output "basic_allow_rule_id" {
  description = "ID of the basic allow rule"
  value       = unifi_fw.allow_default_to_internet.id
}

# Fixed IP computed values
output "fixedip_id" {
  description = "Client ID of the fixed IP reservation"
  value       = unifi_fixedip.test_server.id
}
