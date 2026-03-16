# Fixed IP (DHCP Reservation)
# Assigns a static IP to a known client device by MAC address.
data "unifi_network" "testlan" {
  name = "TestLAN"
}

resource "unifi_fixedip" "test_server" {
  mac        = "00:11:22:33:44:55"
  network_id = data.unifi_network.testlan.id
  fixed_ip   = "192.168.10.50"
  name       = "Fake Test Server"
}
