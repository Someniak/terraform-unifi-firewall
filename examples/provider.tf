terraform {
  required_providers {
    unifi = {
      source = "someniak/unifi"
      # version not needed for local dev — use dev_overrides.tfrc
    }
  }
}

provider "unifi" {
  host     = var.unifi_host
  api_key  = var.unifi_api_key
  username = var.unifi_username
  password = var.unifi_password
  site_id  = var.unifi_site_id
  insecure = var.unifi_insecure
}

