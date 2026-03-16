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
  site_id  = var.unifi_site_id
  insecure = var.unifi_insecure
}

