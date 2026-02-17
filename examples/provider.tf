terraform {
  required_providers {
    unifi = {
      source  = "someniak/unifi"
      version = "0.0.3"
    }
  }
}

provider "unifi" {
  host     = var.unifi_host
  api_key  = var.unifi_api_key
  site_id  = var.unifi_site_id
  insecure = var.unifi_insecure
}

