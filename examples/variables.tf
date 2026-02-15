variable "unifi_host" {
  type        = string
  description = "The host URL of the UniFi controller"
}

variable "unifi_api_key" {
  type        = string
  description = "The API key for authentication"
  sensitive   = true
}

variable "unifi_site_id" {
  type        = string
  description = "The site ID in the UniFi controller"
  default     = "auto"
}

variable "unifi_insecure" {
  type        = bool
  description = "Whether to allow insecure TLS connections"
  default     = true
}
