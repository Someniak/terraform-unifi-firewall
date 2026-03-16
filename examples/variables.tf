variable "unifi_host" {
  type        = string
  description = "The host URL of the UniFi controller"
}

variable "unifi_api_key" {
  type        = string
  description = "The API key for authentication (use this OR username+password)"
  sensitive   = true
  default     = null
}

variable "unifi_username" {
  type        = string
  description = "Username for legacy cookie-based auth (use this OR api_key)"
  default     = null
}

variable "unifi_password" {
  type        = string
  description = "Password for legacy cookie-based auth"
  sensitive   = true
  default     = null
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

variable "iot_network_id" {
  type        = string
  description = "Network ID of the IoT network (for network filter examples)"
  default     = ""
}
