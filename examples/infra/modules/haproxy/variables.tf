variable "namespace" {
  type        = string
  description = "Namespace to install emissary into"
}

variable "global_integration_enabled" {
  type = bool
  description = "How integration with heimdall happens (global or not)"
}