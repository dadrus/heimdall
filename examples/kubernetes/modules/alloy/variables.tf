variable "namespace" {
  type        = string
  description = "Namespace to install alloy into"
}

variable "cluster_name" {
  type        = string
  description = "The name of the cluster (used to add as a label)"
}

variable "loki_endpoint" {
  type        = string
  description = "The endpoint of loki to write the logs to"
}

variable "prometheus_endpoint" {
  type        = string
  description = "The endpoint of prometheus to write the metrics to"
}

variable "otel_traces_endpoint" {
  type        = string
  description = "The endpoint of an OTEL endpoint to send traces to"
}
