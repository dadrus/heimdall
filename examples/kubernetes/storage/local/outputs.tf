output "buckets" {
  description = "Only enabled buckets; Job completion is a dependency of this output."
  value       = var.buckets
  depends_on  = [kubernetes_job_v1.bucket]
}
