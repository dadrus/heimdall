output "buckets" {
  description = "Buckets requested by AP 3. No bucket is created with the default flags."
  value       = module.storage.buckets
}
