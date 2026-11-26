output "buckets" {
  description = "The operations buckets (evidence, loki, tempo)."
  value       = module.observability.buckets
}
