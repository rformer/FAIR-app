output "buckets" {
  description = "The operations buckets: evidence, loki, tempo."
  value = {
    evidence = module.evidence.id
    loki     = module.loki.id
    tempo    = module.tempo.id
  }
}

output "evidence_object_lock" {
  description = "The evidence bucket's Object Lock retention."
  value       = module.evidence.object_lock
}

output "kms_key_arn" {
  description = "The operations storage key."
  value       = aws_kms_key.ops.arn
}
