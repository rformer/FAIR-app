output "config_recorder" {
  description = "The Config recorder's name."
  value       = aws_config_configuration_recorder.this.name
}
