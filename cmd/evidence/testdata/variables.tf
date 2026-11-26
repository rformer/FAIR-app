# The required checks for the evidence tests, in the shape of
# infra/github/variables.tf.
variable "required_checks" {
  description = "Status checks every change to main must pass."
  type        = list(string)
  default = [
    "test",
    "lint",
  ]
}
