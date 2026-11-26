output "dns_delegation" {
  description = "What the instance pipeline needs (infra/instance var.dns; organization root var.dns_delegation)."
  value = {
    account_id        = var.account_id
    zone_id           = aws_route53_zone.parent.zone_id
    domain            = var.domain
    read_role_arn     = aws_iam_role.read.arn
    delegate_role_arn = aws_iam_role.delegate.arn
  }
}

output "registrar" {
  description = "For the registrar, once at bootstrap: the zone's name servers and DS record."
  value = {
    name_servers = aws_route53_zone.parent.name_servers
    ds_record    = aws_route53_key_signing_key.parent.ds_record
  }
}

output "policy_documents" {
  description = "The roles' trust and permission policies (the tests read them)."
  value = {
    "trust/read"     = local.trust.read
    "trust/delegate" = local.trust.delegate
    "role/read"      = local.policy.read
    "role/delegate"  = local.policy.delegate
  }
}
