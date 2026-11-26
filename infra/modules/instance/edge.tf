# The public entry (design §3.5): an internet-facing Application Load
# Balancer in the public subnets, HTTPS only with a FIPS TLS policy (TLS 1.2
# and 1.3, FIPS-validated ciphers), the ACM certificate for var.domain, and
# the WAF web ACL. Its targets are the gateway pods, registered by the load
# balancer controller's TargetGroupBinding (T-15) over HTTPS.
resource "aws_acm_certificate" "public" {
  domain_name       = var.domain
  validation_method = "DNS"
  key_algorithm     = "EC_prime256v1"
  options {
    certificate_transparency_logging_preference = "ENABLED"
  }
  tags = local.tags
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "certificate" {
  for_each = { for o in aws_acm_certificate.public.domain_validation_options : o.domain_name => o }
  zone_id  = aws_route53_zone.public.zone_id
  name     = each.value.resource_record_name
  type     = each.value.resource_record_type
  ttl      = 300
  records  = [each.value.resource_record_value]
}

resource "aws_acm_certificate_validation" "public" {
  certificate_arn         = aws_acm_certificate.public.arn
  validation_record_fqdns = [for r in aws_route53_record.certificate : r.fqdn]
}

resource "aws_lb" "public" {
  #checkov:skip=CKV_AWS_91:ALB access logs can only be delivered with SSE-S3, which the guardrails refuse (every bucket and upload is KMS, ADR-016); every request is logged by the WAF web ACL to CloudWatch Logs under the logs key instead (aws_wafv2_web_acl_logging_configuration.public).
  name                       = local.name
  internal                   = false
  load_balancer_type         = "application"
  ip_address_type            = "ipv4"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = [for z, _ in local.zones : aws_subnet.public[z].id]
  drop_invalid_header_fields = true
  desync_mitigation_mode     = "strictest"
  enable_deletion_protection = true
  enable_http2               = true
  tags                       = local.tags
}

resource "aws_lb_target_group" "gateway" {
  name                 = "${local.name}-gw"
  port                 = var.gateway_port
  protocol             = "HTTPS"
  protocol_version     = "HTTP1"
  target_type          = "ip"
  vpc_id               = aws_vpc.this.id
  deregistration_delay = 30
  health_check {
    enabled             = true
    protocol            = "HTTPS"
    path                = "/readyz"
    port                = "traffic-port"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
    timeout             = 5
  }
  tags = local.tags
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.public.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04"
  certificate_arn   = aws_acm_certificate_validation.public.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway.arn
  }
  tags = local.tags
}

# The web ACL: AWS managed rule groups (IP reputation, the common rule set,
# known bad inputs including Log4j, SQL injection) and a per-address rate
# limit. The common set's body-size rule counts instead of blocking: the
# platform takes uploads (imports up to 50 MiB, F-003, F-011, F-013) and
# limits their sizes itself. SQL injection counts until the sandbox apply
# (T-14) shows no false positives on risk documents' free text; the
# services use parameterized queries only. Anonymizers (Tor, anonymous
# proxies) are blocked; hosting providers' addresses only count, since
# customers' integrations push from their clouds (F-011).
locals {
  managed_rule_groups = [
    { name = "AWSManagedRulesAmazonIpReputationList", priority = 10, count_only = false, count_rules = [] },
    { name = "AWSManagedRulesCommonRuleSet", priority = 20, count_only = false, count_rules = ["SizeRestrictions_BODY"] },
    { name = "AWSManagedRulesSQLiRuleSet", priority = 40, count_only = true, count_rules = [] },
    { name = "AWSManagedRulesAnonymousIpList", priority = 45, count_only = false, count_rules = ["HostingProviderIPList"] },
  ]
}

resource "aws_wafv2_web_acl" "public" {
  name        = local.name
  description = "FAIR ${var.instance}: the public entry"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  dynamic "rule" {
    for_each = local.managed_rule_groups
    content {
      name     = rule.value.name
      priority = rule.value.priority
      override_action {
        dynamic "none" {
          for_each = rule.value.count_only ? [] : [1]
          content {}
        }
        dynamic "count" {
          for_each = rule.value.count_only ? [1] : []
          content {}
        }
      }
      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = rule.value.name
          dynamic "rule_action_override" {
            for_each = rule.value.count_rules
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-${rule.value.name}"
        sampled_requests_enabled   = true
      }
    }
  }

  # Known bad inputs (Log4j's JNDI lookups among them), blocking; written
  # out so policy checks see it.
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 30
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimitPerAddress"
    priority = 50
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-rate"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = local.name
    sampled_requests_enabled   = true
  }

  tags = local.tags
}

resource "aws_wafv2_web_acl_association" "public" {
  resource_arn = aws_lb.public.arn
  web_acl_arn  = aws_wafv2_web_acl.public.arn
}

# Every request, a year, under the logs key; credentials never logged
# (the session cookie and bearer tokens are redacted).
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.name}"
  kms_key_id        = aws_kms_key.home["logs"].arn
  retention_in_days = 365
  tags              = local.tags
}

resource "aws_cloudwatch_log_resource_policy" "waf" {
  policy_name = "${local.name}-waf-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WAFLogDelivery"
      Effect    = "Allow"
      Principal = { Service = "delivery.logs.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "${aws_cloudwatch_log_group.waf.arn}:*"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.acct }
        ArnLike      = { "aws:SourceArn" = "arn:${local.p}:logs:${var.region}:${local.acct}:*" }
      }
    }]
  })
}

resource "aws_wafv2_web_acl_logging_configuration" "public" {
  resource_arn            = aws_wafv2_web_acl.public.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}
