# Internal TLS (design §3.5): an ACM Private CA of the instance's own
# (keys in FIPS 140-2 Level 3 HSMs) that cert-manager's AWS Private CA
# issuer (T-15) uses for the services' certificates. Short-lived mode:
# certificates last at most seven days, so no revocation list is published
# (nothing public, nothing to serve).
resource "aws_acmpca_certificate_authority" "internal" {
  count                           = local.live ? 1 : 0
  type                            = "ROOT"
  usage_mode                      = "SHORT_LIVED_CERTIFICATE"
  key_storage_security_standard   = "FIPS_140_2_LEVEL_3_OR_HIGHER"
  permanent_deletion_time_in_days = 30
  enabled                         = true

  certificate_authority_configuration {
    key_algorithm     = "EC_prime256v1"
    signing_algorithm = "SHA256WITHECDSA"
    subject {
      common_name         = "FAIR ${var.instance} internal CA"
      organization        = "FAIR"
      organizational_unit = var.instance
    }
  }

  revocation_configuration {
    crl_configuration {
      enabled = false
    }
    ocsp_configuration {
      enabled = false
    }
  }

  tags = local.tags
}

resource "aws_acmpca_certificate" "internal_root" {
  count                       = local.live ? 1 : 0
  certificate_authority_arn   = aws_acmpca_certificate_authority.internal[0].arn
  certificate_signing_request = aws_acmpca_certificate_authority.internal[0].certificate_signing_request
  signing_algorithm           = "SHA256WITHECDSA"
  template_arn                = "arn:${local.p}:acm-pca:::template/RootCACertificate/V1"
  validity {
    type  = "YEARS"
    value = 10
  }
}

resource "aws_acmpca_certificate_authority_certificate" "internal" {
  count                     = local.live ? 1 : 0
  certificate_authority_arn = aws_acmpca_certificate_authority.internal[0].arn
  certificate               = aws_acmpca_certificate.internal_root[0].certificate
  certificate_chain         = aws_acmpca_certificate.internal_root[0].certificate_chain
}
