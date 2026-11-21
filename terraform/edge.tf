# Domain 3 Task 3.1 (network edge): a regional AWS WAF web ACL with the Core
# Rule Set and a rate-based rule. It is not associated with an Application
# Load Balancer, API Gateway, or CloudFront distribution, so it would not
# inspect traffic even if this lab were applied. Shield Standard is automatic
# for qualifying AWS resources and is not a Terraform resource. Shield
# Advanced is a paid subscription and is not enabled here.

resource "aws_wafv2_web_acl" "edge" {
  name        = "${var.name_prefix}-edge"
  description = "Study web ACL: AWS Managed Rules Core Rule Set plus a rate-based rule. Not associated with a resource."
  scope       = "REGIONAL"
  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimitByIP"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitByIP"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-edge"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = local.waf_log_group_name
  retention_in_days = 365
  kms_key_id        = aws_kms_key.infra_logs.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "edge" {
  resource_arn            = aws_wafv2_web_acl.edge.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
}
