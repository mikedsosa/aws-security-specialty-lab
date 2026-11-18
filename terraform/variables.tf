variable "offline_plan" {
  description = "Skip provider calls that need real credentials. Keep true for this lab."
  type        = bool
  default     = true
}

variable "region" {
  description = "Home Region for the lab."
  type        = string
  default     = "us-east-1"
}

variable "replica_region" {
  description = "Second Region for trail bucket replication. Default is already in allowed_regions."
  type        = string
  default     = "us-west-2"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "scs-lab"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.name_prefix))
    error_message = "name_prefix must be 3-21 lowercase letters, digits or hyphens."
  }
}

variable "management_account_id" {
  description = "Organization management account. Placeholder only; this lab owns no real account."
  type        = string
  default     = "111122223333"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "Account IDs are 12 digits."
  }
}

variable "security_account_id" {
  description = "Delegated administrator / log reader account. Placeholder only."
  type        = string
  default     = "444455556666"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.security_account_id))
    error_message = "Account IDs are 12 digits."
  }
}

variable "organization_id" {
  description = "Organization ID. Placeholder only."
  type        = string
  default     = "o-exampleorg1"

  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "Organization IDs look like o-xxxxxxxxxx."
  }
}

variable "guardrail_target_ids" {
  description = "Root, OU or account IDs to attach the SCP and RCP to. Empty means create the policies but attach nothing."
  type        = list(string)
  default     = []
}

variable "allowed_regions" {
  description = "Regions member accounts may use. Everything else is denied by the region SCP statement."
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}

variable "break_glass_role_name" {
  description = "Role name exempted from the protective SCP statements. It must exist in each member account and be tightly controlled."
  type        = string
  default     = "BreakGlassAdmin"
}

variable "key_admin_role_name" {
  description = "Role in the management account that administers (but cannot use) the CloudTrail KMS key."
  type        = string
  default     = "KeyAdmin"
}

variable "deployer_role_name" {
  description = "Role that runs Terraform. It is a key administrator so the key policy does not lock it out."
  type        = string
  default     = "TerraformDeployer"
}

variable "log_reader_role_name" {
  description = "Role in the security account that may decrypt and read CloudTrail logs."
  type        = string
  default     = "SecurityLogReader"
}

variable "trail_name" {
  description = "Organization trail name."
  type        = string
  default     = "scs-lab-org-trail"
}

variable "remediation_exempt_buckets" {
  description = "Bucket names the auto-remediation Lambda must not touch (for example a deliberate public website bucket)."
  type        = list(string)
  default     = []
}

variable "remediation_dry_run" {
  description = "When true, the Lambda logs what it would do and changes nothing."
  type        = bool
  default     = false
}

variable "enable_detection_services" {
  description = "Create GuardDuty and Security Hub CSPM resources. Both are paid services after any trial period."
  type        = bool
  default     = true
}
