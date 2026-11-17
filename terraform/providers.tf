# This lab is offline-first. With offline_plan = true (the default), the
# provider skips every call it would normally make at configure time, and
# scripts/offline-plan.sh points all AWS endpoints at a closed local port so
# no request can leave the machine. Nothing here has been applied.
provider "aws" {
  region = var.region

  skip_credentials_validation = var.offline_plan
  skip_requesting_account_id  = var.offline_plan
  skip_metadata_api_check     = var.offline_plan
  skip_region_validation      = var.offline_plan

  default_tags {
    tags = {
      Project     = var.name_prefix
      Environment = "lab"
      ManagedBy   = "terraform"
      CostCenter  = "study"
    }
  }
}
