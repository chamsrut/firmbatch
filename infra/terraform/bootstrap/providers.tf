provider "aws" {
  region = var.region

  # The provider refuses to read or change anything in any other account, before a single
  # resource is evaluated.
  allowed_account_ids = [var.expected_account_id]

  default_tags {
    tags = {
      "firmbatch:environment" = var.environment
      "firmbatch:managed-by"  = "terraform"
      "firmbatch:root"        = "bootstrap"
    }
  }
}

# A second, independent account and region check. allowed_account_ids stops the provider;
# these postconditions make the same mismatch explicit in the plan. Every resource below
# derives its ARNs from local.account_id, so none is evaluated before this data source.
data "aws_caller_identity" "current" {
  lifecycle {
    postcondition {
      condition     = self.account_id == var.expected_account_id
      error_message = "The AWS credentials belong to an account other than expected_account_id; refusing to plan."
    }
  }
}

data "aws_region" "current" {
  lifecycle {
    postcondition {
      condition     = self.region == var.region
      error_message = "The provider's region differs from var.region; refusing to plan."
    }
  }
}
