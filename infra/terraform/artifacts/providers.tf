provider "aws" {
  region = var.region

  # The provider refuses to read or change anything in any other account, before a single
  # resource is evaluated.
  allowed_account_ids = [var.expected_account_id]

  default_tags {
    tags = {
      "firmbatch:scope"      = "release-artifacts"
      "firmbatch:managed-by" = "terraform"
      "firmbatch:root"       = "artifacts"
    }
  }
}

# A second, independent account and region check, as in the other roots.
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
