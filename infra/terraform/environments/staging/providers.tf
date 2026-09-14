# The workload region (eu-central-1 recommended) is the default provider. The us-east-1 alias
# exists for the one globally required certificate -- the Cognito custom domain's -- and for
# nothing else while CloudFront is deferred.

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.expected_account_id]

  default_tags {
    tags = {
      "firmbatch:environment" = var.environment
      "firmbatch:managed-by"  = "terraform"
      "firmbatch:root"        = "environments/staging"
    }
  }
}

provider "aws" {
  alias               = "us_east_1"
  region              = "us-east-1"
  allowed_account_ids = [var.expected_account_id]

  default_tags {
    tags = {
      "firmbatch:environment" = var.environment
      "firmbatch:managed-by"  = "terraform"
      "firmbatch:root"        = "environments/staging"
    }
  }
}

# allowed_account_ids refuses the wrong account before any resource is evaluated; these
# postconditions state the same refusal in the plan. Every module receives local.account_id,
# which is this data source's value, so no resource is evaluated before it.
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
