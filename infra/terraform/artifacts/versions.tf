# The artifacts root: the canonical release registry and the release-record bucket (ADR 0012
# decision 13 -- build once, promote by digest). The release key and the artifact-publish identity
# are the bootstrap root's, applied before this one.
#
# Applied by a human with short-lived AWS credentials -- an assumed role through AWS SSO with
# MFA -- and never by any GitHub workflow. No pipeline role can reach this root's state: the
# staging plan and apply roles are confined to staging/terraform.tfstate, and artifact-publish
# holds no state permission at all. See ../runbooks/bootstrap.md, part 2.
terraform {
  required_version = "1.15.8"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.64.0"
    }
  }

  # Partial configuration, like the bootstrap root: `bucket`, `region` and `kms_key_id` come from
  # a -backend-config file kept outside the repository. The registry account's own state bucket,
  # under this root's own key.
  backend "s3" {
    key          = "artifacts/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
