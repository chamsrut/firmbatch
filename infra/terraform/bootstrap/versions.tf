# The bootstrap root: the Terraform state bucket and the separate saved-plan bucket, their KMS
# keys and the release key, the account's GitHub OIDC provider, and every delivery identity it
# federates -- the staging plan and apply roles, the artifact-publish role, their policies and
# permissions boundaries (ADR 0011 decisions 8 and 9; ADR 0012 decision 5).
#
# Applied by a human with short-lived AWS credentials -- an assumed role through AWS SSO with
# MFA -- and never by the GitHub pipeline it bootstraps. See ../runbooks/bootstrap.md.
terraform {
  required_version = "1.15.8"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.64.0"
    }
  }

  # Partial configuration. `bucket`, `region` and `kms_key_id` are supplied with
  # `-backend-config` from a file kept outside the repository. The very first apply cannot use
  # this backend, because the bucket it names does not exist yet: the runbook applies once
  # against a temporary, git-ignored local override and then moves the state here with
  # `terraform init -migrate-state`. Its own key, never shared with any environment root.
  backend "s3" {
    key          = "bootstrap/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
