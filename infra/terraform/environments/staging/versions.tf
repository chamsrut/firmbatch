# The staging root: the whole protected staging topology, composed from the eight modules.
# Separate root, separate state key, separate account; no Terraform workspaces (ADR 0011
# decision 8).
#
# NOT OPERATIONAL. It cannot be planned for real until M3.3c's programs, dependencies and
# image have passed review (runtime_contract_reviewed), and nothing in M3.3b plans or applies
# it. Applying it is M3.3d's, after a reviewed plan, a current cost estimate and explicit human
# authorization.
terraform {
  required_version = "1.15.8"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.64.0"
    }
  }

  # Partial configuration: `bucket`, `region` and `kms_key_id` come from -backend-config.
  # The key is this root's own and matches local.state_key, which the IAM policies name.
  backend "s3" {
    key          = "staging/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
