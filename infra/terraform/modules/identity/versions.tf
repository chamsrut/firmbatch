terraform {
  required_version = "1.15.8"

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "6.64.0"
      configuration_aliases = [aws.us_east_1]
    }
  }
}
