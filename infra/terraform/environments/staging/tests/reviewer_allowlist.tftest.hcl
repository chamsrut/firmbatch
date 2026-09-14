# The reviewer allow-list's Terraform validation, one refusal per rule (ADR 0011 decision 6).
# infra/terraform/policy/tests/test_cidr_allowlist.py runs the same cases through the
# independent Python check.
#
# Mocked AWS only, as in staging.tftest.hcl; every run targets the edge module with
# `command = plan`. The accepted ranges are globally routable test values chosen for this file;
# they are no reviewer's network.

mock_provider "aws" {
  override_during = plan

  mock_resource "aws_acm_certificate" {
    defaults = {
      arn = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-4000-8000-000000000001"
      domain_validation_options = [{
        domain_name           = "staging.app.synthetic.example"
        resource_record_name  = "_synthetic.staging.app.synthetic.example."
        resource_record_type  = "CNAME"
        resource_record_value = "_synthetic.acm-validations.aws."
      }]
    }
  }
}

mock_provider "aws" {
  alias           = "us_east_1"
  override_during = plan
}

variables {
  name_prefix                       = "firmbatch-staging"
  vpc_id                            = "vpc-synthetic"
  public_subnet_ids                 = ["subnet-synthetic-a", "subnet-synthetic-b"]
  alb_security_group_id             = "sg-synthetic-alb"
  route53_zone_id                   = "Z0SYNTHETIC00000000"
  app_hostname                      = "staging.app.synthetic.example"
  application_port                  = 8080
  web_api_health_check_path         = "/v1/health"
  identity_broker_health_check_path = "/auth/health"
  reviewer_cidrs                    = ["11.22.33.0/24", "11.22.34.128/25", "2a0f:ffff:1::/64"]
  reviewer_address_space_limit = {
    ipv4_addresses        = 512
    ipv6_slash64_networks = 1
  }
}

run "an_acceptable_list_is_accepted" {
  command = plan

  module {
    source = "../../modules/edge"
  }
}

run "an_empty_list_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = []
  }
  expect_failures = [var.reviewer_cidrs]
}

run "an_invalid_cidr_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["11.22.33.0"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "host_bits_are_refused_as_non_canonical" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["11.22.33.7/24"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "upper_case_ipv6_is_refused_as_non_canonical" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["2A0F:FFFF:1::/64"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "an_expanded_ipv6_form_is_refused_as_non_canonical" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["2a0f:ffff:0001:0000::/64"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "an_ipv4_range_broader_than_24_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["11.22.32.0/23"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "an_ipv6_range_broader_than_64_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["2a0f:ffff::/63"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "the_whole_internet_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["0.0.0.0/0"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "a_private_range_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["10.1.2.0/24"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "loopback_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["127.0.0.0/24"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "link_local_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["169.254.10.0/24"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "multicast_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["224.0.1.0/24"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "a_documentation_range_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["203.0.113.0/24"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "the_unspecified_address_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["0.0.0.0/32"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "ipv6_unique_local_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["fd00:1::/64"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "ipv6_link_local_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["fe80::/64"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "ipv6_documentation_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["2001:db8:1::/64"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "ipv6_unspecified_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["::/128"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "a_duplicate_entry_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["11.22.33.0/24", "11.22.33.0/24"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "an_overlapping_entry_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["11.22.33.0/24", "11.22.33.128/25"]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "more_than_sixteen_entries_are_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = [
      "11.22.33.1/32", "11.22.33.2/32", "11.22.33.3/32", "11.22.33.4/32", "11.22.33.5/32",
      "11.22.33.6/32", "11.22.33.7/32", "11.22.33.8/32", "11.22.33.9/32", "11.22.33.10/32",
      "11.22.33.11/32", "11.22.33.12/32", "11.22.33.13/32", "11.22.33.14/32", "11.22.33.15/32",
      "11.22.33.16/32", "11.22.33.17/32",
    ]
  }
  expect_failures = [var.reviewer_cidrs]
}

run "a_list_over_the_address_space_allowance_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_cidrs = ["11.22.33.0/24", "11.22.35.0/24"]
    reviewer_address_space_limit = {
      ipv4_addresses        = 256
      ipv6_slash64_networks = 0
    }
  }
  expect_failures = [var.reviewer_cidrs]
}

run "an_allowance_over_the_hard_ceiling_is_refused" {
  command = plan
  module {
    source = "../../modules/edge"
  }
  variables {
    reviewer_address_space_limit = {
      ipv4_addresses        = 8192
      ipv6_slash64_networks = 1
    }
  }
  expect_failures = [var.reviewer_address_space_limit]
}
