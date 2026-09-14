"""Repository-owned policy checks for the Milestone 3.3b Terraform and delivery foundation.

Standard library only, so the Terraform-foundation gate runs wherever Python 3.11 does.
Every check here is independent of Terraform's own validation: a property that matters is
asserted twice, once by Terraform and once here, so that a mistake in one is caught by the
other.
"""
