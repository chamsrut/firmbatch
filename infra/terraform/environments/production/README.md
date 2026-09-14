# Production — placeholder

Production is **not created by Milestone 3**, and nothing in this repository plans, applies or
deploys it.

When it exists (Milestone 8), it is a **separate Terraform root, a separate AWS account and a
separate state key** — never a Terraform workspace of the staging root, never the staging
account, and never the staging state bucket's `staging/` key (ADR 0011 decision 8). Its public
hostnames, its delivery environments and roles, its OIDC trust and its cost estimate are
Milestone 8's decisions. The customer portal stays same-origin with the API whatever hostnames
Milestone 8 chooses (ADR 0011 decision 3).

This directory deliberately holds no `.tf` file; `infra/terraform/policy/check.py` refuses one.
