#!/usr/bin/env bash
#
# The Terraform and delivery foundation's static checks (Milestone 3.3b, ADR 0012).
#
# scripts/verify-repository.sh runs this as ONE gate; it also runs on its own, from anywhere:
#
#   bash infra/terraform/scripts/static-checks.sh
#
# In order: the pinned Terraform version; the independent policy checks -- including the check
# that every Terraform test mocks every provider configuration its root declares, which runs
# BEFORE any `terraform test`; the policy and delivery unit tests; `terraform fmt -check
# -recursive`; and, for each root, `init -backend=false -lockfile=readonly`, `validate` and
# `test` against mocked providers.
#
# It makes no AWS API call. Every AWS_* variable is removed, the shared config and credential
# files point at /dev/null and instance metadata is disabled, so no step could find credentials
# even by mistake. The one network access is `terraform init` fetching the pinned provider from
# the Terraform Registry when a root's .terraform directory does not already hold it.
#
# It fails, and never skips: a missing or different Terraform fails the gate, because an unrun
# check reports the same green as a passing one.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd -P)"
TF_DIR="${REPO_ROOT}/infra/terraform"

# --- no credential and no injected argument survives into any step ------------------------
for name in $(compgen -e); do
  case "${name}" in
    AWS_* | TF_CLI_ARGS* | TF_WORKSPACE | TF_VAR_*) unset "${name}" ;;
  esac
done
export AWS_EC2_METADATA_DISABLED=true
export AWS_CONFIG_FILE=/dev/null
export AWS_SHARED_CREDENTIALS_FILE=/dev/null
export CHECKPOINT_DISABLE=1
export TF_IN_AUTOMATION=1
export TF_INPUT=0

fail() {
  printf 'static-checks: %s\n' "$1" >&2
  exit 1
}

step() {
  local label="$1" out summary
  shift
  if ! out="$("$@" 2>&1)"; then
    printf '%s\n' "${out}" | tail -n 40 >&2
    fail "${label} failed"
  fi
  # The tool's own result line -- "Ran N tests", "Success! N passed, 0 failed.", "policy: ..." --
  # so a passing run still says how much it ran.
  summary="$(printf '%s\n' "${out}" | grep -E '^(Ran [0-9]+ tests|Success!|policy: )' | tail -n 1 || true)"
  printf 'static-checks: %s: ok%s\n' "${label}" "${summary:+ -- ${summary}}"
}

# --- the pinned Terraform, or nothing ---------------------------------------------------------
pinned="$(tr -d '[:space:]' < "${TF_DIR}/.terraform-version")"
command -v terraform >/dev/null 2>&1 \
  || fail "terraform is not installed; install exactly ${pinned} (infra/terraform/.terraform-version)"
installed="$(terraform version -json | python3 -c 'import json, sys; print(json.load(sys.stdin)["terraform_version"])')"
[ "${installed}" = "${pinned}" ] \
  || fail "terraform ${installed} is installed; exactly ${pinned} is required (infra/terraform/.terraform-version)"

cd -- "${REPO_ROOT}"

step "policy checks (structure, mocked-provider reach, workflows, container, readiness)" \
  python3 infra/terraform/policy/check.py
step "policy unit tests" \
  python3 -m unittest discover -s infra/terraform/policy/tests -t infra/terraform
step "delivery unit tests" \
  python3 -m unittest discover -s infra/delivery/tests
step "terraform fmt -check -recursive" \
  terraform -chdir="${TF_DIR}" fmt -check -recursive

for root in bootstrap artifacts environments/staging; do
  step "${root}: init -backend=false -lockfile=readonly" \
    terraform -chdir="${TF_DIR}/${root}" init -backend=false -lockfile=readonly -input=false -no-color
  # -no-tests: `terraform test` below validates and runs the test files itself. Validating them
  # here as well simulates a teardown that needs a provider configuration a module under test
  # only receives through configuration_aliases, and fails for that reason alone.
  step "${root}: validate" \
    terraform -chdir="${TF_DIR}/${root}" validate -no-tests -no-color
  step "${root}: test against mocked providers" \
    terraform -chdir="${TF_DIR}/${root}" test -no-color
done

printf 'static-checks: all Terraform and delivery foundation checks passed\n'
