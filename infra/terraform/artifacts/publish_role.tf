# The identities this root names, and the proof that they already exist (ADR 0012 decision 5).
#
# artifact-publish and the release readers -- the staging plan and apply roles -- are created by the
# bootstrap root, never here. This root names them in its repository and record-bucket policies, and
# a resource policy must never name a principal that does not exist yet. So this root reads each
# role before planning anything that names it, and refuses unless artifact-publish is the exact role,
# under its publication-only boundary, trusting exactly this repository's artifact-publish
# environment. A missing role fails the read, and the plan with it.

data "aws_iam_role" "artifact_publish" {
  name = split("/", var.artifact_publish_role_arn)[1]

  lifecycle {
    postcondition {
      condition     = self.arn == var.artifact_publish_role_arn
      error_message = "artifact_publish_role_arn does not name an existing role; apply the bootstrap root first."
    }

    postcondition {
      condition     = self.permissions_boundary == "${replace(var.artifact_publish_role_arn, ":role/", ":policy/")}-boundary"
      error_message = "artifact-publish is not under its publication-only permissions boundary; refusing to name it."
    }

    postcondition {
      condition = try(
        length(jsondecode(self.assume_role_policy).Statement) == 1 &&
        jsondecode(self.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:chamsrut/firmbatch:environment:artifact-publish" &&
        jsondecode(self.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com",
        false
      )
      error_message = "artifact-publish does not trust exactly this repository's artifact-publish environment; refusing to name it."
    }
  }
}

data "aws_iam_role" "release_readers" {
  for_each = toset(var.release_reader_role_arns)

  name = split("/", each.value)[1]
}
