# The staging plan and apply roles' permissions and permissions boundaries, and the artifact-publish role's
# permissions and boundary (ADR 0012 decisions 5, 13 and 15). Each delivery identity has exactly one inline
# policy and one boundary, both here; infra/terraform/policy/check.py refuses any other policy, attachment or
# policy form that could reach one of them.
#
# These are least-privilege SCAFFOLDING, scoped to the accepted staging resource families. The
# exact action lists are refined against the first real saved plan in M3.3d; nothing here has
# been exercised against AWS. Where an action's resource-level or condition-key support is
# uncertain, the grant still names the exact resource: a wrong scope fails closed, never open.
#
# A PERMISSIONS BOUNDARY ADMITS; IT DOES NOT SUBTRACT. Each boundary's Allow statements are its
# ceiling, and an action outside them is outside the role whatever its own policy grants. The apply
# boundary's ceiling names the staging service families, three release-verification reads on the one
# release repository, the IAM reads refresh needs, and iam:PassRole on exactly the ten pre-created
# workload roles to ecs-tasks.amazonaws.com -- so no IAM create, update, delete, attach, detach,
# policy-version, trust-policy or boundary change is ever inside it. Its Deny statements then narrow
# services the ceiling admits. Each names the actions it denies; the two that use NotAction deny only
# requests outside the staging and certificate regions, which infra/terraform/policy/check.py proves
# by evaluating the boundary against representative staging requests.
#
# WHAT IAM CANNOT BOUND. No IAM condition can limit what a trust policy says, what value a secret
# update carries, or which image, command and secret references a task definition names. So trust
# anchors -- every IAM role, policy and boundary, the OIDC provider, KMS keys, secret containers and
# values, the release registry and every bucket -- are a human's; plan-summary --mode apply refuses a
# saved plan that changes one; and task-definition revisions and the two services are the pipeline's
# inside the delivery contract, which plan-summary checks at plan and again before apply.

locals {
  # State access shared by both staging roles: the one state key and its lockfile, nothing else.
  state_statements = [
    {
      Sid       = "ListOnlyThisStateKey"
      Effect    = "Allow"
      Action    = "s3:ListBucket"
      Resource  = local.state_bucket_arn
      Condition = { StringEquals = { "s3:prefix" = [local.state_key, "${local.state_key}.tflock"] } }
    },
    {
      Sid      = "NativeS3LockfileForThisStateKeyOnly"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
      Resource = local.lock_object_arn
    },
    {
      Sid      = "UseTheStateKey"
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
      Resource = aws_kms_key.state.arn
    },
  ]
}

# ------------------------------------------------------------------ plan role

resource "aws_iam_role_policy" "github_plan" {
  name = "plan"
  role = aws_iam_role.github_plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(local.state_statements, [
      {
        Sid      = "ReadStateOnly"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = local.state_object_arn
      },
      {
        Sid      = "CreateNewSavedPlanObjects"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = local.environment_plans_arn
      },
      {
        Sid      = "EncryptSavedPlans"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Encrypt"]
        Resource = aws_kms_key.plans.arn
      },
      {
        # Refresh reads. Read-oriented: describe, list and get of configuration, never secret
        # values, object contents, log events or Cognito users.
        Sid    = "RefreshStagingResourceFamilies"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity",
          "ec2:Describe*",
          "elasticloadbalancing:Describe*",
          "acm:DescribeCertificate", "acm:ListTagsForCertificate",
          "route53:GetHostedZone", "route53:ListResourceRecordSets", "route53:GetChange", "route53:ListTagsForResource",
          "ecs:DescribeClusters", "ecs:DescribeServices", "ecs:DescribeTaskDefinition", "ecs:ListTagsForResource",
          "rds:DescribeDBInstances", "rds:DescribeDBSubnetGroups", "rds:DescribeDBParameterGroups", "rds:DescribeDBParameters", "rds:ListTagsForResource",
          "secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy",
          "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListResourceTags", "kms:ListAliases",
          "cognito-idp:DescribeUserPool", "cognito-idp:DescribeUserPoolClient", "cognito-idp:DescribeUserPoolDomain",
          "cognito-idp:GetUserPoolMfaConfig", "cognito-idp:DescribeManagedLoginBranding", "cognito-idp:DescribeManagedLoginBrandingByClient",
          "cognito-idp:GetWebACLForResource", "cognito-idp:ListTagsForResource",
          "wafv2:GetWebACL", "wafv2:GetIPSet", "wafv2:GetWebACLForResource", "wafv2:ListTagsForResource",
          "logs:DescribeLogGroups", "logs:ListTagsForResource",
          "cloudwatch:DescribeAlarms", "cloudwatch:ListTagsForResource",
          "sns:GetTopicAttributes", "sns:GetSubscriptionAttributes", "sns:ListTagsForResource",
          "budgets:ViewBudget", "budgets:ListTagsForResource",
          "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags",
          "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:GetOpenIDConnectProvider",
        ]
        Resource = "*"
      },
      {
        # Promotion by digest: the plan job resolves the release record's digest in the canonical
        # repository -- never a tag -- and reads the scan result the admission policy needs.
        Sid      = "VerifyReleaseImagesByDigest"
        Effect   = "Allow"
        Action   = ["ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:DescribeImageScanFindings"]
        Resource = local.release_repository_arn
      },
      {
        Sid      = "ReadReleaseManifests"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = local.release_manifest_objects_arn
      },
      {
        Sid       = "DecryptReleaseManifestsThroughS3"
        Effect    = "Allow"
        Action    = "kms:Decrypt"
        Resource  = aws_kms_key.release.arn
        Condition = { StringEquals = { "kms:ViaService" = "s3.${var.artifact_registry_region}.amazonaws.com" } }
      },
      {
        Sid    = "NeverReadSecretsOrPlansPushImagesOrApply"
        Effect = "Deny"
        Action = [
          "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue", "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecret",
          "s3:GetObjectVersion", "s3:ListBucketVersions", "s3:DeleteObjectVersion",
          "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
          "iam:PassRole", "sts:AssumeRole",
          "ecs:RunTask", "ecs:StartTask", "ecs:ExecuteCommand", "ecs:UpdateService", "ecs:CreateService", "ecs:DeleteService",
          "ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition",
          "ecr:GetAuthorizationToken", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage",
          "ecr:BatchDeleteImage", "ecr:PutImageTagMutability",
          "cognito-idp:ListUsers", "cognito-idp:AdminGetUser",
          "logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartQuery",
        ]
        Resource = "*"
      },
      {
        Sid      = "NeverReadSavedPlans"
        Effect   = "Deny"
        Action   = ["s3:GetObject", "s3:GetObjectAttributes", "s3:GetObjectRetention", "s3:DeleteObject"]
        Resource = "${local.plan_bucket_arn}/*"
      },
    ])
  })
}

# ------------------------------------------------------------------ apply role

resource "aws_iam_role_policy" "github_apply" {
  name = "apply"
  role = aws_iam_role.github_apply.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(local.state_statements, [
      {
        Sid      = "ReadAndWriteThisStateKey"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = local.state_object_arn
      },
      {
        # IAM cannot confine s3:GetObjectVersion to one version, so this reads any saved-plan
        # version under the environment's prefix whose version ID the caller already holds. The
        # role cannot list versions, so it cannot discover one; the workflow reads only the version
        # the approval names. See the accepted IAM limitation in ADR 0012 decision 7.
        Sid      = "ReadSavedPlanVersionsByIdOnly"
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersion", "s3:GetObjectRetention"]
        Resource = local.environment_plans_arn
      },
      {
        Sid      = "DecryptSavedPlans"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.plans.arn
      },
      {
        Sid    = "ManageNetworking"
        Effect = "Allow"
        Action = [
          "ec2:Describe*", "ec2:*Vpc", "ec2:*VpcAttribute", "ec2:*VpcEndpoint", "ec2:*VpcEndpoints", "ec2:*Subnet", "ec2:*SubnetAttribute",
          "ec2:*RouteTable", "ec2:CreateRoute", "ec2:DeleteRoute", "ec2:ReplaceRoute",
          "ec2:*InternetGateway", "ec2:*NatGateway", "ec2:AllocateAddress", "ec2:ReleaseAddress",
          "ec2:*SecurityGroup", "ec2:*SecurityGroupIngress", "ec2:*SecurityGroupEgress", "ec2:*SecurityGroupRules",
          "ec2:ModifySecurityGroupRules", "ec2:UpdateSecurityGroupRuleDescriptions*",
          "ec2:CreateTags", "ec2:DeleteTags",
        ]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
      },
      {
        Sid       = "ManageLoadBalancingAndCognitoWaf"
        Effect    = "Allow"
        Action    = ["elasticloadbalancing:*", "wafv2:*"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
      },
      {
        # The cluster itself.
        Sid       = "ManageTheCluster"
        Effect    = "Allow"
        Action    = ["ecs:CreateCluster", "ecs:UpdateCluster", "ecs:DeleteCluster", "ecs:Describe*", "ecs:List*", "ecs:TagResource", "ecs:UntagResource"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
      },
      {
        # New task-definition revisions of the five approved families. Registration only: every
        # task definition is skip_destroy, so a digest rollout registers a new revision and leaves
        # the previous ones registered for rollback. What a revision contains -- image digest,
        # roles, secret references, hardening -- is checked by plan-summary.
        Sid      = "RegisterApprovedTaskDefinitionRevisions"
        Effect   = "Allow"
        Action   = "ecs:RegisterTaskDefinition"
        Resource = local.task_definition_arns
      },
      {
        # Each service may run only a revision of its own family, never with ECS Exec. A request
        # that does not change the task definition or ECS Exec setting carries neither key.
        Sid      = "RollOutTheWebApiServiceWithItsOwnFamily"
        Effect   = "Allow"
        Action   = ["ecs:CreateService", "ecs:UpdateService"]
        Resource = local.service_arns.web_api
        Condition = {
          ArnEquals            = { "ecs:cluster" = local.cluster_arn }
          ArnLikeIfExists      = { "ecs:task-definition" = local.service_task_definition_arns.web_api }
          StringEqualsIfExists = { "ecs:enable-execute-command" = "false" }
        }
      },
      {
        Sid      = "RollOutTheIdentityBrokerServiceWithItsOwnFamily"
        Effect   = "Allow"
        Action   = ["ecs:CreateService", "ecs:UpdateService"]
        Resource = local.service_arns.identity_broker
        Condition = {
          ArnEquals            = { "ecs:cluster" = local.cluster_arn }
          ArnLikeIfExists      = { "ecs:task-definition" = local.service_task_definition_arns.identity_broker }
          StringEqualsIfExists = { "ecs:enable-execute-command" = "false" }
        }
      },
      {
        Sid       = "RemoveOnlyTheTwoServices"
        Effect    = "Allow"
        Action    = "ecs:DeleteService"
        Resource  = local.service_arn_list
        Condition = { ArnEquals = { "ecs:cluster" = local.cluster_arn } }
      },
      {
        # The only role assignment the pipeline makes: the pre-created workload roles, to ECS
        # tasks. It can neither create, change nor attach a policy to any role.
        Sid       = "PassOnlyThePreCreatedWorkloadRoles"
        Effect    = "Allow"
        Action    = "iam:PassRole"
        Resource  = local.workload_role_arns
        Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
      },
      {
        Sid    = "ManageTheDatabaseInstanceAndItsGroups"
        Effect = "Allow"
        Action = [
          "rds:CreateDBInstance", "rds:ModifyDBInstance", "rds:DeleteDBInstance", "rds:RebootDBInstance",
          "rds:CreateDBSubnetGroup", "rds:ModifyDBSubnetGroup", "rds:DeleteDBSubnetGroup",
          "rds:CreateDBParameterGroup", "rds:ModifyDBParameterGroup", "rds:DeleteDBParameterGroup",
          "rds:AddTagsToResource", "rds:RemoveTagsFromResource", "rds:Describe*", "rds:ListTagsForResource",
        ]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
      },
      {
        # RDS creates its managed master secret with the caller's permission; nothing else may.
        Sid       = "RdsManagedMasterSecretOnly"
        Effect    = "Allow"
        Action    = ["secretsmanager:CreateSecret", "secretsmanager:TagResource", "secretsmanager:DeleteSecret"]
        Resource  = "*"
        Condition = { "ForAnyValue:StringEquals" = { "aws:CalledVia" = ["rds.amazonaws.com"] } }
      },
      {
        # AWS services (RDS, Secrets Manager) take grants on the human-created keys on the
        # caller's behalf; no grant for any other principal.
        Sid       = "KeyGrantsForAwsServicesOnly"
        Effect    = "Allow"
        Action    = ["kms:CreateGrant", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { Bool = { "kms:GrantIsForAWSResource" = "true" } }
      },
      {
        Sid       = "ManageLogGroupsNotTheirContents"
        Effect    = "Allow"
        Action    = ["logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:DescribeLogGroups", "logs:PutRetentionPolicy", "logs:AssociateKmsKey", "logs:TagResource", "logs:UntagResource", "logs:ListTagsForResource", "logs:TagLogGroup", "logs:ListTagsLogGroup"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
      },
      {
        Sid       = "ManageAlarms"
        Effect    = "Allow"
        Action    = ["cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms", "cloudwatch:DescribeAlarms", "cloudwatch:TagResource", "cloudwatch:UntagResource", "cloudwatch:ListTagsForResource"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
      },
      {
        # us-east-1 as well: the Cognito custom domain's certificate lives there.
        Sid       = "ManageCertificates"
        Effect    = "Allow"
        Action    = ["acm:RequestCertificate", "acm:DeleteCertificate", "acm:DescribeCertificate", "acm:ListCertificates", "acm:AddTagsToCertificate", "acm:RemoveTagsFromCertificate", "acm:ListTagsForCertificate"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = [var.region, "us-east-1"] } }
      },
      {
        Sid      = "ManageRecordsInTheOneHostedZone"
        Effect   = "Allow"
        Action   = ["route53:GetHostedZone", "route53:ListResourceRecordSets", "route53:ChangeResourceRecordSets", "route53:ListTagsForResource"]
        Resource = "arn:aws:route53:::hostedzone/${var.route53_zone_id}"
      },
      {
        Sid      = "Route53ChangeStatus"
        Effect   = "Allow"
        Action   = "route53:GetChange"
        Resource = "arn:aws:route53:::change/*"
      },
      {
        Sid    = "ManageUserPoolClientDomainAndBranding"
        Effect = "Allow"
        Action = [
          "cognito-idp:CreateUserPool", "cognito-idp:UpdateUserPool", "cognito-idp:DeleteUserPool", "cognito-idp:DescribeUserPool",
          "cognito-idp:SetUserPoolMfaConfig", "cognito-idp:GetUserPoolMfaConfig",
          "cognito-idp:CreateUserPoolClient", "cognito-idp:UpdateUserPoolClient", "cognito-idp:DeleteUserPoolClient", "cognito-idp:DescribeUserPoolClient",
          "cognito-idp:CreateUserPoolDomain", "cognito-idp:UpdateUserPoolDomain", "cognito-idp:DeleteUserPoolDomain", "cognito-idp:DescribeUserPoolDomain",
          "cognito-idp:CreateManagedLoginBranding", "cognito-idp:UpdateManagedLoginBranding", "cognito-idp:DeleteManagedLoginBranding",
          "cognito-idp:DescribeManagedLoginBranding", "cognito-idp:DescribeManagedLoginBrandingByClient",
          "cognito-idp:AssociateWebACL", "cognito-idp:DisassociateWebACL", "cognito-idp:GetWebACLForResource",
          "cognito-idp:TagResource", "cognito-idp:UntagResource", "cognito-idp:ListTagsForResource",
        ]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
      },
      {
        # Cognito provisions the custom domain's CloudFront distribution on the caller's behalf.
        Sid      = "CognitoCustomDomainDistribution"
        Effect   = "Allow"
        Action   = ["cloudfront:UpdateDistribution", "cloudfront:GetDistribution"]
        Resource = "*"
      },
      {
        Sid      = "ManageAlertTopic"
        Effect   = "Allow"
        Action   = ["sns:CreateTopic", "sns:DeleteTopic", "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:Subscribe", "sns:Unsubscribe", "sns:GetSubscriptionAttributes", "sns:ListSubscriptionsByTopic", "sns:TagResource", "sns:UntagResource", "sns:ListTagsForResource"]
        Resource = "arn:aws:sns:${var.region}:${local.account_id}:${var.name_prefix}-*"
      },
      {
        # The budget alerts; changing its amount or threshold is an ordinary reviewed change.
        # Budget ACTIONS, which could apply a policy under a role, are denied by the boundary.
        Sid      = "ManageTheBudget"
        Effect   = "Allow"
        Action   = ["budgets:ModifyBudget", "budgets:ViewBudget", "budgets:TagResource", "budgets:UntagResource", "budgets:ListTagsForResource"]
        Resource = "arn:aws:budgets::${local.account_id}:budget/${var.name_prefix}-monthly"
      },
      {
        # Immediately before applying, the job re-verifies the release the plan names: the exact
        # release-record version, and the digest's repository, tags and scan. It can read and
        # describe; it can never push, re-tag, delete or reconfigure anything in the registry.
        Sid      = "ReverifyTheReleaseByDigest"
        Effect   = "Allow"
        Action   = ["ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:DescribeImageScanFindings"]
        Resource = local.release_repository_arn
      },
      {
        Sid      = "ReadTheExactReleaseRecordVersion"
        Effect   = "Allow"
        Action   = "s3:GetObjectVersion"
        Resource = local.release_manifest_objects_arn
      },
      {
        Sid       = "DecryptReleaseRecordsThroughS3"
        Effect    = "Allow"
        Action    = "kms:Decrypt"
        Resource  = aws_kms_key.release.arn
        Condition = { StringEquals = { "kms:ViaService" = "s3.${var.artifact_registry_region}.amazonaws.com" } }
      },
      {
        Sid    = "ReadHumanAppliedResources"
        Effect = "Allow"
        Action = [
          "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags",
          "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:GetOpenIDConnectProvider",
          "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListResourceTags", "kms:ListAliases",
          "secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy",
        ]
        Resource = "*"
      },
      {
        Sid      = "CallerIdentity"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      },
    ])
  })
}

# ------------------------------------------------------------------ apply boundary

resource "aws_iam_policy" "apply_boundary" {
  name        = local.apply_boundary_name
  description = "Permissions boundary of the GitHub apply role: staging infrastructure and workload rollout inside the delivery contract; no IAM change, other role assignment, secret value, key policy, one-off task, ECS Exec, image publication, data export, purchase or budget action."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # The ceiling. IAM is deliberately absent: its reads and the one role assignment are the
        # next two statements, so no IAM mutation is within this boundary.
        Sid    = "CeilingIsTheAcceptedStagingFamilies"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity", "s3:*", "kms:*", "ec2:*", "elasticloadbalancing:*", "acm:*", "route53:*",
          "ecs:*", "rds:*", "secretsmanager:*", "cognito-idp:*", "wafv2:*", "logs:*", "cloudwatch:*", "sns:*", "budgets:*",
          "cloudfront:UpdateDistribution", "cloudfront:GetDistribution",
        ]
        Resource = "*"
      },
      {
        Sid      = "CeilingVerifiesTheReleaseRepositoryByDigest"
        Effect   = "Allow"
        Action   = ["ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:DescribeImageScanFindings"]
        Resource = local.release_repository_arn
      },
      {
        Sid    = "CeilingReadsIam"
        Effect = "Allow"
        Action = [
          "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags",
          "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:GetOpenIDConnectProvider",
        ]
        Resource = "*"
      },
      {
        Sid       = "CeilingPassesOnlyThePreCreatedWorkloadRolesToEcsTasks"
        Effect    = "Allow"
        Action    = "iam:PassRole"
        Resource  = local.workload_role_arns
        Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
      },
      {
        # Defense in depth for the ceiling above: passing any other role, or to any other service.
        Sid         = "DenyPassingAnyRoleButThePreCreatedWorkloadRoles"
        Effect      = "Deny"
        Action      = "iam:PassRole"
        NotResource = local.workload_role_arns
      },
      {
        Sid       = "DenyPassingRolesToAnythingButEcsTasks"
        Effect    = "Deny"
        Action    = "iam:PassRole"
        Resource  = "*"
        Condition = { StringNotEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
      },
      {
        Sid      = "DenyIdentityAndAccountAdministration"
        Effect   = "Deny"
        Action   = ["sts:AssumeRole", "sts:GetFederationToken", "sts:GetSessionToken", "organizations:*", "account:*"]
        Resource = "*"
      },
      {
        # A value can arrive through UpdateSecret, CreateSecret or a restore; none is the pipeline's.
        Sid    = "DenySecretValuesAndContainerChanges"
        Effect = "Deny"
        Action = [
          "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue", "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecret", "secretsmanager:UpdateSecretVersionStage", "secretsmanager:RestoreSecret",
          "secretsmanager:RotateSecret", "secretsmanager:CancelRotateSecret", "secretsmanager:PutResourcePolicy",
          "secretsmanager:DeleteResourcePolicy", "secretsmanager:ReplicateSecretToRegions",
        ]
        Resource = "*"
      },
      {
        Sid       = "DenySecretCreationExceptRdsManagedMasterSecret"
        Effect    = "Deny"
        Action    = ["secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:TagResource"]
        Resource  = "*"
        Condition = { "ForAllValues:StringNotEquals" = { "aws:CalledVia" = ["rds.amazonaws.com"] } }
      },
      {
        Sid    = "DenyKeyAdministrationAndNonServiceGrants"
        Effect = "Deny"
        Action = [
          "kms:CreateKey", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:RetireGrant",
          "kms:RevokeGrant", "kms:ReEncrypt*", "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias",
        ]
        Resource = "*"
      },
      {
        # Decryption of state, saved plans and release records only.
        Sid         = "DenyDecryptOutsideStatePlansAndReleaseRecords"
        Effect      = "Deny"
        Action      = "kms:Decrypt"
        NotResource = [aws_kms_key.state.arn, aws_kms_key.plans.arn, aws_kms_key.release.arn]
      },
      {
        Sid       = "DenyGrantsForAnythingButAwsServices"
        Effect    = "Deny"
        Action    = "kms:CreateGrant"
        Resource  = "*"
        Condition = { Bool = { "kms:GrantIsForAWSResource" = "false" } }
      },
      {
        Sid      = "DenyTamperingWithBootstrapKeys"
        Effect   = "Deny"
        Action   = ["kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:CreateGrant", "kms:RetireGrant", "kms:RevokeGrant", "kms:UpdateAlias", "kms:DeleteAlias", "kms:ReEncrypt*"]
        Resource = [aws_kms_key.state.arn, aws_kms_key.plans.arn, aws_kms_key.release.arn]
      },
      {
        # A one-off task runs a chosen command under a workload role; ECS Exec opens a shell in a
        # running task. Neither is a delivery operation.
        Sid      = "DenyOneOffTasksAndEcsExec"
        Effect   = "Deny"
        Action   = ["ecs:RunTask", "ecs:StartTask", "ecs:ExecuteCommand", "ecs:CreateTaskSet", "ecs:UpdateTaskSet", "ecs:DeleteTaskSet", "ecs:UpdateServicePrimaryTaskSet"]
        Resource = "*"
      },
      {
        # Every previous revision stays registered, so a rollback always has a revision to run.
        Sid      = "DenyTaskDefinitionDeregistrationAndDeletion"
        Effect   = "Deny"
        Action   = ["ecs:DeregisterTaskDefinition", "ecs:DeleteTaskDefinitions"]
        Resource = "*"
      },
      {
        Sid         = "DenyServiceChangesOutsideTheTwoServices"
        Effect      = "Deny"
        Action      = ["ecs:CreateService", "ecs:UpdateService", "ecs:DeleteService"]
        NotResource = local.service_arn_list
      },
      {
        # Whatever the role policy says: when a request names a task definition, each service runs
        # only its own family; a request that names none changes no task definition.
        Sid      = "DenyTheWebApiServiceAnyOtherFamily"
        Effect   = "Deny"
        Action   = ["ecs:CreateService", "ecs:UpdateService"]
        Resource = local.service_arns.web_api
        Condition = {
          Null       = { "ecs:task-definition" = "false" }
          ArnNotLike = { "ecs:task-definition" = local.service_task_definition_arns.web_api }
        }
      },
      {
        Sid      = "DenyTheIdentityBrokerServiceAnyOtherFamily"
        Effect   = "Deny"
        Action   = ["ecs:CreateService", "ecs:UpdateService"]
        Resource = local.service_arns.identity_broker
        Condition = {
          Null       = { "ecs:task-definition" = "false" }
          ArnNotLike = { "ecs:task-definition" = local.service_task_definition_arns.identity_broker }
        }
      },
      {
        Sid      = "DenyEcsExecOnAnyService"
        Effect   = "Deny"
        Action   = ["ecs:CreateService", "ecs:UpdateService"]
        Resource = "*"
        Condition = {
          Null            = { "ecs:enable-execute-command" = "false" }
          StringNotEquals = { "ecs:enable-execute-command" = "false" }
        }
      },
      {
        # Images are published once, by artifact-publish, into the artifacts root's registry. The
        # apply role neither pushes, re-tags, deletes nor reconfigures any repository.
        Sid    = "DenyImagePublicationAndRegistryChanges"
        Effect = "Deny"
        Action = [
          "ecr:GetAuthorizationToken", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage",
          "ecr:BatchDeleteImage", "ecr:PutImageTagMutability", "ecr:SetRepositoryPolicy", "ecr:DeleteRepositoryPolicy",
          "ecr:PutLifecyclePolicy", "ecr:DeleteLifecyclePolicy", "ecr:PutReplicationConfiguration", "ecr:PutRegistryPolicy",
          "ecr:CreateRepository", "ecr:DeleteRepository",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDataExportAndLogReads"
        Effect = "Deny"
        Action = [
          "rds:CreateDBSnapshot", "rds:CopyDBSnapshot", "rds:ModifyDBSnapshotAttribute", "rds:StartExportTask",
          "rds:RestoreDBInstanceFromDBSnapshot", "rds:RestoreDBInstanceToPointInTime", "rds:CreateDBInstanceReadReplica",
          "rds:StartDBInstanceAutomatedBackupsReplication",
          "logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartQuery", "logs:GetQueryResults", "logs:StartLiveTail",
          "logs:PutSubscriptionFilter", "logs:CreateExportTask", "logs:PutDestination", "logs:PutDestinationPolicy",
          "logs:PutResourcePolicy", "logs:PutDeliveryDestination", "logs:PutDeliverySource", "logs:CreateDelivery",
        ]
        Resource = "*"
      },
      {
        # The budget alerts and is the pipeline's to change. A budget ACTION is not: it applies an
        # IAM or organization policy, or stops resources, under a role it is given -- an escalation
        # path. Suppressing an alarm is not a delivery operation either.
        Sid    = "DenyPurchasesBudgetActionsAndAlarmSuppression"
        Effect = "Deny"
        Action = [
          "rds:PurchaseReservedDBInstancesOffering", "ec2:Purchase*",
          "cloudwatch:DisableAlarmActions", "cloudwatch:SetAlarmState",
          "budgets:CreateBudgetAction", "budgets:UpdateBudgetAction", "budgets:DeleteBudgetAction", "budgets:ExecuteBudgetAction",
        ]
        Resource = "*"
      },
      {
        Sid       = "DenyAnyDatabaseClassButTheReviewedOne"
        Effect    = "Deny"
        Action    = ["rds:CreateDBInstance", "rds:ModifyDBInstance"]
        Resource  = "*"
        Condition = { StringNotEqualsIfExists = { "rds:DatabaseClass" = var.rds_instance_class } }
      },
      {
        Sid    = "DenyComputeOutsideFargateAndNetworkBridges"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances", "ec2:StartInstances", "ec2:RequestSpotInstances", "ec2:RequestSpotFleet", "ec2:CreateFleet",
          "ec2:CreateLaunchTemplate*", "ec2:ImportKeyPair", "ec2:CreateKeyPair",
          "ec2:*VpcPeeringConnection*", "ec2:*TransitGateway*", "ec2:*VpnConnection*", "ec2:*VpnGateway*",
          "ec2:CreateCustomerGateway", "ec2:*ClientVpn*",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyCognitoUserAdministrationAndIdentityPools"
        Effect = "Deny"
        Action = [
          "cognito-idp:Admin*", "cognito-idp:SignUp", "cognito-idp:ListUsers", "cognito-idp:ListUsersInGroup",
          "cognito-idp:CreateGroup", "cognito-idp:*UserImportJob", "cognito-idp:CreateIdentityProvider",
          "cognito-identity:*",
        ]
        Resource = "*"
      },
      {
        Sid         = "DenyS3OutsideStatePlansAndReleaseRecords"
        Effect      = "Deny"
        Action      = "s3:*"
        NotResource = [local.state_bucket_arn, "${local.state_bucket_arn}/*", local.plan_bucket_arn, "${local.plan_bucket_arn}/*", local.release_manifest_objects_arn]
      },
      {
        Sid    = "DenyReleaseRecordChanges"
        Effect = "Deny"
        Action = [
          "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
          "s3:BypassGovernanceRetention",
        ]
        Resource = local.release_objects_arn
      },
      {
        Sid    = "DenySavedPlanWritesAndRetentionBypass"
        Effect = "Deny"
        Action = [
          "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ListBucketVersions",
          "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
          "s3:PutBucket*", "s3:DeleteBucket*", "s3:PutLifecycleConfiguration", "s3:PutEncryptionConfiguration",
          "s3:PutInventoryConfiguration", "s3:PutReplicationConfiguration",
        ]
        Resource = [local.plan_bucket_arn, "${local.plan_bucket_arn}/*"]
      },
      {
        Sid      = "DenyStateBucketReconfiguration"
        Effect   = "Deny"
        Action   = ["s3:DeleteObjectVersion", "s3:PutBucket*", "s3:DeleteBucket*", "s3:PutLifecycleConfiguration", "s3:PutEncryptionConfiguration", "s3:PutInventoryConfiguration", "s3:PutReplicationConfiguration"]
        Resource = [local.state_bucket_arn, "${local.state_bucket_arn}/*"]
      },
      {
        # The only NotAction denies here, each narrowed by the requested region: global services
        # are exempt, every other request outside the staging and certificate regions is refused.
        Sid       = "DenyRegionsOutsideStagingAndTheCertificateRegion"
        Effect    = "Deny"
        NotAction = ["iam:*", "sts:*", "route53:*", "budgets:*", "cloudfront:*"]
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:RequestedRegion" = [var.region, "us-east-1"] } }
      },
      {
        Sid       = "DenyUsEast1ExceptTheCertificate"
        Effect    = "Deny"
        NotAction = ["acm:*", "iam:*", "sts:*", "route53:*", "budgets:*", "cloudfront:*"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } }
      },
    ]
  })
}

# ------------------------------------------------------------------ artifact-publish

resource "aws_iam_role_policy" "artifact_publish" {
  name = "publish"
  role = aws_iam_role.artifact_publish.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EcrAuthorizationToken"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        # One push, and the reads a resumed publication needs to prove what an earlier attempt
        # pushed: the image's details, its manifest and its configuration blob.
        Sid    = "PushAndReadTheReleaseRepositoryOnly"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload",
          "ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer",
        ]
        Resource = local.release_repository_arn
      },
      {
        # Create a record once, and read back an existing one to prove it is byte-for-byte the
        # record this commit's release produces. The bucket policy refuses any write without
        # If-None-Match, so no record is ever replaced.
        Sid      = "CreateAndReadBackReleaseRecords"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = local.release_objects_arn
      },
      {
        # SSE-KMS for the records only. Image layers need no permission here: ECR encrypts and
        # decrypts them under its own grant on the release key.
        Sid       = "ReleaseRecordEncryptionThroughS3Only"
        Effect    = "Allow"
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource  = aws_kms_key.release.arn
        Condition = { StringEquals = { "kms:ViaService" = "s3.${var.artifact_registry_region}.amazonaws.com" } }
      },
      {
        Sid      = "CallerIdentity"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "artifact_publish_boundary" {
  name        = local.publish_boundary_name
  description = "Permissions boundary of the artifact-publish role: release image push and reads, and release records only; no infrastructure, deployment, role, secret, state or saved plan."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CeilingIsPublicationOnly"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer",
          "s3:PutObject", "s3:GetObject", "kms:GenerateDataKey", "kms:Decrypt", "sts:GetCallerIdentity",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyInfrastructureDeploymentRolesAndSecrets"
        Effect = "Deny"
        Action = [
          "iam:*", "sts:AssumeRole", "ecs:*", "secretsmanager:*", "ssm:*", "ec2:*", "rds:*", "elasticloadbalancing:*",
          "cognito-idp:*", "route53:*", "acm:*", "wafv2:*", "logs:*", "cloudwatch:*", "sns:*", "budgets:*",
          "organizations:*", "account:*",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyImageDeletionRetaggingAndRegistryChanges"
        Effect = "Deny"
        Action = [
          "ecr:BatchDeleteImage", "ecr:PutImageTagMutability", "ecr:SetRepositoryPolicy", "ecr:DeleteRepositoryPolicy",
          "ecr:PutLifecyclePolicy", "ecr:DeleteLifecyclePolicy", "ecr:PutReplicationConfiguration", "ecr:PutRegistryPolicy",
          "ecr:CreateRepository", "ecr:DeleteRepository", "ecr:PutImageScanningConfiguration",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyRegistryAccessOutsideTheReleaseRepository"
        Effect = "Deny"
        Action = [
          "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload",
          "ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer",
        ]
        NotResource = local.release_repository_arn
      },
      {
        Sid         = "DenyS3OutsideReleaseRecords"
        Effect      = "Deny"
        Action      = "s3:*"
        NotResource = local.release_objects_arn
      },
      {
        Sid      = "DenyRecordDeletionAndRetentionBypass"
        Effect   = "Deny"
        Action   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold"]
        Resource = "*"
      },
      {
        Sid       = "DenyKeyUseOutsideS3"
        Effect    = "Deny"
        Action    = "kms:*"
        Resource  = "*"
        Condition = { StringNotEquals = { "kms:ViaService" = "s3.${var.artifact_registry_region}.amazonaws.com" } }
      },
    ]
  })
}

# ------------------------------------------------------------------ plan boundary

# The plan role's own policy is its whole grant; this boundary makes that grant the ceiling in IAM as well.
# A policy attached to the role by any later mistake -- an inline side door or a managed attachment -- still
# cannot read a secret value or a parameter, decrypt with any key but the state key and the release key
# through S3, encrypt with any key but the state and plan keys, write state, read, list or unlock a saved
# plan, or reach any object but state, its lockfile, new saved plans and release records. Human-applied, like
# every delivery identity and boundary in this root; infra/terraform/policy/check.py evaluates it with the
# plan role's policy and against an attached side door.
resource "aws_iam_policy" "plan_boundary" {
  name        = local.plan_boundary_name
  description = "Permissions boundary of the GitHub plan role: refresh reads, state and its lockfile, new saved plans and release verification; no secret value, parameter, other key, state write or saved-plan read."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # The ceiling: exactly the actions the plan role's own policy grants, and nothing else.
        Sid    = "CeilingIsThePlanRolesOwnActions"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity",
          "s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
          "kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey",
          "ec2:Describe*",
          "elasticloadbalancing:Describe*",
          "acm:DescribeCertificate", "acm:ListTagsForCertificate",
          "route53:GetHostedZone", "route53:ListResourceRecordSets", "route53:GetChange", "route53:ListTagsForResource",
          "ecs:DescribeClusters", "ecs:DescribeServices", "ecs:DescribeTaskDefinition", "ecs:ListTagsForResource",
          "rds:DescribeDBInstances", "rds:DescribeDBSubnetGroups", "rds:DescribeDBParameterGroups", "rds:DescribeDBParameters", "rds:ListTagsForResource",
          "secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy",
          "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListResourceTags", "kms:ListAliases",
          "cognito-idp:DescribeUserPool", "cognito-idp:DescribeUserPoolClient", "cognito-idp:DescribeUserPoolDomain",
          "cognito-idp:GetUserPoolMfaConfig", "cognito-idp:DescribeManagedLoginBranding", "cognito-idp:DescribeManagedLoginBrandingByClient",
          "cognito-idp:GetWebACLForResource", "cognito-idp:ListTagsForResource",
          "wafv2:GetWebACL", "wafv2:GetIPSet", "wafv2:GetWebACLForResource", "wafv2:ListTagsForResource",
          "logs:DescribeLogGroups", "logs:ListTagsForResource",
          "cloudwatch:DescribeAlarms", "cloudwatch:ListTagsForResource",
          "sns:GetTopicAttributes", "sns:GetSubscriptionAttributes", "sns:ListTagsForResource",
          "budgets:ViewBudget", "budgets:ListTagsForResource",
          "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags",
          "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:GetOpenIDConnectProvider",
          "ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:DescribeImageScanFindings",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyPlanRoleSecretValuesAndParameters"
        Effect = "Deny"
        Action = [
          "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret",
          "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:GetParameterHistory",
        ]
        Resource = "*"
      },
      {
        Sid         = "DenyPlanRoleDecryptOutsideStateAndReleaseRecords"
        Effect      = "Deny"
        Action      = "kms:Decrypt"
        NotResource = [aws_kms_key.state.arn, aws_kms_key.release.arn]
      },
      {
        Sid       = "DenyPlanRoleReleaseKeyOutsideS3"
        Effect    = "Deny"
        Action    = "kms:Decrypt"
        Resource  = aws_kms_key.release.arn
        Condition = { StringNotEquals = { "kms:ViaService" = "s3.${var.artifact_registry_region}.amazonaws.com" } }
      },
      {
        Sid         = "DenyPlanRoleEncryptOutsideStateAndSavedPlans"
        Effect      = "Deny"
        Action      = ["kms:Encrypt", "kms:GenerateDataKey"]
        NotResource = [aws_kms_key.state.arn, aws_kms_key.plans.arn]
      },
      {
        Sid    = "DenyPlanRoleSavedPlanReadsHistoryAndRetentionBypass"
        Effect = "Deny"
        Action = [
          "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes", "s3:GetObjectRetention", "s3:DeleteObject",
          "s3:DeleteObjectVersion", "s3:ListBucketVersions", "s3:BypassGovernanceRetention", "s3:PutObjectRetention",
          "s3:PutObjectLegalHold",
        ]
        Resource = [local.plan_bucket_arn, "${local.plan_bucket_arn}/*"]
      },
      {
        Sid      = "DenyPlanRoleStateWrites"
        Effect   = "Deny"
        Action   = ["s3:PutObject", "s3:DeleteObject"]
        Resource = local.state_object_arn
      },
      {
        Sid         = "DenyPlanRoleS3OutsideStateSavedPlansAndReleaseRecords"
        Effect      = "Deny"
        Action      = "s3:*"
        NotResource = [local.state_bucket_arn, local.state_object_arn, local.lock_object_arn, local.environment_plans_arn, local.release_manifest_objects_arn]
      },
    ]
  })
}
