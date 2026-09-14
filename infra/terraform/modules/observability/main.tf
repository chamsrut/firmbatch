# Application log groups with explicit retention and encryption, the alarms, and the budget
# (ADR 0011 decisions 2 and 10; topology §10).
#
# AWS Budgets ALERTS. It is not a spending cap and nothing here stops spend.
#
# AWS-managed records that can hold identity data -- CloudTrail, Cognito logging and export,
# SES records, the Cognito WAF's logs -- are not configured here; M3.3d inventories and
# reviews them. None is ever copied into these application log groups.

variable "name_prefix" {
  type     = string
  nullable = false
}

variable "account_id" {
  type     = string
  nullable = false
}

variable "log_retention_days" {
  description = "Retention of every application log group, a human-confirmed parameter."
  type        = number
  nullable    = false

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365], var.log_retention_days)
    error_message = "log_retention_days must be a CloudWatch Logs retention value of at most 365 days."
  }
}

variable "kms_key_arn" {
  type     = string
  nullable = false
}

variable "alert_email" {
  description = "Alert recipient for the alarms and the budget: a human-confirmed parameter, never committed."
  type        = string
  nullable    = false
  sensitive   = true

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be an email address."
  }
}

variable "budget_limit_usd" {
  description = "Monthly budget amount in USD that alerts are measured against. Alerts only; not a cap."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[1-9][0-9]*(\\.[0-9]{1,2})?$", var.budget_limit_usd))
    error_message = "budget_limit_usd must be a positive amount such as 150 or 150.00."
  }
}

variable "budget_alert_threshold_percent" {
  description = "Percentage of budget_limit_usd at which the actual-spend alert fires."
  type        = number
  nullable    = false

  validation {
    condition     = var.budget_alert_threshold_percent >= 1 && var.budget_alert_threshold_percent <= 100
    error_message = "budget_alert_threshold_percent must be from 1 to 100."
  }
}

variable "log_group_suffixes" {
  description = "Log group per service and one-off task, keyed web_api, identity_broker, migrate, bootstrap, identity_binding."
  type        = map(string)
  nullable    = false
}

variable "alb_arn_suffix" {
  type     = string
  nullable = false
}

variable "target_group_arn_suffixes" {
  type     = map(string)
  nullable = false
}

variable "cluster_name" {
  type     = string
  nullable = false
}

variable "service_names" {
  type     = map(string)
  nullable = false
}

variable "db_instance_identifier" {
  type     = string
  nullable = false
}

resource "aws_cloudwatch_log_group" "task" {
  for_each = var.log_group_suffixes

  name              = "/ecs/${var.name_prefix}/${each.value}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

# Alert notifications carry alarm names and budget figures, not application data.
resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudWatchAlarmsFromThisAccount"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
      },
      {
        Sid       = "BudgetsFromThisAccount"
        Effect    = "Allow"
        Principal = { Service = "budgets.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
      },
    ]
  })
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${var.name_prefix}-alb-5xx"
  alarm_description   = "The ALB itself returned 5xx responses."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  dimensions          = { LoadBalancer = var.alb_arn_suffix }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "target_5xx" {
  for_each = var.target_group_arn_suffixes

  alarm_name          = "${var.name_prefix}-${replace(each.key, "_", "-")}-5xx"
  alarm_description   = "The ${replace(each.key, "_", "-")} targets returned 5xx responses."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  dimensions          = { LoadBalancer = var.alb_arn_suffix, TargetGroup = each.value }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "service_running_tasks" {
  for_each = var.service_names

  alarm_name          = "${var.name_prefix}-${replace(each.key, "_", "-")}-no-running-task"
  alarm_description   = "The ${replace(each.key, "_", "-")} service has no running task."
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  dimensions          = { ClusterName = var.cluster_name, ServiceName = each.value }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "database_free_storage" {
  alarm_name          = "${var.name_prefix}-postgres-free-storage"
  alarm_description   = "RDS free storage is below 5 GiB."
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = var.db_instance_identifier }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5368709120
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "database_connections" {
  alarm_name          = "${var.name_prefix}-postgres-connections"
  alarm_description   = "RDS connection count is unusually high for staging."
  namespace           = "AWS/RDS"
  metric_name         = "DatabaseConnections"
  dimensions          = { DBInstanceIdentifier = var.db_instance_identifier }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 60
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = var.budget_limit_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = var.budget_alert_threshold_percent
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.alerts.arn]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_sns_topic_arns = [aws_sns_topic.alerts.arn]
  }
}

output "log_group_names" {
  value = { for key, group in aws_cloudwatch_log_group.task : key => group.name }
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
