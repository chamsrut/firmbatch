# Route 53, the regional ACM certificate, the internet-facing ALB, its 443 and 80 listeners
# and the path rules (ADR 0011 decision 3; topology §2). No WAF on the ALB, no ALB
# authentication, no CloudFront, and access logs stay disabled for M3.3 because the
# /auth/callback query string carries `code` and `state` (decision 10).

# ------------------------------------------------------------------ reviewer allow-list

# The SAME reviewed list admits ports 443 and 80, and nothing else admits anything.
resource "aws_vpc_security_group_ingress_rule" "reviewer" {
  for_each = {
    for pair in setproduct(var.reviewer_cidrs, [80, 443]) :
    "${pair[0]} ${pair[1]}" => { cidr = pair[0], port = pair[1] }
  }

  security_group_id = var.alb_security_group_id
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = strcontains(each.value.cidr, ":") ? null : each.value.cidr
  cidr_ipv6         = strcontains(each.value.cidr, ":") ? each.value.cidr : null
  description       = each.value.port == 80 ? "Reviewer allow-list; redirect to HTTPS only" : "Reviewer allow-list"
}

# ------------------------------------------------------------------ certificate and DNS

resource "aws_acm_certificate" "app" {
  domain_name       = var.app_hostname
  validation_method = "DNS"
  key_algorithm     = "RSA_2048"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "app_certificate_validation" {
  for_each = {
    for option in aws_acm_certificate.app.domain_validation_options : option.domain_name => option
  }

  zone_id         = var.route53_zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  records         = [each.value.resource_record_value]
  ttl             = 300
  allow_overwrite = false
}

resource "aws_acm_certificate_validation" "app" {
  certificate_arn         = aws_acm_certificate.app.arn
  validation_record_fqdns = [for record in aws_route53_record.app_certificate_validation : record.fqdn]
}

resource "aws_route53_record" "app" {
  zone_id = var.route53_zone_id
  name    = var.app_hostname
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}

# ------------------------------------------------------------------ load balancer

resource "aws_lb" "this" {
  name               = "${var.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  ip_address_type    = "ipv4"
  security_groups    = [var.alb_security_group_id]
  subnets            = var.public_subnet_ids

  drop_invalid_header_fields = true
  desync_mitigation_mode     = "strictest"
  enable_deletion_protection = true
  idle_timeout               = 60

  # No access_logs block: ALB access logs stay disabled for M3.3 (ADR 0011 decision 10).
}

resource "aws_lb_target_group" "service" {
  for_each = {
    web_api         = { short = "web-api", health = var.web_api_health_check_path }
    identity_broker = { short = "broker", health = var.identity_broker_health_check_path }
  }

  name                 = "${var.name_prefix}-${each.value.short}"
  port                 = var.application_port
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 30

  health_check {
    path                = each.value.health
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# Port 80 does one thing: redirect to HTTPS.
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      protocol    = "HTTPS"
      port        = "443"
      status_code = "HTTP_301"
    }
  }
}

# Port 443: any Host other than the one customer origin gets a fixed refusal.
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.app.certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Misdirected request"
      status_code  = "421"
    }
  }
}

resource "aws_lb_listener_rule" "identity_broker" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service["identity_broker"].arn
  }

  condition {
    host_header {
      values = [var.app_hostname]
    }
  }

  condition {
    path_pattern {
      values = ["/auth/*"]
    }
  }
}

resource "aws_lb_listener_rule" "web_api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service["web_api"].arn
  }

  condition {
    host_header {
      values = [var.app_hostname]
    }
  }

  condition {
    path_pattern {
      values = ["/v1/*"]
    }
  }
}

# `/` and every frontend route on the exact host.
resource "aws_lb_listener_rule" "web_api_default" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 30

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service["web_api"].arn
  }

  condition {
    host_header {
      values = [var.app_hostname]
    }
  }
}
