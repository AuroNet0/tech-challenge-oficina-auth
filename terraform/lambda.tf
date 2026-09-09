resource "aws_lambda_function" "auth" {
  function_name    = "tech-challenge-oficina-auth"
  role             = aws_iam_role.lambda.arn
  runtime          = "java21"
  handler          = "br.com.fiap.oficina.auth.handler.AuthHandler::handleRequest"
  filename         = "${path.module}/../target/tech-challenge-oficina-auth.jar"
  source_code_hash = filebase64sha256("${path.module}/../target/tech-challenge-oficina-auth.jar")
  memory_size      = 512
  timeout          = 15
  package_type     = "Zip"

  vpc_config {
    subnet_ids         = data.aws_subnets.private.ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      DB_HOST     = data.aws_db_instance.postgres.address
      DB_PORT     = tostring(data.aws_db_instance.postgres.port)
      DB_NAME     = "oficina"
      DB_USER     = "oficina_admin"
      DB_PASSWORD = var.db_password
      JWT_SECRET  = var.jwt_secret
    }
  }

  tags = {
    Project     = "tech-challenge-oficina"
    Environment = "shared"
    Name        = "tech-challenge-oficina-auth"
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_execution,
    aws_iam_role_policy_attachment.lambda_vpc_access
  ]
}