data "aws_vpc" "shared" {
  tags = {
    Project     = "tech-challenge-oficina"
    Environment = "shared"
  }
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.shared.id]
  }

  tags = {
    Tier = "private"
  }
}

data "aws_db_instance" "postgres" {
  db_instance_identifier = "tech-challenge-oficina-postgres"
}

resource "aws_security_group" "lambda" {
  name        = "tech-challenge-oficina-auth-lambda-sg"
  description = "Security group for auth Lambda PostgreSQL access"
  vpc_id      = data.aws_vpc.shared.id

  egress {
    description = "PostgreSQL access inside shared VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.shared.cidr_block]
  }

  tags = {
    Project     = "tech-challenge-oficina"
    Environment = "shared"
    Name        = "tech-challenge-oficina-auth-lambda-sg"
  }
}
