terraform {
  required_version = ">= 1.6"

  backend "s3" {
    bucket       = "tech-challenge-oficina-terraform-state-b1cfa326"
    key          = "auth/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
