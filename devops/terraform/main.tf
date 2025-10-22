
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-north-1"
}

# Security Group for CTFd
resource "aws_security_group" "ctfd_sg" {
  name        = "ctfd-devops-sg"
  description = "Security group for CTFd DevOps project"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "CTFd Application"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Jenkins"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "CTFd-DevOps-SG"
    Project = "CTFd-DevOps"
  }
}

# EC2 Instance
resource "aws_instance" "ctfd_server" {
  ami           = "ami-0c55b159cbfafe1f0"  # Ubuntu 22.04 LTS (update for your region)
  instance_type = "t2.medium"
  key_name      = "ctfd-devops-key"
  
  vpc_security_group_ids = [aws_security_group.ctfd_sg.id]

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y docker.io docker-compose git
              usermod -aG docker ubuntu
              EOF

  tags = {
    Name    = "CTFd-DevOps-Server"
    Project = "CTFd-DevOps"
  }
}

output "instance_public_ip" {
  value = aws_instance.ctfd_server.public_ip
}

output "instance_id" {
  value = aws_instance.ctfd_server.id
}
