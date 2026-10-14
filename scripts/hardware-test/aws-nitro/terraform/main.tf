# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Provisions an EC2 instance with AWS Nitro Enclaves enabled, suitable
# for running the Vault Genome hardware-validation suite (Week 2 of the
# 6-week multi-TEE testing sprint).
#
# Defaults mirror the GCP SEV-SNP module: single instance per terraform
# apply, so the operator can apply N times in parallel for an N-instance
# cohort. AMI is Amazon Linux 2023 (latest Nitro-CLI-compatible image
# with no extra repos required).
#
# IMPORTANT: Nitro Enclaves are supported only on specific instance
# types — m5.xlarge or larger from the m5/m5a/m5d/m5n/m6i families,
# c5/c5a/c5d/c5n/c6i families, r5/r5a/r5d/r5n/r6i families. We default
# to m5.xlarge (4 vCPU, 16 GB) which is the smallest Nitro-Enclaves-
# capable instance and matches our GCP n2d-standard-4 selection.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region. Must support Nitro Enclaves on m5.xlarge."
  type        = string
  default     = "us-east-2"
}

variable "availability_zone" {
  description = "Availability zone within the region. Different AZs guarantee different physical Nitro security chips."
  type        = string
  default     = "us-east-2a"
}

variable "instance_name" {
  description = "Name of the EC2 instance (also used as Name tag)."
  type        = string
  default     = "vault-genome-nitro-test"
}

variable "instance_type" {
  description = "EC2 instance type. Must be Nitro-Enclaves-capable. m5.xlarge (4 vCPU, 16 GB) is the recommended minimum."
  type        = string
  default     = "m5.xlarge"
}

variable "disk_size_gb" {
  description = "Root volume size. 40 GB is the minimum that fits Llama 3.2 3B + Docker + .eif build artifacts."
  type        = number
  default     = 40
}

variable "ssh_key_name" {
  description = "Name of an existing EC2 KeyPair in this region for SSH access. Create one in the EC2 console > Key Pairs first."
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH to the instance. Lock to your IP /32 for production; 0.0.0.0/0 only for short-lived test runs."
  type        = string
  default     = "0.0.0.0/0"
}

variable "create_iam_role" {
  description = "Create the S3/KMS instance role and profile. The attestation path needs no AWS API from the instance; an operator with EC2-only rights sets this to false and the instance runs without a profile."
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# AMI: Amazon Linux 2023 with Nitro Enclaves CLI ready to install
# -----------------------------------------------------------------------------

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  # The standard image, not the minimal one: both match "al2023-ami-*",
  # the minimal one sorts newest by minutes and lacks the tooling the
  # bootstrap expects. The id actually used is in the ami_id_used output
  # and in the run's evidence.
  filter {
    name   = "name"
    values = ["al2023-ami-2023*-kernel-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# -----------------------------------------------------------------------------
# Networking: default VPC + default subnet in chosen AZ
# -----------------------------------------------------------------------------

data "aws_vpc" "default" {
  default = true
}

data "aws_subnet" "default_az" {
  vpc_id            = data.aws_vpc.default.id
  availability_zone = var.availability_zone
  default_for_az    = true
}

resource "aws_security_group" "vault_genome_test" {
  name        = "${var.instance_name}-sg"
  description = "Vault Genome hardware test - SSH ingress + all egress"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from operator"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    description = "All outbound (apt, docker pull, AWS API, KDS, etc.)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.instance_name}-sg"
    Purpose = "vault-genome-hardware-validation"
    Sprint  = "week-2-aws-nitro-enclaves"
  }
}

# -----------------------------------------------------------------------------
# IAM role: minimum needed for instance to pull from S3 + use KMS for
# Nitro attestation-conditional decryption (KMS scope optional, included
# for cross-region transfer tests).
# -----------------------------------------------------------------------------

resource "aws_iam_role" "vault_genome_ec2" {
  count = var.create_iam_role ? 1 : 0
  name  = "${var.instance_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Purpose = "vault-genome-hardware-validation"
  }
}

resource "aws_iam_role_policy" "vault_genome_ec2_inline" {
  count = var.create_iam_role ? 1 : 0
  name  = "${var.instance_name}-inline"
  role  = aws_iam_role.vault_genome_ec2[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::vault-genome-test-*",
          "arn:aws:s3:::vault-genome-test-*/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:RecipientAttestation:ImageSha384" = "*"
          }
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "vault_genome" {
  count = var.create_iam_role ? 1 : 0
  name  = "${var.instance_name}-profile"
  role  = aws_iam_role.vault_genome_ec2[0].name
}

# -----------------------------------------------------------------------------
# EC2 instance with Nitro Enclaves enabled
# -----------------------------------------------------------------------------

resource "aws_instance" "vault_genome" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnet.default_az.id
  vpc_security_group_ids = [aws_security_group.vault_genome_test.id]
  key_name               = var.ssh_key_name
  iam_instance_profile   = var.create_iam_role ? aws_iam_instance_profile.vault_genome[0].name : null

  # CRITICAL: Nitro Enclaves enablement. Without this block the instance
  # cannot run enclaves regardless of instance type capability.
  enclave_options {
    enabled = true
  }

  root_block_device {
    volume_size = var.disk_size_gb
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2 only
    http_endpoint = "enabled"
  }

  tags = {
    Name    = var.instance_name
    Purpose = "vault-genome-hardware-validation"
    Sprint  = "week-2-aws-nitro-enclaves"
    TEE     = "aws-nitro-enclaves"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "instance_id" {
  value = aws_instance.vault_genome.id
}

output "instance_name" {
  value = aws_instance.vault_genome.tags["Name"]
}

output "availability_zone" {
  value = aws_instance.vault_genome.availability_zone
}

output "public_ip" {
  value = aws_instance.vault_genome.public_ip
}

output "ssh_command" {
  value = "ssh -i ~/.ssh/${var.ssh_key_name}.pem ec2-user@${aws_instance.vault_genome.public_ip}"
}

output "ami_id_used" {
  value = data.aws_ami.al2023.id
}
