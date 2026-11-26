# G1-Manifest AWS Foundation: KMS Signing Key + WORM Object-Lock Artifact Bucket
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name for signed DSSE estate-graph envelopes"
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "manifest_signing" {
  description         = "G1-Manifest envelope encryption / signing KMS key"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAccountPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_s3_bucket" "manifest_artifacts" {
  bucket              = var.bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_public_access_block" "manifest_artifacts" {
  bucket                  = aws_s3_bucket.manifest_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "manifest_artifacts" {
  bucket = aws_s3_bucket.manifest_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "manifest_artifacts" {
  bucket = aws_s3_bucket.manifest_artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.manifest_signing.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "manifest_artifacts" {
  bucket = aws_s3_bucket.manifest_artifacts.id
  rule {
    id     = "archive-old-envelopes"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "worm" {
  bucket = aws_s3_bucket.manifest_artifacts.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90
    }
  }
}
