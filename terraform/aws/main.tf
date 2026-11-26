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

resource "aws_kms_key" "manifest_signing" {
  description         = "G1-Manifest envelope encryption / signing KMS key"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "manifest_artifacts" {
  bucket              = var.bucket_name
  object_lock_enabled = true
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
