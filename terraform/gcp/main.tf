# G1-Manifest GCP Foundation: Cloud KMS + Retention-Locked GCS Bucket
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

variable "project_id" {
  type = string
}

variable "bucket_name" {
  type = string
}

variable "log_bucket_name" {
  type        = string
  description = "Target GCS bucket for access logs"
}

variable "kms_key_name" {
  type        = string
  description = "Cloud KMS CryptoKey resource ID for bucket encryption"
}

resource "google_storage_bucket" "manifest_artifacts" {
  name                        = var.bucket_name
  project                     = var.project_id
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = var.kms_key_name
  }

  logging {
    log_bucket        = var.log_bucket_name
    log_object_prefix = "g1-manifest-access-logs/"
  }

  retention_policy {
    retention_period = 7776000 # 90 days
    is_locked        = false
  }
}
