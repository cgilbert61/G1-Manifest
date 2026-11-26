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

resource "google_storage_bucket" "manifest_artifacts" {
  name                        = var.bucket_name
  project                     = var.project_id
  location                    = "US"
  uniform_bucket_level_access = true

  retention_policy {
    retention_period = 7776000 # 90 days
    is_locked        = false
  }
}
