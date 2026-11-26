# G1-Manifest Azure Foundation: Key Vault + Immutable Blob Storage
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.90"
    }
  }
}

variable "location" {
  type    = string
  default = "eastus"
}

resource "azurerm_resource_group" "manifest" {
  name     = "rg-g1-manifest"
  location = var.location
}
