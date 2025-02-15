variable "location" {
  type        = string
  description = "Azure region for HSM deployment"
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name"
}

resource "azurerm_key_vault" "hsm" {
  name                       = "hsm-${var.environment}"
  location                   = var.location
  resource_group_name        = var.resource_group_name
  sku_name                   = "Premium"
  soft_delete_retention_days = 90
  purge_protection_enabled   = true

  network_acls {
    bypass         = "AzureServices"
    default_action = "Deny"
  }
}

# Add HSM-specific key configurations and access policies