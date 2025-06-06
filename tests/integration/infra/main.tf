# Terraform Infrastructure for Compliance Scripts Integration Testing
#
# Purpose: This Terraform configuration defines a set of Azure resources
# designed to create a "compliance obstacle course." The resources will have
# varying configurations, some compliant with typical security policies,
# some intentionally non-compliant, to test the detection capabilities of
# verify-compliance.sh and compliance-check.sh.
#
# Usage:
# 1. Initialize Terraform: `terraform init`
# 2. Deploy infrastructure: `terraform apply`
# 3. After running tests: `terraform destroy`
#
# Note: Specific names, locations, and resource properties should be
# parameterized or easily modifiable for different testing environments.

# --- Provider Configuration ---
# provider "azurerm" {
#   features {}
#   # Ensure you are logged in via Azure CLI or have other authentication configured.
# }

# --- Resource Group ---
# resource "azurerm_resource_group" "rg_integration_test" {
#   name     = "rg-compliance-integration-tests"
#   location = "East US" # Or a configurable location
# }

# --- Log Analytics Workspace (for Diagnostic Settings) ---
# resource "azurerm_log_analytics_workspace" "la_workspace_integration" {
#   name                = "la-compliance-tests"
#   location            = azurerm_resource_group.rg_integration_test.location
#   resource_group_name = azurerm_resource_group.rg_integration_test.name
#   sku                 = "PerGB2018"
#   retention_in_days   = 30 # Short retention for test environment
# }

# --- Key Vaults ---
# Scenario 1: Compliant Key Vault
# resource "azurerm_key_vault" "kv_compliant" {
#   name                        = "kv-compliant-tests"
#   location                    = azurerm_resource_group.rg_integration_test.location
#   resource_group_name         = azurerm_resource_group.rg_integration_test.name
#   tenant_id                   = data.azurerm_client_config.current.tenant_id
#   sku_name                    = "premium" # For HSM keys
#   enabled_for_disk_encryption = true
#   enable_soft_delete          = true
#   soft_delete_retention_days  = 90
#   enable_purge_protection     = true
#
#   # Network ACLs (example: default deny)
#   network_acls {
#     default_action = "Deny"
#     bypass         = "AzureServices"
#   }
# }
# resource "azurerm_key_vault_key" "kv_compliant_hsm_key" {
#   name         = "hsm-key-good"
#   key_vault_id = azurerm_key_vault.kv_compliant.id
#   key_type     = "RSA-HSM"
#   key_size     = 2048
#   key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
#   expiration_date = timeadd(timestamp(), "8000h") # Expires in ~11 months
# }

# Scenario 2: Key Vault missing Soft Delete
# resource "azurerm_key_vault" "kv_no_soft_delete" {
#   name                        = "kv-no-soft-delete"
#   location                    = azurerm_resource_group.rg_integration_test.location
#   resource_group_name         = azurerm_resource_group.rg_integration_test.name
#   tenant_id                   = data.azurerm_client_config.current.tenant_id
#   sku_name                    = "standard"
#   enable_soft_delete          = false # INTENTIONALLY NON-COMPLIANT
# }

# Scenario 3: Key Vault with a key expiring soon
# resource "azurerm_key_vault" "kv_key_expiry" {
#   name                        = "kv-key-expiry-test"
#   # ... common properties ...
#   sku_name                    = "premium"
#   enable_soft_delete          = true
#   soft_delete_retention_days  = 7
#   enable_purge_protection     = true
# }
# resource "azurerm_key_vault_key" "kv_expiring_key" {
#   name         = "expiring-key"
#   key_vault_id = azurerm_key_vault.kv_key_expiry.id
#   key_type     = "RSA-HSM"
#   key_size     = 2048
#   key_opts     = ["sign", "verify"]
#   expiration_date = timeadd(timestamp(), "24h") # Expires in 1 day - INTENTIONALLY NON-COMPLIANT for long expiry checks
# }
# resource "azurerm_key_vault_key" "kv_non_hsm_key" {
#   name         = "non-hsm-key"
#   key_vault_id = azurerm_key_vault.kv_key_expiry.id
#   key_type     = "RSA" # INTENTIONALLY NON-HSM for some checks
#   key_size     = 2048
#   key_opts     = ["sign", "verify"]
# }


# --- Storage Accounts ---
# Scenario 1: Compliant Storage Account (CMK, HTTPS, TLS 1.2, No public access)
# resource "azurerm_storage_account" "sa_compliant" {
#   name                     = "sacomplianttests"
#   # ... common properties ...
#   account_tier             = "Standard"
#   account_replication_type = "LRS"
#   enable_https_traffic_only = true
#   min_tls_version          = "TLS1_2"
#   allow_blob_public_access = false
#   # customer_managed_key { # Requires a Key Vault and Key
#   #   key_vault_key_id = azurerm_key_vault_key.kv_compliant_hsm_key.id
#   # }
# }

# Scenario 2: Storage Account without CMK (or using Microsoft Managed Key)
# resource "azurerm_storage_account" "sa_no_cmk" {
#   name                     = "sanocmktests"
#   # ... common properties ...
#   # No customer_managed_key block - INTENTIONALLY NON-COMPLIANT for CMK checks
# }

# Scenario 3: Storage Account with public blob access enabled
# resource "azurerm_storage_account" "sa_public_blob" {
#   name                     = "sapublicblobtests"
#   # ... common properties ...
#   allow_blob_public_access = true # INTENTIONALLY NON-COMPLIANT
# }


# --- Networking ---
# resource "azurerm_virtual_network" "vnet_integration_test" {
#   name                = "vnet-integration-tests"
#   address_space       = ["10.0.0.0/16"]
#   # ... common properties ...
# }

# Subnet 1: "DMZ" - Expects certain ports open from Internet, others prohibited
# resource "azurerm_subnet" "subnet_dmz" {
#   name                 = "snet-dmz"
#   virtual_network_name = azurerm_virtual_network.vnet_integration_test.name
#   resource_group_name  = azurerm_resource_group.rg_integration_test.name
#   address_prefixes     = ["10.0.1.0/24"]
#   # network_security_group_id = azurerm_network_security_group.nsg_dmz.id
# }
# resource "azurerm_network_security_group" "nsg_dmz" {
#   name                = "nsg-dmz"
#   # ... common properties ...
#   security_rule { # Example: Compliant allowed rule (HTTPS)
#     name                       = "AllowHTTPS_Internet"
#     priority                   = 100
#     direction                  = "Inbound"
#     access                     = "Allow"
#     protocol                   = "Tcp"
#     source_port_range          = "*"
#     destination_port_range     = "443"
#     source_address_prefix      = "Internet"
#     destination_address_prefix = "*"
#   }
#   security_rule { # Example: Non-compliant rule (allowing a prohibited port like FTP)
#     name                       = "AllowFTP_Internet"
#     priority                   = 110
#     direction                  = "Inbound"
#     access                     = "Allow"
#     protocol                   = "Tcp"
#     source_port_range          = "*"
#     destination_port_range     = "21" # Assume 21 is prohibited for DMZ in network_requirements.json
#     source_address_prefix      = "Internet"
#     destination_address_prefix = "*"
#   }
# }

# Subnet 2: "Internal" - Expects no direct Internet inbound, specific internal traffic allowed
# resource "azurerm_subnet" "subnet_internal" {
#   name                 = "snet-internal"
#   # ...
#   address_prefixes     = ["10.0.2.0/24"]
#   # network_security_group_id = azurerm_network_security_group.nsg_internal.id
# }
# resource "azurerm_network_security_group" "nsg_internal" {
#   name                = "nsg-internal"
#   # ... common properties ...
#   security_rule { # Example: Missing a required allowed rule (e.g., from another internal subnet)
#     name                       = "AllowSomethingSpecific"
#     priority                   = 100
#     direction                  = "Inbound"
#     access                     = "Allow"
#     protocol                   = "Tcp"
#     source_port_range          = "*"
#     destination_port_range     = "1433" # Example SQL
#     source_address_prefix      = "10.0.3.0/24" # Allowed source
#     destination_address_prefix = "*"
#   }
#   # This NSG might be missing a rule that network_requirements.json says *must* exist for "internal" subnets.
# }

# Subnet 3: "NoNSG" - Intentionally missing an NSG
# resource "azurerm_subnet" "subnet_no_nsg" {
#   name                 = "snet-no-nsg"
#   # ...
#   address_prefixes     = ["10.0.3.0/24"]
#   # No network_security_group_id associated - INTENTIONALLY NON-COMPLIANT for NSG attachment checks
# }

# --- Diagnostic Settings ---
# Scenario 1: Resource with diagnostic settings configured (e.g., for kv_compliant)
# resource "azurerm_monitor_diagnostic_setting" "kv_compliant_diag" {
#   name                       = "kv-compliant-diag-settings"
#   target_resource_id         = azurerm_key_vault.kv_compliant.id
#   log_analytics_workspace_id = azurerm_log_analytics_workspace.la_workspace_integration.id
#
#   log {
#     category = "AuditEvent"
#     enabled  = true
#     retention_policy {
#       enabled = true
#       days    = 90
#     }
#   }
#   # Add metrics as needed
# }

# Scenario 2: Resource without diagnostic settings (e.g., sa_no_cmk)
# This is implicitly tested if sa_no_cmk is checked for diagnostics and none are found.

# --- Helper Data ---
# data "azurerm_client_config" "current" {}

# --- Outputs (Optional) ---
# output "resource_group_name" {
#  value = azurerm_resource_group.rg_integration_test.name
# }
# output "key_vault_compliant_uri" {
#  value = azurerm_key_vault.kv_compliant.vault_uri
# }
# ... other outputs that might be useful for test scripts
