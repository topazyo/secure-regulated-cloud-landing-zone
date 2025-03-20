#!/bin/bash
# verify-compliance.sh
# Comprehensive compliance verification script for secure landing zones
# This script validates compliance across multiple regulatory frameworks
# and security controls after a security incident or as part of routine checks.

set -e

# Configuration
SUBSCRIPTION_ID=""
RESOURCE_GROUP=""
LOG_ANALYTICS_WORKSPACE=""
KEY_VAULT_NAME=""
REPORT_OUTPUT_DIR="./compliance-reports"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
REPORT_FILE="${REPORT_OUTPUT_DIR}/compliance-report-${TIMESTAMP}.json"
CRITICAL_CONTROLS_FILE="./config/compliance/critical_controls.json"
FRAMEWORKS=("PCI-DSS" "SWIFT-SCR" "GDPR")

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Ensure required tools are installed
check_prerequisites() {
    echo -e "${BLUE}[INFO]${NC} Checking prerequisites..."
    
    # Check for Azure CLI
    if ! command -v az &> /dev/null; then
        echo -e "${RED}[ERROR]${NC} Azure CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}[ERROR]${NC} jq is not installed. Please install it first."
        exit 1
    fi
    
    # Check Azure CLI login status
    if ! az account show &> /dev/null; then
        echo -e "${YELLOW}[WARN]${NC} Not logged into Azure. Attempting login..."
        az login
    fi
    
    # Set subscription
    if [ -n "$SUBSCRIPTION_ID" ]; then
        echo -e "${BLUE}[INFO]${NC} Setting subscription to $SUBSCRIPTION_ID"
        az account set --subscription "$SUBSCRIPTION_ID"
    else
        SUBSCRIPTION_ID=$(az account show --query id -o tsv)
        echo -e "${BLUE}[INFO]${NC} Using current subscription: $SUBSCRIPTION_ID"
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$REPORT_OUTPUT_DIR"
}

# Load configuration from environment or parameters
load_configuration() {
    echo -e "${BLUE}[INFO]${NC} Loading configuration..."
    
    # Load from parameters if provided
    while getopts "s:g:w:k:o:" opt; do
        case $opt in
            s) SUBSCRIPTION_ID=$OPTARG ;;
            g) RESOURCE_GROUP=$OPTARG ;;
            w) LOG_ANALYTICS_WORKSPACE=$OPTARG ;;
            k) KEY_VAULT_NAME=$OPTARG ;;
            o) REPORT_OUTPUT_DIR=$OPTARG ;;
            \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
        esac
    done
    
    # If not provided as parameters, try to load from environment
    if [ -z "$RESOURCE_GROUP" ]; then
        RESOURCE_GROUP=${AZURE_RESOURCE_GROUP:-""}
        if [ -z "$RESOURCE_GROUP" ]; then
            echo -e "${YELLOW}[WARN]${NC} Resource group not specified. Will scan all resource groups."
        fi
    fi
    
    if [ -z "$LOG_ANALYTICS_WORKSPACE" ]; then
        LOG_ANALYTICS_WORKSPACE=${AZURE_LOG_ANALYTICS_WORKSPACE:-""}
        if [ -z "$LOG_ANALYTICS_WORKSPACE" ]; then
            echo -e "${YELLOW}[WARN]${NC} Log Analytics workspace not specified. Will attempt to detect."
            # Try to find the security monitoring workspace
            LOG_ANALYTICS_WORKSPACE=$(az monitor log-analytics workspace list --query "[?contains(name, 'security')].name" -o tsv | head -1)
            if [ -n "$LOG_ANALYTICS_WORKSPACE" ]; then
                echo -e "${BLUE}[INFO]${NC} Found Log Analytics workspace: $LOG_ANALYTICS_WORKSPACE"
            fi
        fi
    fi
    
    if [ -z "$KEY_VAULT_NAME" ]; then
        KEY_VAULT_NAME=${AZURE_KEY_VAULT_NAME:-""}
        if [ -z "$KEY_VAULT_NAME" ]; then
            echo -e "${YELLOW}[WARN]${NC} Key Vault not specified. Will attempt to detect."
            # Try to find a key vault
            KEY_VAULT_NAME=$(az keyvault list --query "[0].name" -o tsv)
            if [ -n "$KEY_VAULT_NAME" ]; then
                echo -e "${BLUE}[INFO]${NC} Found Key Vault: $KEY_VAULT_NAME"
            fi
        fi
    fi
}

# Validate network security configuration
validate_network_security() {
    echo -e "${BLUE}[INFO]${NC} Validating network security configuration..."
    
    local results=()
    local status="Compliant"
    
    # Check NSGs for default deny rules
    echo -e "${BLUE}[INFO]${NC} Checking NSG configurations..."
    local nsgs=$(az network nsg list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    
    for nsg in $nsgs; do
        echo -e "${BLUE}[INFO]${NC} Checking NSG: $nsg"
        
        # Check for default deny rule
        local has_default_deny=$(az network nsg show --name "$nsg" --resource-group "$RESOURCE_GROUP" --query "securityRules[?direction=='Inbound' && access=='Deny' && priority>=4000].name" -o tsv)
        
        if [ -z "$has_default_deny" ]; then
            echo -e "${RED}[FAIL]${NC} NSG $nsg does not have a default deny rule"
            results+=("NSG $nsg: Missing default deny rule")
            status="Non-Compliant"
        else
            echo -e "${GREEN}[PASS]${NC} NSG $nsg has default deny rule"
        fi
        
        # Check for overly permissive rules
        local permissive_rules=$(az network nsg show --name "$nsg" --resource-group "$RESOURCE_GROUP" --query "securityRules[?direction=='Inbound' && access=='Allow' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet')].name" -o tsv)
        
        if [ -n "$permissive_rules" ]; then
            echo -e "${RED}[FAIL]${NC} NSG $nsg has overly permissive rules: $permissive_rules"
            results+=("NSG $nsg: Overly permissive rules found")
            status="Non-Compliant"
        else
            echo -e "${GREEN}[PASS]${NC} NSG $nsg has no overly permissive rules"
        fi
    done
    
    # Check network isolation between critical segments
    echo -e "${BLUE}[INFO]${NC} Checking network isolation..."
    
    # This would typically use Network Watcher to verify isolation
    # For this script, we'll check for the existence of proper NSG associations
    
    local subnets=$(az network vnet subnet list --resource-group "$RESOURCE_GROUP" --vnet-name $(az network vnet list --resource-group "$RESOURCE_GROUP" --query "[0].name" -o tsv) --query "[].name" -o tsv 2>/dev/null || echo "")
    
    if [ -n "$subnets" ]; then
        for subnet in $subnets; do
            local nsg_id=$(az network vnet subnet show --resource-group "$RESOURCE_GROUP" --vnet-name $(az network vnet list --resource-group "$RESOURCE_GROUP" --query "[0].name" -o tsv) --name "$subnet" --query "networkSecurityGroup.id" -o tsv)
            
            if [ -z "$nsg_id" ] || [ "$nsg_id" == "null" ]; then
                echo -e "${RED}[FAIL]${NC} Subnet $subnet does not have an NSG attached"
                results+=("Subnet $subnet: No NSG attached")
                status="Non-Compliant"
            else
                echo -e "${GREEN}[PASS]${NC} Subnet $subnet has NSG attached"
            fi
        done
    else
        echo -e "${YELLOW}[WARN]${NC} No subnets found or unable to list subnets"
    fi
    
    echo -e "${BLUE}[INFO]${NC} Network security validation complete. Status: $status"
    
    # Return results as JSON
    local json_results=$(printf '%s\n' "${results[@]}" | jq -R . | jq -s .)
    echo "{\"category\": \"NetworkSecurity\", \"status\": \"$status\", \"findings\": $json_results}"
}

# Validate encryption configuration
validate_encryption() {
    echo -e "${BLUE}[INFO]${NC} Validating encryption configuration..."
    
    local results=()
    local status="Compliant"
    
    # Check Key Vault configuration
    if [ -n "$KEY_VAULT_NAME" ]; then
        echo -e "${BLUE}[INFO]${NC} Checking Key Vault: $KEY_VAULT_NAME"
        
        # Check HSM protection
        local sku=$(az keyvault show --name "$KEY_VAULT_NAME" --query "properties.sku.name" -o tsv)
        if [ "$sku" != "Premium" ]; then
            echo -e "${RED}[FAIL]${NC} Key Vault $KEY_VAULT_NAME is not using Premium SKU (HSM)"
            results+=("Key Vault $KEY_VAULT_NAME: Not using Premium SKU (HSM)")
            status="Non-Compliant"
        else
            echo -e "${GREEN}[PASS]${NC} Key Vault $KEY_VAULT_NAME is using Premium SKU (HSM)"
        fi
        
        # Check soft delete and purge protection
        local soft_delete=$(az keyvault show --name "$KEY_VAULT_NAME" --query "properties.enableSoftDelete" -o tsv)
        local purge_protection=$(az keyvault show --name "$KEY_VAULT_NAME" --query "properties.enablePurgeProtection" -o tsv)
        
        if [ "$soft_delete" != "true" ]; then
            echo -e "${RED}[FAIL]${NC} Key Vault $KEY_VAULT_NAME does not have soft delete enabled"
            results+=("Key Vault $KEY_VAULT_NAME: Soft delete not enabled")
            status="Non-Compliant"
        else
            echo -e "${GREEN}[PASS]${NC} Key Vault $KEY_VAULT_NAME has soft delete enabled"
        fi
        
        if [ "$purge_protection" != "true" ]; then
            echo -e "${RED}[FAIL]${NC} Key Vault $KEY_VAULT_NAME does not have purge protection enabled"
            results+=("Key Vault $KEY_VAULT_NAME: Purge protection not enabled")
            status="Non-Compliant"
        else
            echo -e "${GREEN}[PASS]${NC} Key Vault $KEY_VAULT_NAME has purge protection enabled"
        fi
        
        # Check key types and rotation
        echo -e "${BLUE}[INFO]${NC} Checking key configurations..."
        local keys=$(az keyvault key list --vault-name "$KEY_VAULT_NAME" --query "[].name" -o tsv)
        
        for key in $keys; do
            local key_type=$(az keyvault key show --vault-name "$KEY_VAULT_NAME" --name "$key" --query "key.kty" -o tsv)
            
            if [[ "$key_type" != *"HSM"* ]]; then
                echo -e "${RED}[FAIL]${NC} Key $key is not HSM-protected ($key_type)"
                results+=("Key $key: Not HSM-protected")
                status="Non-Compliant"
            else
                echo -e "${GREEN}[PASS]${NC} Key $key is HSM-protected"
            fi
            
            # Check key expiration (if set)
            local expires=$(az keyvault key show --vault-name "$KEY_VAULT_NAME" --name "$key" --query "attributes.expires" -o tsv)
            
            if [ -z "$expires" ] || [ "$expires" == "null" ]; then
                echo -e "${RED}[FAIL]${NC} Key $key does not have an expiration date set"
                results+=("Key $key: No expiration date")
                status="Non-Compliant"
            else
                # Convert to timestamp and check if within 90 days
                local expires_ts=$(date -d "$expires" +%s)
                local now_ts=$(date +%s)
                local diff_days=$(( (expires_ts - now_ts) / 86400 ))
                
                if [ $diff_days -gt 90 ]; then
                    echo -e "${RED}[FAIL]${NC} Key $key rotation period exceeds 90 days ($diff_days days)"
                    results+=("Key $key: Rotation period exceeds 90 days")
                    status="Non-Compliant"
                else
                    echo -e "${GREEN}[PASS]${NC} Key $key has proper rotation period ($diff_days days)"
                fi
            fi
        done
    else
        echo -e "${YELLOW}[WARN]${NC} No Key Vault specified, skipping encryption validation"
        results+=("No Key Vault specified for validation")
    fi
    
    # Check storage account encryption
    echo -e "${BLUE}[INFO]${NC} Checking storage account encryption..."
    local storage_accounts=$(az storage account list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv 2>/dev/null || echo "")
    
    if [ -n "$storage_accounts" ]; then
        for sa in $storage_accounts; do
            local encryption_enabled=$(az storage account show --name "$sa" --query "encryption.services.blob.enabled" -o tsv)
            local encryption_type=$(az storage account show --name "$sa" --query "encryption.keySource" -o tsv)
            
            if [ "$encryption_enabled" != "true" ]; then
                echo -e "${RED}[FAIL]${NC} Storage account $sa does not have encryption enabled"
                results+=("Storage account $sa: Encryption not enabled")
                status="Non-Compliant"
            else
                echo -e "${GREEN}[PASS]${NC} Storage account $sa has encryption enabled"
            fi
            
            if [ "$encryption_type" != "Microsoft.Keyvault" ]; then
                echo -e "${YELLOW}[WARN]${NC} Storage account $sa is not using Key Vault for encryption keys"
                results+=("Storage account $sa: Not using Key Vault for encryption")
            else
                echo -e "${GREEN}[PASS]${NC} Storage account $sa is using Key Vault for encryption"
            fi
        done
    else
        echo -e "${YELLOW}[WARN]${NC} No storage accounts found or unable to list storage accounts"
    fi
    
    echo -e "${BLUE}[INFO]${NC} Encryption validation complete. Status: $status"
    
    # Return results as JSON
    local json_results=$(printf '%s\n' "${results[@]}" | jq -R . | jq -s .)
    echo "{\"category\": \"Encryption\", \"status\": \"$status\", \"findings\": $json_results}"
}

# Validate identity and access controls
validate_identity_access() {
    echo -e "${BLUE}[INFO]${NC} Validating identity and access controls..."
    
    local results=()
    local status="Compliant"
    
    # Check for privileged role assignments
    echo -e "${BLUE}[INFO]${NC} Checking privileged role assignments..."
    local privileged_roles=("Owner" "Contributor" "User Access Administrator")
    
    for role in "${privileged_roles[@]}"; do
        local assignments=$(az role assignment list --role "$role" --scope "/subscriptions/$SUBSCRIPTION_ID" --query "[].principalName" -o tsv)
        
        if [ -n "$assignments" ]; then
            echo -e "${YELLOW}[WARN]${NC} Found principals with $role role: $assignments"
            results+=("Privileged role $role assigned to: $assignments")
            
            # Check if these are permanent assignments (not PIM)
            # This is a simplified check - in reality, you'd need to use Microsoft Graph API to check PIM status
            local permanent_count=$(echo "$assignments" | wc -l)
            if [ $permanent_count -gt 3 ]; then
                echo -e "${RED}[FAIL]${NC} Too many permanent $role assignments ($permanent_count)"
                status="Non-Compliant"
            fi
        else
            echo -e "${GREEN}[PASS]${NC} No direct assignments for $role role"
        fi
    done
    
    # Check for custom RBAC roles
    echo -e "${BLUE}[INFO]${NC} Checking custom RBAC roles..."
    local custom_roles=$(az role definition list --custom-role-only true --scope "/subscriptions/$SUBSCRIPTION_ID" --query "[].roleName" -o tsv)
    
    if [ -n "$custom_roles" ]; then
        echo -e "${BLUE}[INFO]${NC} Found custom roles: $custom_roles"
        
        for role in $custom_roles; do
            # Check if the role has wildcard actions
            local wildcard_actions=$(az role definition list --name "$role" --query "[0].permissions[0].actions[?contains(@, '*')]" -o tsv)
            
            if [ -n "$wildcard_actions" ]; then
                echo -e "${RED}[FAIL]${NC} Custom role $role has wildcard permissions: $wildcard_actions"
                results+=("Custom role $role: Has wildcard permissions")
                status="Non-Compliant"
            else
                echo -e "${GREEN}[PASS]${NC} Custom role $role has no wildcard permissions"
            fi
        done
    else
        echo -e "${GREEN}[PASS]${NC} No custom RBAC roles defined"
    fi
    
    # Check for MFA enforcement
    # Note: This requires Microsoft Graph API access, which is beyond the scope of az CLI
    # For a real implementation, you would use Microsoft Graph API or Azure AD PowerShell
    echo -e "${YELLOW}[WARN]${NC} MFA validation requires Microsoft Graph API access - skipping"
    results+=("MFA validation: Requires Microsoft Graph API - not performed")
    
    echo -e "${BLUE}[INFO]${NC} Identity and access validation complete. Status: $status"
    
    # Return results as JSON
    local json_results=$(printf '%s\n' "${results[@]}" | jq -R . | jq -s .)
    echo "{\"category\": \"IdentityAccess\", \"status\": \"$status\", \"findings\": $json_results}"
}

# Validate logging and monitoring
validate_logging_monitoring() {
    echo -e "${BLUE}[INFO]${NC} Validating logging and monitoring configuration..."
    
    local results=()
    local status="Compliant"
    
    # Check diagnostic settings
    echo -e "${BLUE}[INFO]${NC} Checking diagnostic settings..."
    
    # Check Key Vault logging
    if [ -n "$KEY_VAULT_NAME" ]; then
        local kv_diag=$(az monitor diagnostic-settings list --resource "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEY_VAULT_NAME" --query "[0].name" -o tsv 2>/dev/null || echo "")
        
        if [ -z "$kv_diag" ]; then
            echo -e "${RED}[FAIL]${NC} Key Vault $KEY_VAULT_NAME has no diagnostic settings"
            results+=("Key Vault $KEY_VAULT_NAME: No diagnostic settings")
            status="Non-Compliant"
        else
            echo -e "${GREEN}[PASS]${NC} Key Vault $KEY_VAULT_NAME has diagnostic settings"
            
            # Check if all required logs are enabled
            local audit_logs_enabled=$(az monitor diagnostic-settings show --resource "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEY_VAULT_NAME" --name "$kv_diag" --query "logs[?category=='AuditEvent'].enabled" -o tsv)
            
            if [ "$audit_logs_enabled" != "true" ]; then
                echo -e "${RED}[FAIL]${NC} Key Vault audit logs are not enabled"
                results+=("Key Vault $KEY_VAULT_NAME: Audit logs not enabled")
                status="Non-Compliant"
            else
                echo -e "${GREEN}[PASS]${NC} Key Vault audit logs are enabled"
            fi
        fi
    fi
    
    # Check NSG flow logs
    echo -e "${BLUE}[INFO]${NC} Checking NSG flow logs..."
    local nsgs=$(az network nsg list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    
    for nsg in $nsgs; do
        # This is a simplified check - in reality, NSG flow logs are configured through Network Watcher
        local flow_logs=$(az network watcher flow-log list --location $(az network nsg show --name "$nsg" --resource-group "$RESOURCE_GROUP" --query "location" -o tsv) --query "[?contains(targetResourceId, '$nsg')].name" -o tsv 2>/dev/null || echo "")
        
        if [ -z "$flow_logs" ]; then
            echo -e "${RED}[FAIL]${NC} NSG $nsg has no flow logs configured"
            results+=("NSG $nsg: No flow logs configured")
            status="Non-Compliant"
        else
            echo -e "${GREEN}[PASS]${NC} NSG $nsg has flow logs configured"
            
            # Check retention period
            local retention=$(az network watcher flow-log show --name "$flow_logs" --location $(az network nsg show --name "$nsg" --resource-group "$RESOURCE_GROUP" --query "location" -o tsv) --query "retentionPolicy.days" -o tsv 2>/dev/null || echo "0")
            
            if [ "$retention" -lt 90 ]; then
                echo -e "${RED}[FAIL]${NC} NSG flow logs retention period is less than 90 days ($retention days)"
                results+=("NSG $nsg: Flow logs retention < 90 days")
                status="Non-Compliant"
            else
                echo -e "${GREEN}[PASS]${NC} NSG flow logs retention period is compliant ($retention days)"
            fi
        fi
    done
    
    # Check Activity Log settings
    echo -e "${BLUE}[INFO]${NC} Checking Activity Log settings..."
    local activity_log_settings=$(az monitor log-profiles list --query "[0].name" -o tsv 2>/dev/null || echo "")
    
    if [ -z "$activity_log_settings" ]; then
        echo -e "${RED}[FAIL]${NC} No Activity Log profile configured"
        results+=("Activity Log: No profile configured")
        status="Non-Compliant"
    else
        echo -e "${GREEN}[PASS]${NC} Activity Log profile is configured"
        
        # Check retention
        local retention=$(az monitor log-profiles list --query "[0].retentionPolicy.days" -o tsv)
        
        if [ "$retention" -lt 365 ]; then
            echo -e "${RED}[FAIL]${NC} Activity Log retention period is less than 365 days ($retention days)"
            results+=("Activity Log: Retention < 365 days")
            status="Non-Compliant"
        else
            echo -e "${GREEN}[PASS]${NC} Activity Log retention period is compliant ($retention days)"
        fi
    fi
    
    # Check Log Analytics workspace
    if [ -n "$LOG_ANALYTICS_WORKSPACE" ]; then
        echo -e "${BLUE}[INFO]${NC} Checking Log Analytics workspace: $LOG_ANALYTICS_WORKSPACE"
        
        # Check retention period
        local retention=$(az monitor log-analytics workspace show --resource-group "$RESOURCE_GROUP" --workspace-name "$LOG_ANALYTICS_WORKSPACE" --query "retentionInDays" -o tsv 2>/dev/null || echo "0")
        
        if [ "$retention" -lt 365 ]; then
            echo -e "${RED}[FAIL]${NC} Log Analytics workspace retention is less than 365 days ($retention days)"
            results+=("Log Analytics: Retention < 365 days")
            status="Non-Compliant"
        else
            echo -e "${GREEN}[PASS]${NC} Log Analytics workspace retention is compliant ($retention days)"
        fi
        
        # Check if Security Insights (Sentinel) is enabled
        local sentinel_solution=$(az monitor log-analytics solution list --resource-group "$RESOURCE_GROUP" --query "[?contains(name, 'SecurityInsights')].name" -o tsv 2>/dev/null || echo "")
        
        if [ -z "$sentinel_solution" ]; then
            echo -e "${YELLOW}[WARN]${NC} Security Insights (Sentinel) is not enabled"
            results+=("Log Analytics: Security Insights not enabled")
        else
            echo -e "${GREEN}[PASS]${NC} Security Insights (Sentinel) is enabled"
        fi
    else
        echo -e "${YELLOW}[WARN]${NC} No Log Analytics workspace specified, skipping workspace checks"
        results+=("Log Analytics: No workspace specified")
    fi
    
    echo -e "${BLUE}[INFO]${NC} Logging and monitoring validation complete. Status: $status"
    
    # Return results as JSON
    local json_results=$(printf '%s\n' "${results[@]}" | jq -R . | jq -s .)
    echo "{\"category\": \"LoggingMonitoring\", \"status\": \"$status\", \"findings\": $json_results}"
}

# Validate regulatory compliance
validate_regulatory_compliance() {
    echo -e "${BLUE}[INFO]${NC} Validating regulatory compliance..."
    
    local results=()
    local status="Compliant"
    
    # For each regulatory framework
    for framework in "${FRAMEWORKS[@]}"; do
        echo -e "${BLUE}[INFO]${NC} Checking compliance with $framework..."
        
        case $framework in
            "PCI-DSS")
                # Check PCI-DSS specific requirements
                local pci_results=$(validate_pci_dss)
                local pci_status=$(echo "$pci_results" | jq -r '.status')
                
                if [ "$pci_status" != "Compliant" ]; then
                    status="Non-Compliant"
                fi
                
                results+=("$framework: $pci_status")
                ;;
                
            "SWIFT-SCR")
                # Check SWIFT-SCR specific requirements
                local swift_results=$(validate_swift_scr)
                local swift_status=$(echo "$swift_results" | jq -r '.status')
                
                if [ "$swift_status" != "Compliant" ]; then
                    status="Non-Compliant"
                fi
                
                results+=("$framework: $swift_status")
                ;;
                
            "GDPR")
                # Check GDPR specific requirements
                local gdpr_results=$(validate_gdpr)
                local gdpr_status=$(echo "$gdpr_results" | jq -r '.status')
                
                if [ "$gdpr_status" != "Compliant" ]; then
                    status="Non-Compliant"
                fi
                
                results+=("$framework: $gdpr_status")
                ;;
        esac
    done
    
    echo -e "${BLUE}[INFO]${NC} Regulatory compliance validation complete. Status: $status"
    
    # Return results as JSON
    local json_results=$(printf '%s\n' "${results[@]}" | jq -R . | jq -s .)
    echo "{\"category\": \"RegulatoryCompliance\", \"status\": \"$status\", \"findings\": $json_results}"
}

# Validate PCI-DSS compliance
validate_pci_dss() {
    local results=()
    local status="Compliant"
    
    # Check requirement 1.1 - Network segmentation
    echo -e "${BLUE}[INFO]${NC} Checking PCI-DSS Requirement 1.1 - Network segmentation..."
    local network_results=$(validate_network_security)
    local network_status=$(echo "$network_results" | jq -r '.status')
    
    if [ "$network_status" != "Compliant" ]; then
        echo -e "${RED}[FAIL]${NC} PCI-DSS Requirement 1.1 - Network segmentation is non-compliant"
        results+=("Requirement 1.1: Non-Compliant")
        status="Non-Compliant"
    else
        echo -e "${GREEN}[PASS]${NC} PCI-DSS Requirement 1.1 - Network segmentation is compliant"
        results+=("Requirement 1.1: Compliant")
    fi
    
    # Check requirement 3.4 - Encryption
    echo -e "${BLUE}[INFO]${NC} Checking PCI-DSS Requirement 3.4 - Encryption..."
    local encryption_results=$(validate_encryption)
    local encryption_status=$(echo "$encryption_results" | jq -r '.status')
    
    if [ "$encryption_status" != "Compliant" ]; then
        echo -e "${RED}[FAIL]${NC} PCI-DSS Requirement 3.4 - Encryption is non-compliant"
        results+=("Requirement 3.4: Non-Compliant")
        status="Non-Compliant"
    else
        echo -e "${GREEN}[PASS]${NC} PCI-DSS Requirement 3.4 - Encryption is compliant"
        results+=("Requirement 3.4: Compliant")
    fi
    
    # Check requirement 10.2 - Logging
    echo -e "${BLUE}[INFO]${NC} Checking PCI-DSS Requirement 10.2 - Logging..."
    local logging_results=$(validate_logging_monitoring)
    local logging_status=$(echo "$logging_results" | jq -r '.status')
    
    if [ "$logging_status" != "Compliant" ]; then
        echo -e "${RED}[FAIL]${NC} PCI-DSS Requirement 10.2 - Logging is non-compliant"
        results+=("Requirement 10.2: Non-Compliant")
        status="Non-Compliant"
    else
        echo -e "${GREEN}[PASS]${NC} PCI-DSS Requirement 10.2 - Logging is compliant"
        results+=("Requirement 10.2: Compliant")
    fi
    
    # Return results as JSON
    local json_results=$(printf '%s\n' "${results[@]}" | jq -R . | jq -s .)
    echo "{\"framework\": \"PCI-DSS\", \"status\": \"$status\", \"findings\": $json_results}"
}

# Validate SWIFT-SCR compliance
validate_swift_scr() {
    local results=()
    local status="Compliant"
    
    # Check SWIFT-SCR specific requirements
    echo -e "${BLUE}[INFO]${NC} Checking SWIFT-SCR requirements..."
    
    # Check requirement 1.1 - Restrict Internet Access
    echo -e "${BLUE}[INFO]${NC} Checking SWIFT-SCR Requirement 1.1 - Restrict Internet Access..."
    local network_results=$(validate_network_security)
    local network_status=$(echo "$network_results" | jq -r '.status')
    
    if [ "$network_status" != "Compliant" ]; then
        echo -e "${RED}[FAIL]${NC} SWIFT-SCR Requirement 1.1 - Restrict Internet Access is non-compliant"
        results+=("Requirement 1.1: Non-Compliant")
        status="Non-Compliant"
    else
        echo -e "${GREEN}[PASS]${NC} SWIFT-SCR Requirement 1.1 - Restrict Internet Access is compliant"
        results+=("Requirement 1.1: Compliant")
    fi
    
    # Check requirement 2.2 - Multi-factor Authentication
    echo -e "${BLUE}[INFO]${NC} Checking SWIFT-SCR Requirement 2.2 - Multi-factor Authentication..."
    # This is a placeholder - actual MFA validation requires Microsoft Graph API
    echo -e "${YELLOW}[WARN]${NC} SWIFT-SCR Requirement 2.2 - MFA validation requires Microsoft Graph API - skipping"
    results+=("Requirement 2.2: Validation requires Microsoft Graph API - not performed")
    
    # Return results as JSON
    local json_results=$(printf '%s\n' "${results[@]}" | jq -R . | jq -s .)
    echo "{\"framework\": \"SWIFT-SCR\", \"status\": \"$status\", \"findings\": $json_results}"
}

# Validate GDPR compliance
validate_gdpr() {
    local results=()
    local status="Compliant"
    
    # Check GDPR specific requirements
    echo -e "${BLUE}[INFO]${NC} Checking GDPR requirements..."
    
    # Check encryption for personal data
    echo -e "${BLUE}[INFO]${NC} Checking GDPR - Encryption for personal data..."
    local encryption_results=$(validate_encryption)
    local encryption_status=$(echo "$encryption_results" | jq -r '.status')
    
    if [ "$encryption_status" != "Compliant" ]; then
        echo -e "${RED}[FAIL]${NC} GDPR - Encryption for personal data is non-compliant"
        results+=("Encryption: Non-Compliant")
        status="Non-Compliant"
    else
        echo -e "${GREEN}[PASS]${NC} GDPR - Encryption for personal data is compliant"
        results+=("Encryption: Compliant")
    fi
    
    # Check logging and monitoring for breach detection
    echo -e "${BLUE}[INFO]${NC} Checking GDPR - Logging for breach detection..."
    local logging_results=$(validate_logging_monitoring)
    local logging_status=$(echo "$logging_results" | jq -r '.status')
    
    if [ "$logging_status" != "Compliant" ]; then
        echo -e "${RED}[FAIL]${NC} GDPR - Logging for breach detection is non-compliant"
        results+=("Logging: Non-Compliant")
        status="Non-Compliant"
    else
        echo -e "${GREEN}[PASS]${NC} GDPR - Logging for breach detection is compliant"
        results+=("Logging: Compliant")
    fi
    
    # Return results as JSON
    local json_results=$(printf '%s\n' "${results[@]}" | jq -R . | jq -s .)
    echo "{\"framework\": \"GDPR\", \"status\": \"$status\", \"findings\": $json_results}"
}

# Generate comprehensive compliance report
generate_compliance_report() {
    echo -e "${BLUE}[INFO]${NC} Generating comprehensive compliance report..."
    
    # Collect all validation results
    local network_results=$(validate_network_security)
    local encryption_results=$(validate_encryption)
    local identity_results=$(validate_identity_access)
    local logging_results=$(validate_logging_monitoring)
    local regulatory_results=$(validate_regulatory_compliance)
    
    # Determine overall compliance status
    local overall_status="Compliant"
    
    if [ "$(echo "$network_results" | jq -r '.status')" != "Compliant" ] || \
       [ "$(echo "$encryption_results" | jq -r '.status')" != "Compliant" ] || \
       [ "$(echo "$identity_results" | jq -r '.status')" != "Compliant" ] || \
       [ "$(echo "$logging_results" | jq -r '.status')" != "Compliant" ] || \
       [ "$(echo "$regulatory_results" | jq -r '.status')" != "Compliant" ]; then
        overall_status="Non-Compliant"
    fi
    
    # Create the report JSON
    local report=$(cat <<EOF
{
  "complianceReport": {
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "environment": {
      "subscriptionId": "$SUBSCRIPTION_ID",
      "resourceGroup": "$RESOURCE_GROUP"
    },
    "overallStatus": "$overall_status",
    "categories": {
      "networkSecurity": $(echo "$network_results"),
      "encryption": $(echo "$encryption_results"),
      "identityAccess": $(echo "$identity_results"),
      "loggingMonitoring": $(echo "$logging_results"),
      "regulatoryCompliance": $(echo "$regulatory_results")
    }
  }
}
EOF
)
    
    # Save the report to a file
    echo "$report" | jq . > "$REPORT_FILE"
    
    echo -e "${GREEN}[SUCCESS]${NC} Compliance report generated: $REPORT_FILE"
    
    # Print summary
    echo -e "\n${BLUE}=== Compliance Summary ===${NC}"
    echo -e "Overall Status: $(if [ "$overall_status" == "Compliant" ]; then echo -e "${GREEN}$overall_status${NC}"; else echo -e "${RED}$overall_status${NC}"; fi)"
    echo -e "Network Security: $(if [ "$(echo "$network_results" | jq -r '.status')" == "Compliant" ]; then echo -e "${GREEN}Compliant${NC}"; else echo -e "${RED}Non-Compliant${NC}"; fi)"
    echo -e "Encryption: $(if [ "$(echo "$encryption_results" | jq -r '.status')" == "Compliant" ]; then echo -e "${GREEN}Compliant${NC}"; else echo -e "${RED}Non-Compliant${NC}"; fi)"
    echo -e "Identity & Access: $(if [ "$(echo "$identity_results" | jq -r '.status')" == "Compliant" ]; then echo -e "${GREEN}Compliant${NC}"; else echo -e "${RED}Non-Compliant${NC}"; fi)"
    echo -e "Logging & Monitoring: $(if [ "$(echo "$logging_results" | jq -r '.status')" == "Compliant" ]; then echo -e "${GREEN}Compliant${NC}"; else echo -e "${RED}Non-Compliant${NC}"; fi)"
    echo -e "Regulatory Compliance: $(if [ "$(echo "$regulatory_results" | jq -r '.status')" == "Compliant" ]; then echo -e "${GREEN}Compliant${NC}"; else echo -e "${RED}Non-Compliant${NC}"; fi)"
    
    return 0
}

# Main function
main() {
    echo -e "${BLUE}=== Secure Landing Zone Compliance Verification ===${NC}"
    echo -e "${BLUE}=== $(date) ===${NC}\n"
    
    # Check prerequisites
    check_prerequisites
    
    # Load configuration
    load_configuration "$@"
    
    # Generate comprehensive compliance report
    generate_compliance_report
    
    # Return exit code based on compliance status
    if grep -q "Non-Compliant" "$REPORT_FILE"; then
        echo -e "\n${RED}[ALERT]${NC} Compliance verification failed. Please review the report and address the findings."
        return 1
    else
        echo -e "\n${GREEN}[SUCCESS]${NC} Compliance verification passed."
        return 0
    fi
}

# Run the main function
main "$@"