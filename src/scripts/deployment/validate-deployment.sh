#!/bin/bash
set -e

# Secure Landing Zone Deployment Validation Script
# This script validates all security and compliance aspects of the deployment

# Configuration
SUBSCRIPTION_ID=${AZURE_SUBSCRIPTION_ID:-$(az account show --query id -o tsv)}
RESOURCE_GROUP=${RESOURCE_GROUP_NAME:-"secure-landing-zone-rg"}
LOCATION=${LOCATION:-"switzerlandnorth"}
LOG_FILE="deployment-validation-$(date +%Y%m%d%H%M%S).log"

# Ensure log directory exists
mkdir -p logs
LOG_PATH="logs/$LOG_FILE"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Log to file
    echo "[$timestamp] [$level] $message" >> $LOG_PATH
    
    # Log to console with color
    case $level in
        "INFO")
            echo -e "${BLUE}[$level]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[$level]${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[$level]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[$level]${NC} $message"
            ;;
        *)
            echo "[$level] $message"
            ;;
    esac
}

# Setup function
setup() {
    log "INFO" "Starting deployment validation for Secure Landing Zone"
    log "INFO" "Subscription: $SUBSCRIPTION_ID"
    log "INFO" "Resource Group: $RESOURCE_GROUP"
    
    # Check if logged in to Azure
    az account show &> /dev/null || {
        log "ERROR" "Not logged in to Azure. Please run 'az login'"
        exit 1
    }
    
    # Set subscription context
    az account set --subscription "$SUBSCRIPTION_ID"
    log "INFO" "Azure CLI context set to subscription: $SUBSCRIPTION_ID"
    
    # Check if resource group exists
    az group show --name "$RESOURCE_GROUP" &> /dev/null || {
        log "ERROR" "Resource group '$RESOURCE_GROUP' does not exist"
        exit 1
    }
}

# Validate network security
validate_network_security() {
    log "INFO" "Validating network security configuration..."
    
    # Check Network Security Groups
    NSG_COUNT=$(az network nsg list --resource-group "$RESOURCE_GROUP" --query "length(@)" -o tsv)
    if [ "$NSG_COUNT" -eq 0 ]; then
        log "ERROR" "No Network Security Groups found in resource group"
        return 1
    fi
    log "INFO" "Found $NSG_COUNT Network Security Groups"

    # Check for default deny rules
    DEFAULT_DENY_COUNT=$(az network nsg list --resource-group "$RESOURCE_GROUP" --query "[].securityRules[?access=='Deny' && direction=='Inbound' && priority>=4000].name" -o tsv | wc -l)
    if [ "$DEFAULT_DENY_COUNT" -eq 0 ]; then
        log "WARNING" "No default deny rules found in NSGs"
    else
        log "SUCCESS" "Found $DEFAULT_DENY_COUNT default deny rules in NSGs"
    fi
    
    # Check Network Watcher flow logs
    FLOW_LOGS_ENABLED=$(az network watcher flow-log list --location "$LOCATION" --query "[?resourceGroupName=='$RESOURCE_GROUP' && enabled==\`true\`].name" -o tsv)
    if [ -z "$FLOW_LOGS_ENABLED" ]; then
        log "WARNING" "Network flow logs are not enabled"
    else
        log "SUCCESS" "Network flow logs are properly configured"
    fi
    
    # Check subnet segregation
    SUBNETS=$(az network vnet list --resource-group "$RESOURCE_GROUP" --query "[].subnets[].name" -o tsv)
    if [[ "$SUBNETS" == *"swift"* ]] && [[ "$SUBNETS" == *"pci"* ]]; then
        log "SUCCESS" "Proper subnet segregation found"
    else
        log "WARNING" "Expected subnet segregation not found"
    fi
    
    log "INFO" "Network security validation completed"
}

# Validate encryption
validate_encryption() {
    log "INFO" "Validating encryption configuration..."
    
    # Check Key Vault existence
    KEY_VAULTS=$(az keyvault list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    if [ -z "$KEY_VAULTS" ]; then
        log "ERROR" "No Key Vault found in resource group"
        return 1
    fi
    log "INFO" "Found Key Vaults: $KEY_VAULTS"
    
    # Check for HSM protection
    for KV in $KEY_VAULTS; do
        SKU=$(az keyvault show --name "$KV" --query "properties.sku.name" -o tsv)
        if [ "$SKU" != "Premium" ]; then
            log "WARNING" "Key Vault '$KV' is not using Premium SKU for HSM protection"
        else
            log "SUCCESS" "Key Vault '$KV' is properly configured with Premium SKU"
        fi
        
        # Check key protection
        KEYS=$(az keyvault key list --vault-name "$KV" --query "[].kid" -o tsv)
        if [ -z "$KEYS" ]; then
            log "WARNING" "No keys found in Key Vault '$KV'"
        else
            for KEY in $KEYS; do
                KEY_NAME=$(basename "$KEY")
                KEY_TYPE=$(az keyvault key show --id "$KEY" --query "key.kty" -o tsv)
                if [[ "$KEY_TYPE" != *"HSM"* ]]; then
                    log "WARNING" "Key '$KEY_NAME' is not HSM-protected"
                else
                    log "SUCCESS" "Key '$KEY_NAME' is properly HSM-protected"
                fi
            done
        fi
    done
    
    # Check storage account encryption
    STORAGE_ACCOUNTS=$(az storage account list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    for SA in $STORAGE_ACCOUNTS; do
        ENCRYPTION=$(az storage account show --name "$SA" --query "encryption.services.blob.enabled" -o tsv)
        if [ "$ENCRYPTION" != "true" ]; then
            log "ERROR" "Storage account '$SA' does not have encryption enabled"
        else
            log "SUCCESS" "Storage account '$SA' has encryption properly configured"
        fi
    done
    
    log "INFO" "Encryption validation completed"
}

# Validate compliance policies
validate_compliance_policies() {
    log "INFO" "Validating compliance policies..."
    
    # Check Azure Policy assignments
    POLICIES=$(az policy assignment list --query "[?resourceGroup=='$RESOURCE_GROUP'].name" -o tsv)
    if [ -z "$POLICIES" ]; then
        log "WARNING" "No policy assignments found for resource group"
    else
        log "INFO" "Found policy assignments: $POLICIES"
    fi
    
    # Check for required policies
    REQUIRED_POLICIES=("encrypt-storage" "secure-transfer" "network-isolation")
    for POLICY in "${REQUIRED_POLICIES[@]}"; do
        if [[ "$POLICIES" == *"$POLICY"* ]]; then
            log "SUCCESS" "Required policy '$POLICY' is assigned"
        else
            log "WARNING" "Required policy '$POLICY' is not assigned"
        fi
    done
    
    # Check compliance state
    log "INFO" "Checking current compliance state..."
    NON_COMPLIANT=$(az policy state list --resource-group "$RESOURCE_GROUP" --query "[?complianceState=='NonCompliant'].resourceId" -o tsv)
    if [ -z "$NON_COMPLIANT" ]; then
        log "SUCCESS" "All resources are policy compliant"
    else
        log "WARNING" "Found non-compliant resources: $NON_COMPLIANT"
    fi
    
    log "INFO" "Compliance policy validation completed"
}

# Validate monitoring and alerting
validate_monitoring() {
    log "INFO" "Validating monitoring and alerting configuration..."
    
    # Check Log Analytics workspace
    WORKSPACES=$(az monitor log-analytics workspace list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    if [ -z "$WORKSPACES" ]; then
        log "ERROR" "No Log Analytics workspace found"
        return 1
    fi
    log "INFO" "Found Log Analytics workspaces: $WORKSPACES"
    
    # Check workspace retention
    for WS in $WORKSPACES; do
        RETENTION=$(az monitor log-analytics workspace show --resource-group "$RESOURCE_GROUP" --workspace-name "$WS" --query "retentionInDays" -o tsv)
        if [ "$RETENTION" -lt 365 ]; then
            log "WARNING" "Log Analytics workspace '$WS' retention period ($RETENTION days) is less than required (365 days)"
        else
            log "SUCCESS" "Log Analytics workspace '$WS' retention is properly configured"
        fi
    done
    
    # Check alert rules
    ALERT_RULES=$(az monitor scheduled-query list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv 2>/dev/null || echo "")
    if [ -z "$ALERT_RULES" ]; then
        log "WARNING" "No alert rules found"
    else
        log "SUCCESS" "Alert rules are configured: $ALERT_RULES"
    fi
    
    # Check action groups
    ACTION_GROUPS=$(az monitor action-group list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    if [ -z "$ACTION_GROUPS" ]; then
        log "WARNING" "No action groups found for alerts"
    else
        log "SUCCESS" "Action groups are configured: $ACTION_GROUPS"
    fi
    
    log "INFO" "Monitoring validation completed"
}

# Validate HSM configuration
validate_hsm() {
    log "INFO" "Validating HSM configuration..."
    
    # Check for Managed HSM
    MANAGED_HSM=$(az keyvault list --resource-group "$RESOURCE_GROUP" --query "[?properties.hsmPoolResourceId!=null].name" -o tsv)
    if [ -z "$MANAGED_HSM" ]; then
        log "WARNING" "No Managed HSM found"
    else
        log "SUCCESS" "Managed HSM is properly configured"
    fi
    
    # Check key rotation settings
    KEY_VAULTS=$(az keyvault list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    for KV in $KEY_VAULTS; do
        # Check if keys have rotation policy
        KEYS=$(az keyvault key list --vault-name "$KV" --query "[].name" -o tsv)
        for KEY in $KEYS; do
            # Note: This would typically check rotation policy, but CLI doesn't directly support this
            # We would use a custom approach to check rotation policy
            log "INFO" "Manual verification required for key rotation policy on '$KEY'"
        done
    done
    
    log "INFO" "HSM validation completed"
}

# Validate identity and access controls
validate_identity_controls() {
    log "INFO" "Validating identity and access controls..."
    
    # Check role assignments
    ROLE_ASSIGNMENTS=$(az role assignment list --resource-group "$RESOURCE_GROUP" --query "[].roleDefinitionName" -o tsv)
    if [ -z "$ROLE_ASSIGNMENTS" ]; then
        log "WARNING" "No role assignments found for resource group"
    else
        log "INFO" "Found role assignments: $ROLE_ASSIGNMENTS"
    fi
    
    # Check for privileged roles
    PRIVILEGED_ROLES=("Owner" "Contributor")
    for ROLE in "${PRIVILEGED_ROLES[@]}"; do
        COUNT=$(echo "$ROLE_ASSIGNMENTS" | grep -c "$ROLE" || true)
        if [ "$COUNT" -gt 2 ]; then
            log "WARNING" "Found $COUNT '$ROLE' assignments, which exceeds recommended limit"
        else
            log "SUCCESS" "Number of '$ROLE' assignments is within acceptable limits"
        fi
    done
    
    # Check for custom RBAC roles
    CUSTOM_ROLES=$(az role definition list --custom-role-only true --query "[?resourceTypes[?contains(@, '$RESOURCE_GROUP')]].roleName" -o tsv)
    if [ -z "$CUSTOM_ROLES" ]; then
        log "INFO" "No custom RBAC roles found"
    else
        log "SUCCESS" "Custom RBAC roles are configured: $CUSTOM_ROLES"
    fi
    
    log "INFO" "Identity and access control validation completed"
}

# Main validation function
run_validation() {
    log "INFO" "Running comprehensive deployment validation"
    
    local failures=0
    
    # Run all validation functions
    validate_network_security || ((failures++))
    validate_encryption || ((failures++))
    validate_compliance_policies || ((failures++))
    validate_monitoring || ((failures++))
    validate_hsm || ((failures++))
    validate_identity_controls || ((failures++))
    
    # Final validation status
    if [ "$failures" -eq 0 ]; then
        log "SUCCESS" "All validation checks passed successfully"
        log "INFO" "Detailed validation log available at: $LOG_PATH"
        return 0
    else
        log "ERROR" "$failures validation checks failed. See log for details"
        log "INFO" "Detailed validation log available at: $LOG_PATH"
        return 1
    fi
}

# Main execution flow
main() {
    setup
    run_validation
    exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        log "INFO" "For troubleshooting guidance, see docs/troubleshooting/validation_failures.md"
    fi
    
    return $exit_code
}

# Run main function
main