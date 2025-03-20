#!/bin/bash
# restore-security-baseline.sh
#
# This script restores the security baseline configuration after a security incident.
# It performs the following actions:
# 1. Validates current environment state
# 2. Restores network security configurations
# 3. Rotates compromised credentials
# 4. Reapplies security policies
# 5. Validates compliance status
#
# Usage: ./restore-security-baseline.sh [--resource-group <name>] [--subscription <id>] [--environment <env>]

set -e

# Default values
RESOURCE_GROUP=""
SUBSCRIPTION_ID=""
ENVIRONMENT="production"
LOG_FILE="security-restore-$(date +%Y%m%d-%H%M%S).log"
RESTORE_POINT=""
FORCE=false
SKIP_VALIDATION=false
SKIP_KEY_ROTATION=false

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display usage information
function show_usage {
    echo "Usage: $0 [OPTIONS]"
    echo "Restore security baseline after an incident"
    echo ""
    echo "Options:"
    echo "  --resource-group, -g   Resource group name"
    echo "  --subscription, -s     Subscription ID"
    echo "  --environment, -e      Environment (default: production)"
    echo "  --restore-point, -r    Specific restore point timestamp (default: latest)"
    echo "  --force, -f            Force restore without confirmation"
    echo "  --skip-validation      Skip pre and post validation"
    echo "  --skip-key-rotation    Skip credential rotation"
    echo "  --help, -h             Show this help message"
    exit 1
}

# Function to log messages
function log {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Display to console with color
    case $level in
        "INFO")
            echo -e "${BLUE}[$timestamp] [INFO] $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[$timestamp] [SUCCESS] $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}[$timestamp] [WARNING] $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}[$timestamp] [ERROR] $message${NC}"
            ;;
        *)
            echo "[$timestamp] [$level] $message"
            ;;
    esac
}

# Function to check prerequisites
function check_prerequisites {
    log "INFO" "Checking prerequisites..."
    
    # Check if Azure CLI is installed
    if ! command -v az &> /dev/null; then
        log "ERROR" "Azure CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        log "ERROR" "jq is not installed. Please install it first."
        exit 1
    }
    
    # Check if user is logged in to Azure
    if ! az account show &> /dev/null; then
        log "WARNING" "Not logged in to Azure. Attempting to log in..."
        az login || { log "ERROR" "Failed to log in to Azure."; exit 1; }
    fi
    
    # Set subscription if provided
    if [[ -n "$SUBSCRIPTION_ID" ]]; then
        log "INFO" "Setting subscription to $SUBSCRIPTION_ID"
        az account set --subscription "$SUBSCRIPTION_ID" || { 
            log "ERROR" "Failed to set subscription to $SUBSCRIPTION_ID"
            exit 1
        }
    fi
    
    # Validate resource group exists
    if [[ -n "$RESOURCE_GROUP" ]]; then
        if ! az group show --name "$RESOURCE_GROUP" &> /dev/null; then
            log "ERROR" "Resource group $RESOURCE_GROUP does not exist"
            exit 1
        fi
    else
        log "ERROR" "Resource group is required"
        show_usage
    fi
    
    log "SUCCESS" "Prerequisites check completed successfully"
}

# Function to validate current state
function validate_current_state {
    if [[ "$SKIP_VALIDATION" == true ]]; then
        log "INFO" "Skipping pre-validation as requested"
        return 0
    fi
    
    log "INFO" "Validating current environment state..."
    
    # Create a temporary file to store validation results
    local validation_file=$(mktemp)
    
    # Check network security groups
    log "INFO" "Checking network security groups..."
    az network nsg list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv | while read -r nsg_name; do
        log "INFO" "Validating NSG: $nsg_name"
        az network nsg show --resource-group "$RESOURCE_GROUP" --name "$nsg_name" > "$validation_file"
        
        # Check for default deny rules
        if ! jq -e '.securityRules[] | select(.name=="DenyAllInbound" and .priority==4096)' "$validation_file" &> /dev/null; then
            log "WARNING" "NSG $nsg_name is missing default deny rule"
        fi
    done
    
    # Check Key Vault configuration
    log "INFO" "Checking Key Vault configuration..."
    az keyvault list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv | while read -r vault_name; do
        log "INFO" "Validating Key Vault: $vault_name"
        az keyvault show --name "$vault_name" > "$validation_file"
        
        # Check for soft-delete and purge protection
        if [[ $(jq -r '.properties.enableSoftDelete' "$validation_file") != "true" ]]; then
            log "WARNING" "Key Vault $vault_name does not have soft-delete enabled"
        fi
        
        if [[ $(jq -r '.properties.enablePurgeProtection' "$validation_file") != "true" ]]; then
            log "WARNING" "Key Vault $vault_name does not have purge protection enabled"
        fi
    done
    
    # Check Azure Policy assignments
    log "INFO" "Checking Azure Policy assignments..."
    policy_count=$(az policy assignment list --resource-group "$RESOURCE_GROUP" --query "length(@)" -o tsv)
    if [[ "$policy_count" -eq 0 ]]; then
        log "WARNING" "No policy assignments found for resource group $RESOURCE_GROUP"
    fi
    
    # Cleanup
    rm -f "$validation_file"
    
    log "SUCCESS" "Current state validation completed"
}

# Function to restore network security configuration
function restore_network_security {
    log "INFO" "Restoring network security configuration..."
    
    # Get the list of all NSGs in the resource group
    local nsgs=$(az network nsg list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    
    for nsg_name in $nsgs; do
        log "INFO" "Processing NSG: $nsg_name"
        
        # Check if we have a baseline configuration for this NSG
        local baseline_file="../config/security/baselines/nsg/${ENVIRONMENT}/${nsg_name}.json"
        if [[ -f "$baseline_file" ]]; then
            log "INFO" "Restoring NSG $nsg_name from baseline configuration"
            
            # Delete all custom rules (keeping default rules)
            log "INFO" "Removing existing custom rules from NSG $nsg_name"
            az network nsg rule list --resource-group "$RESOURCE_GROUP" --nsg-name "$nsg_name" --query "[].name" -o tsv | while read -r rule_name; do
                # Skip default rules that start with "Default"
                if [[ "$rule_name" != Default* ]]; then
                    log "INFO" "Deleting rule: $rule_name"
                    az network nsg rule delete --resource-group "$RESOURCE_GROUP" --nsg-name "$nsg_name" --name "$rule_name"
                fi
            done
            
            # Apply baseline rules
            log "INFO" "Applying baseline rules to NSG $nsg_name"
            jq -c '.securityRules[]' "$baseline_file" | while read -r rule; do
                rule_name=$(echo "$rule" | jq -r '.name')
                log "INFO" "Adding rule: $rule_name"
                
                # Extract rule properties
                priority=$(echo "$rule" | jq -r '.priority')
                direction=$(echo "$rule" | jq -r '.direction')
                access=$(echo "$rule" | jq -r '.access')
                protocol=$(echo "$rule" | jq -r '.protocol')
                source_port_range=$(echo "$rule" | jq -r '.sourcePortRange')
                destination_port_range=$(echo "$rule" | jq -r '.destinationPortRange')
                source_address_prefix=$(echo "$rule" | jq -r '.sourceAddressPrefix')
                destination_address_prefix=$(echo "$rule" | jq -r '.destinationAddressPrefix')
                
                # Create the rule
                az network nsg rule create \
                    --resource-group "$RESOURCE_GROUP" \
                    --nsg-name "$nsg_name" \
                    --name "$rule_name" \
                    --priority "$priority" \
                    --direction "$direction" \
                    --access "$access" \
                    --protocol "$protocol" \
                    --source-port-range "$source_port_range" \
                    --destination-port-range "$destination_port_range" \
                    --source-address-prefix "$source_address_prefix" \
                    --destination-address-prefix "$destination_address_prefix"
            done
        else
            log "WARNING" "No baseline configuration found for NSG $nsg_name"
            
            # Apply default secure configuration
            log "INFO" "Applying default secure configuration to NSG $nsg_name"
            
            # Ensure default deny rule exists
            if ! az network nsg rule show --resource-group "$RESOURCE_GROUP" --nsg-name "$nsg_name" --name "DenyAllInbound" &> /dev/null; then
                log "INFO" "Adding default deny rule to NSG $nsg_name"
                az network nsg rule create \
                    --resource-group "$RESOURCE_GROUP" \
                    --nsg-name "$nsg_name" \
                    --name "DenyAllInbound" \
                    --priority 4096 \
                    --direction "Inbound" \
                    --access "Deny" \
                    --protocol "*" \
                    --source-port-range "*" \
                    --destination-port-range "*" \
                    --source-address-prefix "*" \
                    --destination-address-prefix "*"
            fi
        fi
    done
    
    # Restore Azure Firewall rules if applicable
    if az resource list --resource-group "$RESOURCE_GROUP" --resource-type "Microsoft.Network/azureFirewalls" --query "[].name" -o tsv &> /dev/null; then
        log "INFO" "Restoring Azure Firewall rules..."
        
        local firewall_name=$(az resource list --resource-group "$RESOURCE_GROUP" --resource-type "Microsoft.Network/azureFirewalls" --query "[0].name" -o tsv)
        local baseline_file="../config/security/baselines/firewall/${ENVIRONMENT}/firewall-policy.json"
        
        if [[ -f "$baseline_file" ]]; then
            log "INFO" "Applying baseline firewall policy"
            
            # Create a temporary policy
            local policy_name="restore-policy-$(date +%s)"
            az network firewall policy create --name "$policy_name" --resource-group "$RESOURCE_GROUP"
            
            # Import rules from baseline
            az network firewall policy import --name "$policy_name" --resource-group "$RESOURCE_GROUP" --file "$baseline_file"
            
            # Assign policy to firewall
            az network firewall update --name "$firewall_name" --resource-group "$RESOURCE_GROUP" --firewall-policy "$policy_name"
            
            log "SUCCESS" "Firewall rules restored successfully"
        else
            log "WARNING" "No baseline firewall policy found"
        fi
    fi
    
    log "SUCCESS" "Network security configuration restored"
}

# Function to rotate credentials
function rotate_credentials {
    if [[ "$SKIP_KEY_ROTATION" == true ]]; then
        log "INFO" "Skipping credential rotation as requested"
        return 0
    fi
    
    log "INFO" "Rotating credentials..."
    
    # Rotate Key Vault keys
    log "INFO" "Rotating Key Vault keys..."
    az keyvault list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv | while read -r vault_name; do
        log "INFO" "Processing Key Vault: $vault_name"
        
        # Get all keys
        az keyvault key list --vault-name "$vault_name" --query "[].name" -o tsv | while read -r key_name; do
            log "INFO" "Rotating key: $key_name"
            
            # Get key attributes to preserve them
            local key_attributes=$(az keyvault key show --vault-name "$vault_name" --name "$key_name" --query "attributes")
            
            # Create new version of the key
            az keyvault key rotate --vault-name "$vault_name" --name "$key_name" || {
                log "WARNING" "Failed to rotate key $key_name, creating new version manually"
                
                # Get key type and size
                local key_info=$(az keyvault key show --vault-name "$vault_name" --name "$key_name")
                local key_type=$(echo "$key_info" | jq -r '.key.kty')
                
                # Create new version
                az keyvault key create --vault-name "$vault_name" --name "$key_name" --kty "$key_type"
            }
            
            log "SUCCESS" "Key $key_name rotated successfully"
        done
    done
    
    # Rotate service principal credentials if applicable
    if [[ -f "../config/security/service-principals.json" ]]; then
        log "INFO" "Rotating service principal credentials..."
        
        jq -c '.[]' "../config/security/service-principals.json" | while read -r sp; do
            sp_name=$(echo "$sp" | jq -r '.name')
            sp_id=$(echo "$sp" | jq -r '.id')
            
            log "INFO" "Rotating credentials for service principal: $sp_name"
            
            # Reset credentials
            new_password=$(az ad sp credential reset --id "$sp_id" --query "password" -o tsv)
            
            # Store new password in Key Vault
            vault_name=$(az keyvault list --resource-group "$RESOURCE_GROUP" --query "[0].name" -o tsv)
            secret_name="sp-$sp_name"
            
            az keyvault secret set --vault-name "$vault_name" --name "$secret_name" --value "$new_password"
            
            log "SUCCESS" "Service principal $sp_name credentials rotated successfully"
        done
    fi
    
    log "SUCCESS" "Credentials rotated successfully"
}

# Function to reapply security policies
function reapply_security_policies {
    log "INFO" "Reapplying security policies..."
    
    # Check if we have policy definitions
    local policy_dir="../config/policy"
    if [[ -d "$policy_dir" ]]; then
        # Apply each policy definition
        find "$policy_dir" -name "*.json" | while read -r policy_file; do
            policy_name=$(basename "$policy_file" .json)
            log "INFO" "Applying policy: $policy_name"
            
            # Create or update policy definition
            az policy definition create --name "$policy_name" --rules "$policy_file" --mode "All" || {
                log "WARNING" "Failed to create policy definition, attempting update"
                az policy definition update --name "$policy_name" --rules "$policy_file" --mode "All"
            }
            
            # Assign policy to resource group
            az policy assignment create \
                --name "${policy_name}-assignment" \
                --policy "$policy_name" \
                --resource-group "$RESOURCE_GROUP" \
                --enforcement-mode "Default"
        done
    else
        log "WARNING" "No policy definitions found in $policy_dir"
        
        # Apply built-in security policies
        log "INFO" "Applying built-in security policies..."
        
        # Azure Security Benchmark
        az policy assignment create \
            --name "security-benchmark" \
            --policy "1f3afdf9-d0c9-4c3d-847f-89da613e70a8" \
            --resource-group "$RESOURCE_GROUP" \
            --enforcement-mode "Default"
            
        # Require encryption for PaaS services
        az policy assignment create \
            --name "encrypt-paas-services" \
            --policy "4733ea3e-8ecb-42a1-98a0-df8f7ce4d99e" \
            --resource-group "$RESOURCE_GROUP" \
            --enforcement-mode "Default"
    fi
    
    log "SUCCESS" "Security policies reapplied successfully"
}

# Function to validate restored configuration
function validate_restored_configuration {
    if [[ "$SKIP_VALIDATION" == true ]]; then
        log "INFO" "Skipping post-validation as requested"
        return 0
    fi
    
    log "INFO" "Validating restored configuration..."
    
    # Run Azure Security Center assessment
    log "INFO" "Running Azure Security Center assessment..."
    az security assessment create \
        --assessment-type "OnDemandNetworkSecurityGroupAssessment" \
        --resource-group "$RESOURCE_GROUP" \
        --target-resource-id "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP"
    
    # Wait for assessment to complete
    log "INFO" "Waiting for assessment to complete..."
    sleep 60
    
    # Get assessment results
    assessment_results=$(az security assessment list --resource-group "$RESOURCE_GROUP" --query "[?type=='Microsoft.Security/assessments']")
    
    # Check for high severity findings
    high_severity_count=$(echo "$assessment_results" | jq '[.[] | select(.properties.status.severity=="High")] | length')
    if [[ "$high_severity_count" -gt 0 ]]; then
        log "WARNING" "Found $high_severity_count high severity security findings"
        echo "$assessment_results" | jq '.[] | select(.properties.status.severity=="High") | .properties.displayName'
    else
        log "SUCCESS" "No high severity security findings detected"
    fi
    
    # Validate network configuration
    log "INFO" "Validating network configuration..."
    ../scripts/validate-network-isolation.sh --resource-group "$RESOURCE_GROUP" || {
        log "WARNING" "Network isolation validation failed"
    }
    
    # Validate compliance
    log "INFO" "Validating compliance status..."
    ../scripts/verify-compliance.sh --resource-group "$RESOURCE_GROUP" || {
        log "WARNING" "Compliance verification failed"
    }
    
    log "SUCCESS" "Restored configuration validation completed"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --resource-group|-g)
            RESOURCE_GROUP="$2"
            shift 2
            ;;
        --subscription|-s)
            SUBSCRIPTION_ID="$2"
            shift 2
            ;;
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --restore-point|-r)
            RESTORE_POINT="$2"
            shift 2
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --skip-validation)
            SKIP_VALIDATION=true
            shift
            ;;
        --skip-key-rotation)
            SKIP_KEY_ROTATION=true
            shift
            ;;
        --help|-h)
            show_usage
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            ;;
    esac
done

# Main execution
log "INFO" "Starting security baseline restoration for environment: $ENVIRONMENT"
log "INFO" "Resource Group: $RESOURCE_GROUP"
log "INFO" "Log file: $LOG_FILE"

# Check prerequisites
check_prerequisites

# Confirm restoration unless forced
if [[ "$FORCE" != true ]]; then
    read -p "Are you sure you want to restore the security baseline? This will modify your environment. [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "INFO" "Operation cancelled by user"
        exit 0
    fi
fi

# Execute restoration process
validate_current_state
restore_network_security
rotate_credentials
reapply_security_policies
validate_restored_configuration

log "SUCCESS" "Security baseline restoration completed successfully"
log "INFO" "See $LOG_FILE for detailed logs"

exit 0