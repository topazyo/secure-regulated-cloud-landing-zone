#!/bin/bash
# compliance-check.sh - Comprehensive compliance validation for regulated cloud environments
# 
# This script performs a thorough compliance check of your Azure environment against
# multiple regulatory frameworks including PCI-DSS, SWIFT-SCR, and custom security baselines.
# It validates network segmentation, encryption standards, access controls, and monitoring.
#
# Usage: ./compliance-check.sh [--subscription <subscription-id>] [--framework <framework-name>] [--output <output-format>]

set -e

# Default values
SUBSCRIPTION_ID=""
FRAMEWORK="all"
OUTPUT_FORMAT="json"
REPORT_FILE="compliance-report-$(date +%Y%m%d-%H%M%S).json"
LOG_FILE="compliance-check-$(date +%Y%m%d-%H%M%S).log"
VERBOSE=false
REMEDIATE=false

# Configuration Files (New)
SCRIPT_DIR_COMPLIANCE_CHECK=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# Assuming config is relative to 'src/' directory, so one level up from 'src/scripts/compliance/'
CONFIG_BASE_DIR="$SCRIPT_DIR_COMPLIANCE_CHECK/../../../config"
NETWORK_CONFIG_FILE="$CONFIG_BASE_DIR/network/network_config.json"
NETWORK_REQUIREMENTS_FILE="$CONFIG_BASE_DIR/compliance/network_requirements.json"

# Loaded Configs (New)
NETWORK_CONFIG_JSON=""
NETWORK_REQUIREMENTS_JSON=""


# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display usage information
function show_usage {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --subscription <id>    Azure subscription ID"
    echo "  --framework <name>     Regulatory framework to check (pci-dss, swift-scr, all)"
    echo "  --output <format>      Output format (json, csv, html)"
    echo "  --report <filename>    Report filename"
    echo "  --remediate            Attempt to auto-remediate issues"
    echo "  --verbose              Enable verbose output"
    echo "  --help                 Show this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --subscription)
            SUBSCRIPTION_ID="$2"
            shift 2
            ;;
        --framework)
            FRAMEWORK="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --report)
            REPORT_FILE="$2"
            shift 2
            ;;
        --remediate)
            REMEDIATE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            show_usage
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            ;;
    esac
done

# Initialize logging
function log {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    echo -e "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    if [[ "$VERBOSE" == "true" || "$level" == "ERROR" ]]; then
        case $level in
            "INFO")
                echo -e "${BLUE}[$timestamp] [INFO] $message${NC}"
                ;;
            "WARNING")
                echo -e "${YELLOW}[$timestamp] [WARNING] $message${NC}"
                ;;
            "ERROR")
                echo -e "${RED}[$timestamp] [ERROR] $message${NC}"
                ;;
            "SUCCESS")
                echo -e "${GREEN}[$timestamp] [SUCCESS] $message${NC}"
                ;;
            *)
                echo -e "[$timestamp] [$level] $message"
                ;;
        esac
    fi
}

# Initialize results array
declare -A COMPLIANCE_RESULTS
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Function to check if Azure CLI is installed
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
    
    # Check if Azure CLI is logged in
    if [[ -z "$SUBSCRIPTION_ID" ]]; then
        SUBSCRIPTION_ID=$(az account show --query id -o tsv 2>/dev/null)
        if [[ -z "$SUBSCRIPTION_ID" ]]; then
            log "ERROR" "Not logged in to Azure. Please run 'az login' first."
            exit 1
        fi
    else
        # Set the specified subscription
        az account set --subscription "$SUBSCRIPTION_ID" || {
            log "ERROR" "Failed to set subscription: $SUBSCRIPTION_ID"
            exit 1
        }
    fi
    
    log "SUCCESS" "Prerequisites check passed. Using subscription: $SUBSCRIPTION_ID"
}

# Function to load external JSON configuration files (New)
function load_external_configs {
    log "INFO" "Loading external configuration files..."

    if [[ -f "$NETWORK_CONFIG_FILE" ]]; then
        NETWORK_CONFIG_JSON=$(jq '.' "$NETWORK_CONFIG_FILE")
        if [ $? -ne 0 ]; then
            log "ERROR" "Failed to parse $NETWORK_CONFIG_FILE. JSON errors."
            NETWORK_CONFIG_JSON="" # Ensure it's empty on error
        else
            log "INFO" "$NETWORK_CONFIG_FILE loaded successfully."
        fi
    else
        log "WARNING" "$NETWORK_CONFIG_FILE not found. Checks relying on it may be skipped or use defaults."
    fi

    if [[ -f "$NETWORK_REQUIREMENTS_FILE" ]]; then
        NETWORK_REQUIREMENTS_JSON=$(jq '.' "$NETWORK_REQUIREMENTS_FILE")
        if [ $? -ne 0 ]; then
            log "ERROR" "Failed to parse $NETWORK_REQUIREMENTS_FILE. JSON errors."
            NETWORK_REQUIREMENTS_JSON="" # Ensure it's empty on error
        else
            log "INFO" "$NETWORK_REQUIREMENTS_FILE loaded successfully."
        fi
    else
        log "WARNING" "$NETWORK_REQUIREMENTS_FILE not found. Checks relying on it may be skipped or use defaults."
    fi
}

# Function to match subnet name against a glob pattern (New)
# Simple glob match, Bash specific. For more complex patterns, might need different tools.
function glob_match {
    local string="$1"
    local pattern="$2"
    case "$string" in
        $pattern) return 0 ;;
        *) return 1 ;;
    esac
}


# Function to get specific requirements for a subnet (New)
# Returns a JSON object of the first matching requirement, or empty if no match.
function get_subnet_requirements {
    local subnet_name="$1"
    # No need to pass NETWORK_REQUIREMENTS_JSON as it's a global var

    if [[ -z "$NETWORK_REQUIREMENTS_JSON" ]]; then
        echo "" # Return empty if the main requirements JSON is not loaded
        return
    fi

    # Loop through subnetSpecificRequirements, find first match by subnetNamePattern (glob)
    local num_subnet_reqs=$(echo "$NETWORK_REQUIREMENTS_JSON" | jq '.subnetSpecificRequirements | length')
    for (( i=0; i<$num_subnet_reqs; i++ )); do
        local req_obj=$(echo "$NETWORK_REQUIREMENTS_JSON" | jq ".subnetSpecificRequirements[$i]")
        local pattern=$(echo "$req_obj" | jq -r '.subnetNamePattern')

        if glob_match "$subnet_name" "$pattern"; then
            echo "$req_obj" # Output the JSON object of the matching requirement
            return
        fi
    done

    echo "" # No match found
}


# Function to record compliance check result
function record_result {
    local category=$1
    local check_name=$2
    local status=$3
    local details=$4
    local remediation=$5
    
    COMPLIANCE_RESULTS["$category:$check_name"]=$(cat <<EOF
{
    "category": "$category",
    "check": "$check_name",
    "status": "$status",
    "details": "$details",
    "remediation": "$remediation",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
)
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    case $status in
        "PASSED")
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            log "SUCCESS" "[$category] $check_name: PASSED"
            ;;
        "FAILED")
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            log "ERROR" "[$category] $check_name: FAILED - $details"
            ;;
        "WARNING")
            WARNING_CHECKS=$((WARNING_CHECKS + 1))
            log "WARNING" "[$category] $check_name: WARNING - $details"
            ;;
    esac
}

# Function to check network segmentation
function check_network_segmentation {
    log "INFO" "Checking network segmentation..."
    
    # Get all virtual networks
    local vnets=$(az network vnet list --query "[].{name:name, resourceGroup:resourceGroup}" -o json)
    
    # Check if each subnet has an NSG attached & validate NSG rules based on network_requirements.json
    for vnet_row in $(echo "$vnets" | jq -c '.[]'); do
        local vnet_name=$(echo "$vnet_row" | jq -r '.name')
        local vnet_rg=$(echo "$vnet_row" | jq -r '.resourceGroup')
        
        log "INFO" "Checking VNet: $vnet_name in resource group: $vnet_rg"
        
        local subnets_json=$(az network vnet subnet list --vnet-name "$vnet_name" --resource-group "$vnet_rg" -o json)
        
        for subnet_row in $(echo "$subnets_json" | jq -c '.[]'); do
            local subnet_name=$(echo "$subnet_row" | jq -r '.name')
            local subnet_id=$(echo "$subnet_row" | jq -r '.id')
            local nsg_id=$(echo "$subnet_row" | jq -r '.networkSecurityGroup.id // empty')
            local nsg_name=$(echo "$nsg_id" | awk -F'/' '{print $NF}') # Extract NSG name from ID

            if [[ -z "$nsg_id" ]]; then
                record_result "Network" "NSG-Attached-$vnet_name-$subnet_name" "FAILED" "Subnet $subnet_name in VNet $vnet_name does not have an NSG attached" "Attach an NSG to the subnet."
                # Remediation logic (if enabled) would go here
            else
                record_result "Network" "NSG-Attached-$vnet_name-$subnet_name" "PASSED" "Subnet $subnet_name in VNet $vnet_name has an NSG attached: $nsg_name" ""

                # Enhanced check using network_requirements.json
                if [[ -n "$NETWORK_REQUIREMENTS_JSON" ]]; then
                    local subnet_req_json=$(get_subnet_requirements "$subnet_name" "$NETWORK_REQUIREMENTS_JSON")

                    if [[ -n "$subnet_req_json" ]]; then
                        log "INFO" "Applying specific requirements for subnet pattern matching '$subnet_name' using NSG '$nsg_name'."
                        local prohibited_sources_jq=$(echo "$subnet_req_json" | jq -c '.prohibitedInboundSources // []')

                        if [[ $(echo "$prohibited_sources_jq" | jq '. | length') -gt 0 ]]; then
                            local nsg_rules_json=$(az network nsg rule list --nsg-name "$nsg_name" --resource-group "$vnet_rg" -o json) # Assuming NSG is in same RG as VNet for simplicity here

                            echo "$nsg_rules_json" | jq -c '.[] | select(.direction == "Inbound")' | while IFS= read -r rule_json; do
                                local rule_name=$(echo "$rule_json" | jq -r '.name')
                                local source_prefix=$(echo "$rule_json" | jq -r '.sourceAddressPrefix // "Any"')
                                local source_prefixes_array=$(echo "$rule_json" | jq -c '.sourceAddressPrefixes // []')

                                # Check single sourceAddressPrefix
                                if echo "$prohibited_sources_jq" | jq -e --arg sp "$source_prefix" '.[] | select(. == $sp)' > /dev/null; then
                                     record_result "Network" "Subnet-$subnet_name-NSGRule-$rule_name-ProhibitedSource" "FAILED" "NSG rule '$rule_name' allows prohibited source '$source_prefix' for subnet '$subnet_name'." "Review NSG rule."
                                     continue # Next rule
                                fi
                                # Check sourceAddressPrefixes array
                                echo "$source_prefixes_array" | jq -r '.[]' | while IFS= read -r sp_item; do
                                    if echo "$prohibited_sources_jq" | jq -e --arg sp_item_arg "$sp_item" '.[] | select(. == $sp_item_arg)' > /dev/null; then
                                        record_result "Network" "Subnet-$subnet_name-NSGRule-$rule_name-ProhibitedSourceArray" "FAILED" "NSG rule '$rule_name' allows prohibited source '$sp_item' (from array) for subnet '$subnet_name'." "Review NSG rule."
                                        # TODO: This could report multiple times for one rule if multiple prohibited sources are in its array. Could be refined.
                                    fi
                                done
                            done
                        fi # end if prohibited_sources_jq has items

                        local prohibited_ports_jq=$(echo "$subnet_req_json" | jq -c '.prohibitedPorts // []')
                        if [[ $(echo "$prohibited_ports_jq" | jq '. | length') -gt 0 ]]; then
                            log "INFO" "Checking prohibited ports for subnet '$subnet_name' (NSG: '$nsg_name'). Prohibited: $(echo "$prohibited_ports_jq" | jq -r 'join(", ")')"
                            # Re-use nsg_rules_json if already fetched, or fetch if not (e.g. if prohibited_sources was empty)
                            if [[ -z "$nsg_rules_json" ]]; then
                                nsg_rules_json=$(az network nsg rule list --nsg-name "$nsg_name" --resource-group "$vnet_rg" -o json)
                            fi

                            echo "$nsg_rules_json" | jq -c '.[]' | while IFS= read -r rule_json; do
                                local rule_name=$(echo "$rule_json" | jq -r '.name')
                                local direction=$(echo "$rule_json" | jq -r '.direction')
                                local protocol=$(echo "$rule_json" | jq -r '.protocol') # Tcp, Udp, Icmp, *
                                local dest_port_range=$(echo "$rule_json" | jq -r '.destinationPortRange // "*"')
                                local dest_port_ranges_array=$(echo "$rule_json" | jq -c '.destinationPortRanges // []')

                                # Helper function to check if a port/range overlaps with prohibited ports might be needed for complex cases.
                                # Simple check: direct match of single port or "*" if "*" is prohibited.
                                # This simplified check looks for direct matches or if a specific port in rule matches a prohibited port.
                                # It does not fully parse ranges vs ranges yet.

                                local port_check_target="$dest_port_range"
                                if [[ "$dest_port_range" == "*" && $(echo "$dest_port_ranges_array" | jq '. | length') -gt 0 ]]; then
                                    # If destinationPortRange is "*" but destinationPortRanges has specific values, use those.
                                    # For simplicity, we'll just check the first one here if it exists, or rely on dest_port_range being *
                                    # A full solution would iterate through dest_port_ranges_array.
                                     port_check_target_from_array=$(echo "$dest_port_ranges_array" | jq -r '.[0] // "*"')
                                     if [[ "$port_check_target_from_array" != "*" ]]; then
                                        port_check_target="$port_check_target_from_array" # Prefer specific over wildcard if available
                                     fi
                                fi

                                # Check if port_check_target (single port or simple range like "80", "22", "3000-4000", or "*")
                                # is among the prohibited_ports_jq array.
                                echo "$prohibited_ports_jq" | jq -r '.[]' | while IFS= read -r prohibited_port_entry; do
                                    # Case 1: Prohibited port is a single port number
                                    if [[ "$prohibited_port_entry" =~ ^[0-9]+$ ]]; then
                                        if [[ "$port_check_target" == "$prohibited_port_entry" ]]; then
                                            record_result "Network" "Subnet-$subnet_name-NSGRule-$rule_name-ProhibitedPort" "FAILED" "NSG rule '$rule_name' ($direction/$protocol) uses prohibited port '$prohibited_port_entry' for subnet '$subnet_name'." "Review NSG rule."
                                            break # Found a prohibited port for this rule
                                        elif [[ "$port_check_target" == "*" ]]; then # Rule allows all ports, and specific port is prohibited
                                             record_result "Network" "Subnet-$subnet_name-NSGRule-$rule_name-ProhibitedPortWildcard" "FAILED" "NSG rule '$rule_name' ($direction/$protocol) uses wildcard '*' for ports, which includes prohibited port '$prohibited_port_entry' for subnet '$subnet_name'." "Review NSG rule."
                                             break
                                        fi
                                        # Add more sophisticated range checking here if needed:
                                        # E.g., if port_check_target is "100-200" and prohibited_port_entry is "150"
                                        # Or if port_check_target is "150" and prohibited_port_entry is "100-200"
                                    # Case 2: Prohibited port is "*"
                                    elif [[ "$prohibited_port_entry" == "*" ]]; then
                                        # If any rule defines any port (even specific ones, unless it's for an allowed overriding rule), it could be an issue.
                                        # This usually means NO traffic on any port is allowed unless explicitly defined in an allow list.
                                        # This check is simpler: if "*" is prohibited, any rule with a port is suspicious unless it's an overriding allow.
                                        # For now, a simple interpretation: if "*" is prohibited, any rule specifying ports is a failure.
                                        # This needs refinement based on how "allowedInbound/Outbound" rules would interact.
                                        # Let's assume for now this means no rule should exist if "*" is prohibited, unless it's a default deny.
                                        # This part is tricky and might need to be combined with allowed rules logic.
                                        # For now, if "*" is prohibited, and the rule is not a Deny rule, it's a potential issue.
                                        if [[ "$port_check_target" != "" && "$(echo "$rule_json" | jq -r .access)" == "Allow" ]]; then
                                             record_result "Network" "Subnet-$subnet_name-NSGRule-$rule_name-WildcardPortProhibited" "WARNING" "NSG rule '$rule_name' ($direction/$protocol) defines ports while '*' is prohibited for subnet '$subnet_name'. Review if this rule is overridden by a specific allow." "Review NSG rule."
                                             break
                                        fi
                                    fi
                                done # </ prohibited_ports_jq loop
                            done # </ nsg_rules_json loop
                        fi # </ prohibited_ports_jq length check
                    fi
                fi
            fi
        done
    done
    
    # General "overly permissive rules" check (can be kept or refined)
    log "INFO" "Performing general check for overly permissive NSG rules..."
    local all_nsgs_json=$(az network nsg list --query "[].{name:name, resourceGroup:resourceGroup, securityRules:securityRules}" -o json)
    
    echo "$all_nsgs_json" | jq -c '.[]' | while IFS= read -r nsg_row; do
        local nsg_name=$(echo "$nsg_row" | jq -r '.name')
        local nsg_rg=$(echo "$nsg_row" | jq -r '.resourceGroup')
        
        # Original generic check for "any" source allowing inbound
        echo "$nsg_row" | jq -c '.securityRules[]? | select(.sourceAddressPrefix == "*" and .access == "Allow" and .direction == "Inbound")' | while IFS= read -r permissive_rule_json; do
             if [[ -n "$permissive_rule_json" ]]; then # Check if anything was selected
                local rule_name=$(echo "$permissive_rule_json" | jq -r '.name')
                record_result "Network" "GenericPermissiveRule-$nsg_name-$rule_name" "WARNING" "NSG $nsg_name (RG: $nsg_rg) rule '$rule_name' allows * source for Inbound traffic." "Restrict source address for rule '$rule_name'."
             fi
        done
    done
}

# Function to check general network requirements (New)
function check_general_network_requirements {
    log "INFO" "Checking general network requirements..."

    if [[ -z "$NETWORK_REQUIREMENTS_JSON" ]]; then
        log "WARNING" "NETWORK_REQUIREMENTS_JSON not loaded. Skipping general network requirement checks."
        record_result "Network" "GeneralNetworkRequirements" "WARNING" "network_requirements.json not loaded, skipping these checks." ""
        return
    fi

    local default_deny_all_inbound=$(echo "$NETWORK_REQUIREMENTS_JSON" | jq -r '.generalRequirements.defaultDenyAllInbound // "false"')

    if [[ "$default_deny_all_inbound" == "true" ]]; then
        log "INFO" "Verifying defaultDenyAllInbound requirement for all NSGs..."
        local all_nsgs_for_deny_check=$(az network nsg list --query "[].{name:name, resourceGroup:resourceGroup, securityRules:securityRules}" -o json)

        echo "$all_nsgs_for_deny_check" | jq -c '.[]' | while IFS= read -r nsg_row; do
            local nsg_name=$(echo "$nsg_row" | jq -r '.name')
            local nsg_rg=$(echo "$nsg_row" | jq -r '.resourceGroup')
            local has_default_deny_rule=false

            # Check for a rule that denies all traffic from any source to any destination on any protocol
            # Typically these are high priority numbers (e.g., 4000-4096)
            # For simplicity, check if any rule matches the core deny-all characteristics.
            # A more precise check would also ensure it's among the highest priorities for Deny.
            echo "$nsg_row" | jq -c '.securityRules[]?' | while IFS= read -r rule_json_str; do
                if [[ -n "$rule_json_str" ]]; then # Ensure rule_json_str is not empty
                    local access=$(echo "$rule_json_str" | jq -r '.access')
                    local direction=$(echo "$rule_json_str" | jq -r '.direction')
                    local protocol=$(echo "$rule_json_str" | jq -r '.protocol')
                    local source_prefix=$(echo "$rule_json_str" | jq -r '.sourceAddressPrefix // ""')
                    local dest_port=$(echo "$rule_json_str" | jq -r '.destinationPortRange // ""')

                    if [[ "$access" == "Deny" && \
                          "$direction" == "Inbound" && \
                          "$protocol" == "*" && \
                          ( "$source_prefix" == "*" || "$source_prefix" == "0.0.0.0/0" || "$source_prefix" == "any" || "$source_prefix" == "Internet" ) && \
                          ( "$dest_port" == "*" ) ]]; then
                        has_default_deny_rule=true
                        break # Found a suitable default deny rule
                    fi
                fi
            done

            if $has_default_deny_rule; then
                record_result "Network" "NSGDefaultDenyInbound-$nsg_name" "PASSED" "NSG $nsg_name (RG: $nsg_rg) has a default deny all inbound rule." ""
            else
                record_result "Network" "NSGDefaultDenyInbound-$nsg_name" "FAILED" "NSG $nsg_name (RG: $nsg_rg) is MISSING a default deny all inbound rule." "Add a high-priority deny all inbound rule to NSG $nsg_name."
            fi
        done
    else
        log "INFO" "generalRequirements.defaultDenyAllInbound is not true or not set in network_requirements.json. Skipping this check."
    fi
    # Add other general checks here, e.g., for defaultDenyAllOutbound, requireFlowLogging
}


# Function to check encryption standards
function check_encryption_standards {
    log "INFO" "Checking encryption standards..."
    
    # Check Key Vault configuration
    log "INFO" "Checking Key Vault configuration..."
    
    # Get all Key Vaults
    local key_vaults=$(az keyvault list -o json)
    
    for kv in $(echo "$key_vaults" | jq -c '.[]'); do
        local kv_name=$(echo "$kv" | jq -r '.name')
        local resource_group=$(echo "$kv" | jq -r '.resourceGroup')
        
        # Check if using Premium SKU (required for HSM)
        local sku=$(echo "$kv" | jq -r '.properties.sku.name')
        if [[ "$sku" != "Premium" ]]; then
            record_result "Encryption" "KeyVault-SKU-$kv_name" "FAILED" "Key Vault $kv_name is not using Premium SKU (required for HSM)" "Upgrade the Key Vault to Premium SKU"
        else
            record_result "Encryption" "KeyVault-SKU-$kv_name" "PASSED" "Key Vault $kv_name is using Premium SKU" ""
        fi
        
        # Check if soft delete is enabled
        local soft_delete=$(echo "$kv" | jq -r '.properties.enableSoftDelete')
        if [[ "$soft_delete" != "true" ]]; then
            record_result "Encryption" "KeyVault-SoftDelete-$kv_name" "FAILED" "Key Vault $kv_name does not have soft delete enabled" "Enable soft delete for the Key Vault"
            
            if [[ "$REMEDIATE" == "true" ]]; then
                log "INFO" "Attempting to remediate by enabling soft delete..."
                az keyvault update --name "$kv_name" --enable-soft-delete true || log "ERROR" "Failed to enable soft delete for Key Vault: $kv_name"
            fi
        else
            record_result "Encryption" "KeyVault-SoftDelete-$kv_name" "PASSED" "Key Vault $kv_name has soft delete enabled" ""
        fi
        
        # Check if purge protection is enabled
        local purge_protection=$(echo "$kv" | jq -r '.properties.enablePurgeProtection // false')
        if [[ "$purge_protection" != "true" ]]; then
            record_result "Encryption" "KeyVault-PurgeProtection-$kv_name" "FAILED" "Key Vault $kv_name does not have purge protection enabled" "Enable purge protection for the Key Vault"
            
            if [[ "$REMEDIATE" == "true" ]]; then
                log "INFO" "Attempting to remediate by enabling purge protection..."
                az keyvault update --name "$kv_name" --enable-purge-protection true || log "ERROR" "Failed to enable purge protection for Key Vault: $kv_name"
            fi
        else
            record_result "Encryption" "KeyVault-PurgeProtection-$kv_name" "PASSED" "Key Vault $kv_name has purge protection enabled" ""
        fi
        
        # Check network access configuration
        local network_acls=$(echo "$kv" | jq -r '.properties.networkAcls.defaultAction // "Allow"')
        if [[ "$network_acls" != "Deny" ]]; then
            record_result "Encryption" "KeyVault-NetworkACLs-$kv_name" "WARNING" "Key Vault $kv_name does not restrict network access (default action: $network_acls)" "Configure network ACLs to restrict access"
        else
            record_result "Encryption" "KeyVault-NetworkACLs-$kv_name" "PASSED" "Key Vault $kv_name restricts network access" ""
        fi
    done
    
    # Check Storage Account encryption
    log "INFO" "Checking Storage Account encryption..."
    
    # Get all Storage Accounts
    local storage_accounts=$(az storage account list -o json)
    
    for sa in $(echo "$storage_accounts" | jq -c '.[]'); do
        local sa_name=$(echo "$sa" | jq -r '.name')
        local resource_group=$(echo "$sa" | jq -r '.resourceGroup')
        
        # Check if encryption is enabled
        local encryption_enabled=$(echo "$sa" | jq -r '.encryption.services.blob.enabled')
        if [[ "$encryption_enabled" != "true" ]]; then
            record_result "Encryption" "StorageEncryption-$sa_name" "FAILED" "Storage Account $sa_name does not have encryption enabled" "Enable encryption for the Storage Account"
        else
            record_result "Encryption" "StorageEncryption-$sa_name" "PASSED" "Storage Account $sa_name has encryption enabled" ""
        fi
        
        # Check if HTTPS is enforced
        local https_only=$(echo "$sa" | jq -r '.enableHttpsTrafficOnly')
        if [[ "$https_only" != "true" ]]; then
            record_result "Encryption" "StorageHttps-$sa_name" "FAILED" "Storage Account $sa_name does not enforce HTTPS" "Enable HTTPS-only for the Storage Account"
            
            if [[ "$REMEDIATE" == "true" ]]; then
                log "INFO" "Attempting to remediate by enabling HTTPS-only..."
                az storage account update --name "$sa_name" --resource-group "$resource_group" --https-only true || log "ERROR" "Failed to enable HTTPS-only for Storage Account: $sa_name"
            fi
        else
            record_result "Encryption" "StorageHttps-$sa_name" "PASSED" "Storage Account $sa_name enforces HTTPS" ""
        fi
        
        # Check minimum TLS version
        local min_tls=$(echo "$sa" | jq -r '.minimumTlsVersion // "TLS1_0"')
        if [[ "$min_tls" != "TLS1_2" ]]; then
            record_result "Encryption" "StorageTLS-$sa_name" "FAILED" "Storage Account $sa_name does not enforce TLS 1.2 (current: $min_tls)" "Enforce TLS 1.2 for the Storage Account"
            
            if [[ "$REMEDIATE" == "true" ]]; then
                log "INFO" "Attempting to remediate by enforcing TLS 1.2..."
                az storage account update --name "$sa_name" --resource-group "$resource_group" --min-tls-version TLS1_2 || log "ERROR" "Failed to enforce TLS 1.2 for Storage Account: $sa_name"
            fi
        else
            record_result "Encryption" "StorageTLS-$sa_name" "PASSED" "Storage Account $sa_name enforces TLS 1.2" ""
        fi
    done
}

# Function to check access controls
function check_access_controls {
    log "INFO" "Checking access controls..."
    
    # Check for privileged role assignments
    log "INFO" "Checking privileged role assignments..."
    
    # Get all role assignments for Owner and Contributor roles
    local privileged_roles=$(az role assignment list --include-inherited --include-groups --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']" -o json)
    
    # Count the number of privileged assignments
    local privileged_count=$(echo "$privileged_roles" | jq 'length')
    
    if [[ "$privileged_count" -gt 5 ]]; then
        record_result "AccessControl" "PrivilegedRoles" "WARNING" "There are $privileged_count privileged role assignments (Owner/Contributor)" "Review and minimize privileged role assignments"
    else
        record_result "AccessControl" "PrivilegedRoles" "PASSED" "There are $privileged_count privileged role assignments (Owner/Contributor)" ""
    fi
    
    # Check for custom roles
    log "INFO" "Checking custom roles..."
    
    local custom_roles=$(az role definition list --custom-role-only true -o json)
    local custom_roles_count=$(echo "$custom_roles" | jq 'length')
    
    if [[ "$custom_roles_count" -gt 0 ]]; then
        # Check for overly permissive custom roles
        local permissive_roles=$(echo "$custom_roles" | jq '[.[] | select(.permissions[].actions | contains(["*"]))] | length')
        
        if [[ "$permissive_roles" -gt 0 ]]; then
            record_result "AccessControl" "CustomRoles" "WARNING" "There are $permissive_roles custom roles with wildcard (*) permissions" "Review and restrict permissions in custom roles"
        else
            record_result "AccessControl" "CustomRoles" "PASSED" "No custom roles with wildcard permissions found" ""
        fi
    else
        record_result "AccessControl" "CustomRoles" "PASSED" "No custom roles defined" ""
    fi
    
    # Check Azure AD PIM settings (requires Graph API permissions)
    log "INFO" "Checking Azure AD PIM settings (limited check)..."
    
    # This is a simplified check - in a real environment, you would use Microsoft Graph API
    # to check PIM settings in detail
    
    # For demonstration, we'll just check if there are any permanent Owner assignments
    local permanent_owners=$(az role assignment list --role Owner --query "[?properties.principalType=='User']" -o json)
    local permanent_owners_count=$(echo "$permanent_owners" | jq 'length')
    
    if [[ "$permanent_owners_count" -gt 0 ]]; then
        record_result "AccessControl" "PermanentOwners" "WARNING" "There are $permanent_owners_count permanent Owner role assignments" "Consider using Azure AD PIM for just-in-time privileged access"
    else
        record_result "AccessControl" "PermanentOwners" "PASSED" "No permanent Owner role assignments found" ""
    fi
}

# Function to check monitoring and logging
function check_monitoring {
    log "INFO" "Checking monitoring and logging configuration..."
    
    # Check if Azure Monitor is configured
    log "INFO" "Checking Azure Monitor configuration..."
    
    # Check Log Analytics workspaces
    local workspaces=$(az monitor log-analytics workspace list -o json)
    local workspace_count=$(echo "$workspaces" | jq 'length')
    
    if [[ "$workspace_count" -eq 0 ]]; then
        record_result "Monitoring" "LogAnalyticsWorkspace" "FAILED" "No Log Analytics workspace found" "Create a Log Analytics workspace for centralized logging"
    else
        record_result "Monitoring" "LogAnalyticsWorkspace" "PASSED" "Log Analytics workspace(s) found" ""
        
        # Check retention period for each workspace
        for workspace in $(echo "$workspaces" | jq -c '.[]'); do
            local workspace_name=$(echo "$workspace" | jq -r '.name')
            local retention=$(echo "$workspace" | jq -r '.retentionInDays')
            
            if [[ "$retention" -lt 365 ]]; then
                record_result "Monitoring" "LogRetention-$workspace_name" "FAILED" "Log Analytics workspace $workspace_name has retention period less than 365 days (current: $retention days)" "Increase retention period to at least 365 days"
                
                if [[ "$REMEDIATE" == "true" ]]; then
                    log "INFO" "Attempting to remediate by increasing retention period..."
                    local resource_group=$(echo "$workspace" | jq -r '.resourceGroup')
                    az monitor log-analytics workspace update --name "$workspace_name" --resource-group "$resource_group" --retention-time 365 || log "ERROR" "Failed to update retention period for workspace: $workspace_name"
                fi
            else
                record_result "Monitoring" "LogRetention-$workspace_name" "PASSED" "Log Analytics workspace $workspace_name has sufficient retention period ($retention days)" ""
            fi
        done
    fi
    
    # Check diagnostic settings for key resources
    log "INFO" "Checking diagnostic settings for key resources..."
    
    # Check Key Vaults
    local key_vaults=$(az keyvault list --query '[].name' -o tsv)
    
    for kv_name in $key_vaults; do
        local diag_settings=$(az monitor diagnostic-settings list --resource "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/*/providers/Microsoft.KeyVault/vaults/$kv_name" -o json 2>/dev/null)
        local diag_count=$(echo "$diag_settings" | jq 'length')
        
        if [[ "$diag_count" -eq 0 ]]; then
            record_result "Monitoring" "KeyVaultDiagnostics-$kv_name" "FAILED" "No diagnostic settings found for Key Vault $kv_name" "Configure diagnostic settings to send logs to Log Analytics"
        else
            # Check if logs are sent to Log Analytics
            local log_analytics_configured=$(echo "$diag_settings" | jq '[.[] | select(.workspaceId != null)] | length')
            
            if [[ "$log_analytics_configured" -eq 0 ]]; then
                record_result "Monitoring" "KeyVaultDiagnostics-$kv_name" "WARNING" "Diagnostic settings for Key Vault $kv_name do not send logs to Log Analytics" "Configure diagnostic settings to send logs to Log Analytics"
            else
                record_result "Monitoring" "KeyVaultDiagnostics-$kv_name" "PASSED" "Diagnostic settings for Key Vault $kv_name send logs to Log Analytics" ""
            fi
        fi
    done
    
    # Check if Azure Security Center is configured
    log "INFO" "Checking Azure Security Center configuration..."
    
    local asc_policy=$(az security auto-provisioning-setting show --name "default" -o json 2>/dev/null)
    local auto_provisioning=$(echo "$asc_policy" | jq -r '.autoProvision // "Off"')
    
    if [[ "$auto_provisioning" != "On" ]]; then
        record_result "Monitoring" "SecurityCenterAutoProvisioning" "WARNING" "Azure Security Center auto-provisioning is not enabled" "Enable auto-provisioning in Azure Security Center"
    else
        record_result "Monitoring" "SecurityCenterAutoProvisioning" "PASSED" "Azure Security Center auto-provisioning is enabled" ""
    fi
}

# Function to check PCI-DSS specific requirements
function check_pci_dss {
    log "INFO" "Checking PCI-DSS specific requirements..."
    
    # Check requirement 3.4 - Encrypt PAN data
    log "INFO" "Checking PCI-DSS Requirement 3.4 - Encrypt PAN data..."
    
    # This would be a more complex check in a real environment
    # For demonstration, we'll check if there are any storage accounts without encryption
    
    local storage_accounts=$(az storage account list --query "[?encryption.services.blob.enabled==\`false\`]" -o json)
    local unencrypted_count=$(echo "$storage_accounts" | jq 'length')
    
    if [[ "$unencrypted_count" -gt 0 ]]; then
        record_result "PCI-DSS" "Req3.4-Encryption" "FAILED" "Found $unencrypted_count storage accounts without encryption" "Enable encryption for all storage accounts"
    else
        record_result "PCI-DSS" "Req3.4-Encryption" "PASSED" "All storage accounts have encryption enabled" ""
    fi
    
    # Check requirement 6.5 - Secure development
    log "INFO" "Checking PCI-DSS Requirement 6.5 - Secure development..."
    
    # This would be a more complex check in a real environment
    # For demonstration, we'll check if Azure DevOps security scanning is enabled
    
    # Placeholder for actual implementation
    record_result "PCI-DSS" "Req6.5-SecureDevelopment" "WARNING" "Manual verification required for secure development practices" "Implement secure coding standards and security testing in CI/CD pipelines"
    
    # Check requirement 10.2 - Automated audit trails
    log "INFO" "Checking PCI-DSS Requirement 10.2 - Automated audit trails..."
    
    # Check if Activity Log is being collected
    local activity_log_settings=$(az monitor diagnostic-settings list --resource "/subscriptions/$SUBSCRIPTION_ID" -o json 2>/dev/null)
    local activity_log_count=$(echo "$activity_log_settings" | jq 'length')
    
    if [[ "$activity_log_count" -eq 0 ]]; then
        record_result "PCI-DSS" "Req10.2-AuditTrails" "FAILED" "No diagnostic settings found for Activity Log" "Configure diagnostic settings to send Activity Log to Log Analytics"
    else
        record_result "PCI-DSS" "Req10.2-AuditTrails" "PASSED" "Activity Log is being collected" ""
    fi
}

# Function to check SWIFT-SCR specific requirements
function check_swift_scr {
    log "INFO" "Checking SWIFT-SCR specific requirements..."
    
    # Check SWIFT CSP 1.1 - Restrict Internet Access
    log "INFO" "Checking SWIFT CSP 1.1 - Restrict Internet Access..."
    
    # This would be a more complex check in a real environment
    # For demonstration, we'll check if there are any NSGs with open internet access
    
    local nsgs=$(az network nsg list -o json)
    
    local open_internet_rules=0
    for nsg in $(echo "$nsgs" | jq -c '.[]'); do
        local nsg_name=$(echo "$nsg" | jq -r '.name')
        
        # Check for rules allowing inbound traffic from internet
        local internet_rules=$(echo "$nsg" | jq '.securityRules[] | select(.sourceAddressPrefix == "Internet" and .access == "Allow" and .direction == "Inbound")')
        
        if [[ -n "$internet_rules" ]]; then
            open_internet_rules=$((open_internet_rules + 1))
        fi
    done
    
    if [[ "$open_internet_rules" -gt 0 ]]; then
        record_result "SWIFT-SCR" "CSP1.1-RestrictInternet" "FAILED" "Found $open_internet_rules NSGs with rules allowing inbound traffic from Internet" "Review and restrict internet access in NSG rules"
    else
        record_result "SWIFT-SCR" "CSP1.1-RestrictInternet" "PASSED" "No NSGs with open internet access found" ""
    fi
    
    # Check SWIFT CSP 2.2 - Multi-factor Authentication
    log "INFO" "Checking SWIFT CSP 2.2 - Multi-factor Authentication..."
    
    # This would require Microsoft Graph API access to check MFA status
    # For demonstration, we'll just provide a warning
    
    record_result "SWIFT-SCR" "CSP2.2-MFA" "WARNING" "Manual verification required for multi-factor authentication" "Ensure MFA is enabled for all users with access to SWIFT-related resources"
    
    # Check SWIFT CSP 5.1 - Vulnerability Scanning
    log "INFO" "Checking SWIFT CSP 5.1 - Vulnerability Scanning..."
    
    # Check if Azure Security Center vulnerability assessment is enabled
    local va_solutions=$(az security va list -o json 2>/dev/null)
    local va_count=$(echo "$va_solutions" | jq 'length')
    
    if [[ "$va_count" -eq 0 ]]; then
        record_result "SWIFT-SCR" "CSP5.1-VulnerabilityScanning" "FAILED" "No vulnerability assessment solution found" "Enable vulnerability assessment in Azure Security Center"
    else
        record_result "SWIFT-SCR" "CSP5.1-VulnerabilityScanning" "PASSED" "Vulnerability assessment solution found" ""
    fi
}

# Function to generate the final report
function generate_report {
    log "INFO" "Generating compliance report..."
    
    # Calculate compliance score
    local compliance_score=0
    if [[ "$TOTAL_CHECKS" -gt 0 ]]; then
        compliance_score=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
    fi
    
    # Create report JSON
    local report_json=$(cat <<EOF
{
    "summary": {
        "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
        "subscription_id": "$SUBSCRIPTION_ID",
        "framework": "$FRAMEWORK",
        "total_checks": $TOTAL_CHECKS,
        "passed_checks": $PASSED_CHECKS,
        "failed_checks": $FAILED_CHECKS,
        "warning_checks": $WARNING_CHECKS,
        "compliance_score": $compliance_score
    },
    "results": [
EOF
)
    
    # Add all results to the report
    local first=true
    for key in "${!COMPLIANCE_RESULTS[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            report_json+=","
        fi
        report_json+="${COMPLIANCE_RESULTS[$key]}"
    done
    
    report_json+="
    ]
}"
    
    # Save report to file
    echo "$report_json" > "$REPORT_FILE"
    
    # Generate different format if requested
    case "$OUTPUT_FORMAT" in
        "csv")
            log "INFO" "Converting report to CSV format..."
            echo "Category,Check,Status,Details,Remediation,Timestamp" > "${REPORT_FILE%.json}.csv"
            echo "$report_json" | jq -r '.results[] | [.category, .check, .status, .details, .remediation, .timestamp] | @csv' >> "${REPORT_FILE%.json}.csv"
            REPORT_FILE="${REPORT_FILE%.json}.csv"
            ;;
        "html")
            log "INFO" "Converting report to HTML format..."
            # Create HTML report
            cat > "${REPORT_FILE%.json}.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Report - $(date +%Y-%m-%d)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #0066cc; }
        .summary { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .score { font-size: 24px; font-weight: bold; }
        .passed { color: #00aa00; }
        .failed { color: #cc0000; }
        .warning { color: #ff9900; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #0066cc; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .status-PASSED { background-color: #dfffdf; }
        .status-FAILED { background-color: #ffdfdf; }
        .status-WARNING { background-color: #ffffdf; }
        .remediation { font-style: italic; color: #666; }
    </style>
</head>
<body>
    <h1>Compliance Report</h1>
    <div class="summary">
        <p><strong>Subscription ID:</strong> $SUBSCRIPTION_ID</p>
        <p><strong>Framework:</strong> $FRAMEWORK</p>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>Compliance Score:</strong> <span class="score">$compliance_score%</span></p>
        <p>
            <span class="passed">✓ Passed: $PASSED_CHECKS</span> | 
            <span class="failed">✗ Failed: $FAILED_CHECKS</span> | 
            <span class="warning">⚠ Warnings: $WARNING_CHECKS</span> | 
            Total: $TOTAL_CHECKS
        </p>
    </div>
EOF

            # Add results by category
            echo "<h2>Detailed Results</h2>" >> "${REPORT_FILE%.json}.html"
            
            # Get unique categories
            local categories=$(echo "$report_json" | jq -r '.results[].category' | sort | uniq)
            
            for category in $categories; do
                echo "<h3>$category</h3>" >> "${REPORT_FILE%.json}.html"
                echo "<table>" >> "${REPORT_FILE%.json}.html"
                echo "<tr><th>Check</th><th>Status</th><th>Details</th><th>Remediation</th></tr>" >> "${REPORT_FILE%.json}.html"
                
                # Filter results for this category
                local category_results=$(echo "$report_json" | jq -r --arg cat "$category" '.results[] | select(.category == $cat)')
                
                echo "$category_results" | jq -c '.' | while read -r result; do
                    local check=$(echo "$result" | jq -r '.check')
                    local status=$(echo "$result" | jq -r '.status')
                    local details=$(echo "$result" | jq -r '.details')
                    local remediation=$(echo "$result" | jq -r '.remediation')
                    
                    echo "<tr class=\"status-$status\">" >> "${REPORT_FILE%.json}.html"
                    echo "<td>$check</td>" >> "${REPORT_FILE%.json}.html"
                    
                    # Status with icon
                    if [[ "$status" == "PASSED" ]]; then
                        echo "<td>✓ Passed</td>" >> "${REPORT_FILE%.json}.html"
                    elif [[ "$status" == "FAILED" ]]; then
                        echo "<td>✗ Failed</td>" >> "${REPORT_FILE%.json}.html"
                    else
                        echo "<td>⚠ Warning</td>" >> "${REPORT_FILE%.json}.html"
                    fi
                    
                    echo "<td>$details</td>" >> "${REPORT_FILE%.json}.html"
                    echo "<td class=\"remediation\">$remediation</td>" >> "${REPORT_FILE%.json}.html"
                    echo "</tr>" >> "${REPORT_FILE%.json}.html"
                done
                
                echo "</table>" >> "${REPORT_FILE%.json}.html"
            done
            
            # Close HTML
            echo "</body></html>" >> "${REPORT_FILE%.json}.html"
            REPORT_FILE="${REPORT_FILE%.json}.html"
            ;;
    esac
    
    log "SUCCESS" "Compliance report generated: $REPORT_FILE"
    
    # Print summary to console
    echo -e "\n${BLUE}=== Compliance Check Summary ===${NC}"
    echo -e "Total checks: $TOTAL_CHECKS"
    echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
    echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"
    echo -e "Warnings: ${YELLOW}$WARNING_CHECKS${NC}"
    echo -e "Compliance score: ${BLUE}$compliance_score%${NC}"
    echo -e "Report saved to: ${BLUE}$REPORT_FILE${NC}\n"
}

# Function to check Azure Policy compliance
function check_azure_policy {
    log "INFO" "Checking Azure Policy compliance..."
    
    # Get policy state summary
    local policy_summary=$(az policy state summarize -o json)
    
    # Get non-compliant policies
    local non_compliant=$(echo "$policy_summary" | jq '.policyAssignments[] | select(.results.nonCompliantResources > 0)')
    local non_compliant_count=$(echo "$non_compliant" | jq -s 'length')
    
    if [[ "$non_compliant_count" -gt 0 ]]; then
        # Get details of non-compliant policies
        for policy in $(echo "$non_compliant" | jq -c '.'); do
            local policy_name=$(echo "$policy" | jq -r '.policyAssignmentId' | awk -F '/' '{print $NF}')
            local non_compliant_resources=$(echo "$policy" | jq -r '.results.nonCompliantResources')
            
            record_result "AzurePolicy" "PolicyCompliance-$policy_name" "FAILED" "$non_compliant_resources resources are non-compliant with policy $policy_name" "Review non-compliant resources and remediate issues"
            
            # Get specific non-compliant resources for this policy
            if [[ "$VERBOSE" == "true" ]]; then
                log "INFO" "Non-compliant resources for policy $policy_name:"
                az policy state list --filter "policyAssignmentName eq '$policy_name' and complianceState eq 'NonCompliant'" --query "[].resourceId" -o tsv | while read -r resource_id; do
                    log "INFO" "  - $resource_id"
                done
            fi
        done
    else
        record_result "AzurePolicy" "PolicyCompliance" "PASSED" "All resources are compliant with assigned policies" ""
    fi
    
    # Check if required policies are assigned
    log "INFO" "Checking for required security policies..."
    
    local required_policies=(
        "Enable Azure Security Center on your subscription"
        "Require encryption on Data Lake Store accounts"
        "Secure transfer to storage accounts should be enabled"
        "Deploy network watcher when virtual networks are created"
    )
    
    local assigned_policies=$(az policy assignment list --query "[].displayName" -o json)
    
    for policy in "${required_policies[@]}"; do
        if echo "$assigned_policies" | jq -e --arg policy "$policy" 'contains([$policy])' > /dev/null; then
            record_result "AzurePolicy" "RequiredPolicy-$(echo $policy | tr ' ' '-')" "PASSED" "Required policy '$policy' is assigned" ""
        else
            record_result "AzurePolicy" "RequiredPolicy-$(echo $policy | tr ' ' '-')" "WARNING" "Required policy '$policy' is not assigned" "Assign the policy to ensure compliance"
        fi
    done
}

# Function to check Azure Security Center recommendations
function check_security_center {
    log "INFO" "Checking Azure Security Center recommendations..."
    
    # Get security recommendations
    local recommendations=$(az security recommendation list -o json)
    
    # Count recommendations by severity
    local high_severity=$(echo "$recommendations" | jq '[.[] | select(.properties.severity == "High")] | length')
    local medium_severity=$(echo "$recommendations" | jq '[.[] | select(.properties.severity == "Medium")] | length')
    local low_severity=$(echo "$recommendations" | jq '[.[] | select(.properties.severity == "Low")] | length')
    
    if [[ "$high_severity" -gt 0 ]]; then
        record_result "SecurityCenter" "HighSeverityRecommendations" "FAILED" "There are $high_severity high severity security recommendations" "Review and remediate high severity recommendations"
    else
        record_result "SecurityCenter" "HighSeverityRecommendations" "PASSED" "No high severity security recommendations found" ""
    fi
    
    if [[ "$medium_severity" -gt 0 ]]; then
        record_result "SecurityCenter" "MediumSeverityRecommendations" "WARNING" "There are $medium_severity medium severity security recommendations" "Review and remediate medium severity recommendations"
    else
        record_result "SecurityCenter" "MediumSeverityRecommendations" "PASSED" "No medium severity security recommendations found" ""
    fi
    
    # Check secure score
    log "INFO" "Checking Azure Security Center secure score..."
    
    local secure_score=$(az security secure-score list --query "[0].properties.score.current" -o tsv 2>/dev/null)
    
    if [[ -z "$secure_score" ]]; then
        record_result "SecurityCenter" "SecureScore" "WARNING" "Unable to retrieve secure score" "Ensure Azure Security Center is properly configured"
    else
        if [[ $(echo "$secure_score < 70" | bc -l) -eq 1 ]]; then
            record_result "SecurityCenter" "SecureScore" "WARNING" "Secure score is below 70% (current: $secure_score%)" "Review security recommendations to improve secure score"
        else
            record_result "SecurityCenter" "SecureScore" "PASSED" "Secure score is $secure_score%" ""
        fi
    fi
}

# Function to check real-time compliance validation
function check_real_time_validation {
    log "INFO" "Checking real-time compliance validation capabilities..."
    
    # Check if Azure Event Grid is configured for security events
    local event_grid_topics=$(az eventgrid topic list -o json)
    local security_topics=$(echo "$event_grid_topics" | jq '[.[] | select(.name | contains("security"))] | length')
    
    if [[ "$security_topics" -eq 0 ]]; then
        record_result "RealTimeValidation" "EventGridIntegration" "WARNING" "No Event Grid topics found for security events" "Configure Event Grid for real-time security event processing"
    else
        record_result "RealTimeValidation" "EventGridIntegration" "PASSED" "Event Grid topics found for security events" ""
    fi
    
    # Check if Azure Functions or Logic Apps are used for automated remediation
    local functions=$(az functionapp list --query "[?contains(name, 'security') || contains(name, 'compliance') || contains(name, 'remediation')].name" -o json)
    local functions_count=$(echo "$functions" | jq 'length')
    
    local logic_apps=$(az logic workflow list --query "[?contains(name, 'security') || contains(name, 'compliance') || contains(name, 'remediation')].name" -o json)
    local logic_apps_count=$(echo "$logic_apps" | jq 'length')
    
    if [[ "$functions_count" -eq 0 && "$logic_apps_count" -eq 0 ]]; then
        record_result "RealTimeValidation" "AutomatedRemediation" "WARNING" "No Azure Functions or Logic Apps found for automated remediation" "Implement automated remediation workflows"
    else
        record_result "RealTimeValidation" "AutomatedRemediation" "PASSED" "Found $functions_count Functions and $logic_apps_count Logic Apps for automated remediation" ""
    fi
    
    # Check if Azure Monitor alerts are configured for compliance
    local alerts=$(az monitor alert list -o json 2>/dev/null)
    local compliance_alerts=$(echo "$alerts" | jq '[.[] | select(.name | contains("compliance") or .name | contains("security"))] | length')
    
    if [[ "$compliance_alerts" -eq 0 ]]; then
        record_result "RealTimeValidation" "ComplianceAlerts" "WARNING" "No compliance-related alerts found" "Configure alerts for compliance violations"
    else
        record_result "RealTimeValidation" "ComplianceAlerts" "PASSED" "Found $compliance_alerts compliance-related alerts" ""
    fi
}

# Main function
function main {
    # Display banner
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║             AZURE COMPLIANCE VALIDATION FRAMEWORK             ║"
    echo "║                                                               ║"
    echo "║                 For Regulated Industries                      ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Check prerequisites
    check_prerequisites

    # Load external configurations (New)
    load_external_configs
    
    # Run general network requirements check first if applicable
    if [[ "$FRAMEWORK" == "all" || "$FRAMEWORK" == "pci-dss" || "$FRAMEWORK" == "swift-scr" ]]; then # Assuming general checks apply to all relevant frameworks
        check_general_network_requirements
    fi

    # Run compliance checks based on selected framework
    if [[ "$FRAMEWORK" == "all" || "$FRAMEWORK" == "pci-dss" ]]; then
        check_network_segmentation # This is now enhanced by network_requirements.json
        check_encryption_standards
        check_access_controls
        check_monitoring
        check_pci_dss
    fi
    
    if [[ "$FRAMEWORK" == "all" || "$FRAMEWORK" == "swift-scr" ]]; then
        # check_network_segmentation is already called if framework is 'all' or 'pci-dss'
        # If only 'swift-scr' is specified, then call it.
        if [[ "$FRAMEWORK" == "swift-scr" && "$FRAMEWORK" != "pci-dss" ]]; then # Avoid double call if 'all'
             check_network_segmentation
        fi
        check_encryption_standards
        check_access_controls
        check_monitoring
        check_swift_scr
    fi
    
    # Run additional checks
    check_azure_policy
    check_security_center
    check_real_time_validation
    
    # Generate report
    generate_report
}

# Run main function
main