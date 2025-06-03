#!/bin/bash
#
# Purpose: Performs data-driven compliance verification of Azure resources.
# This script reads control definitions from 'config/compliance/critical_controls.json'
# and executes corresponding checks against the Azure environment.
# It covers various areas like Key Vault configuration, Network Security Group rules,
# RBAC, custom roles, diagnostic settings, Log Analytics, and Sentinel.
#
# Usage: ./verify-compliance.sh [options]
#
# Options:
#   -s <subscription_id>   : Azure Subscription ID. Defaults to the current active subscription.
#   -g <resource_group>    : Name of the Resource Group to scope checks to. Many controls use this
#                            as the default scope if a more specific target is not defined in the control.
#                            If not specified, some checks might run across all RGs (if supported by the check)
#                            or require explicit `targetScope` in the control definition.
#   -w <la_workspace_name> : Name of the primary Log Analytics workspace (e.g., for Sentinel, LA retention checks).
#                            Can often be auto-detected if named conventionally (e.g., contains 'security') if not provided.
#   -k <key_vault_name>    : Name of a primary Key Vault. Some Key Vault checks might use this if a specific
#                            Key Vault is not defined in the `targetScope` of the control.
#                            Can be auto-detected if one is available in the context.
#   -o <report_output_dir> : Directory to save the JSON compliance report.
#                            Defaults to "./compliance-reports".
#
# Prerequisites:
#   - Azure CLI: Installed and logged in (run `az login`).
#   - jq: JSON processor utility must be installed.
#   - Configuration File: `config/compliance/critical_controls.json` must exist at `../../config/compliance/critical_controls.json`
#     relative to this script's location. This file dictates the checks to be performed.
#
# Example Usage:
#   # Run checks against the current subscription, attempting to auto-detect RG/KeyVault/LAW where possible
#   ./verify-compliance.sh
#
#   # Run checks scoped to a specific resource group and subscription
#   ./verify-compliance.sh -s "your-subscription-id" -g "your-resource-group"
#
#   # Specify Key Vault and Log Analytics Workspace for checks that might use them as defaults
#   ./verify-compliance.sh -s "your-subscription-id" -g "your-resource-group" -k "myMainKeyVault" -w "myMainLogAnalyticsWorkspace"
#
# Output:
#   - Detailed logs to STDOUT, prefixed with INFO, ERROR, WARNING, SUCCESS.
#   - A JSON report file named `compliance-report-YYYYMMDD-HHMMSS.json` in the specified output directory.
#   - Exits with 0 if all executed checks (not skipped) are "Compliant".
#   - Exits with 1 if any check results in "Non-Compliant", or if a script/configuration error occurs.
#

set -e

# Configuration
SUBSCRIPTION_ID=""
RESOURCE_GROUP=""
LOG_ANALYTICS_WORKSPACE=""
KEY_VAULT_NAME=""
REPORT_OUTPUT_DIR="./compliance-reports"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
REPORT_FILE="${REPORT_OUTPUT_DIR}/compliance-report-${TIMESTAMP}.json"
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
CRITICAL_CONTROLS_FILE="$SCRIPT_DIR/../../config/compliance/critical_controls.json" # Adjusted path
# FRAMEWORKS variable and old functions are removed by this diff.

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
        az account set --subscription "$SUBSCRIPTION_ID" --only-show-errors || { echo -e "${RED}[ERROR]${NC} Failed to set subscription $SUBSCRIPTION_ID"; exit 1; }
        echo -e "${BLUE}[INFO]${NC} Using subscription: $SUBSCRIPTION_ID"
    else
        SUBSCRIPTION_ID=$(az account show --query id -o tsv --only-show-errors)
        if [ $? -ne 0 ] || [ -z "$SUBSCRIPTION_ID" ]; then
            echo -e "${RED}[ERROR]${NC} Failed to get current subscription. Please login to Azure CLI."
            exit 1
        fi
        echo -e "${BLUE}[INFO]${NC} Using current subscription: $SUBSCRIPTION_ID"
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$REPORT_OUTPUT_DIR"

    # Check if CRITICAL_CONTROLS_FILE exists
    if [ ! -f "$CRITICAL_CONTROLS_FILE" ]; then
        echo -e "${RED}[ERROR]${NC} Critical controls file not found at: $CRITICAL_CONTROLS_FILE"
        exit 1
    fi
    echo -e "${BLUE}[INFO]${NC} Loading critical controls from: $CRITICAL_CONTROLS_FILE"
}

# Load configuration from environment or parameters
load_configuration() {
    echo -e "${BLUE}[INFO]${NC} Loading script configuration..."
    
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
            echo -e "${YELLOW}[WARN]${NC} Resource group not specified. Some checks might be limited or require specific targetScope in controls JSON."
        fi
    fi
    
    if [ -z "$LOG_ANALYTICS_WORKSPACE" ]; then
        LOG_ANALYTICS_WORKSPACE=${AZURE_LOG_ANALYTICS_WORKSPACE:-""}
        if [ -z "$LOG_ANALYTICS_WORKSPACE" ]; then
            echo -e "${YELLOW}[WARN]${NC} Log Analytics workspace not specified. Will attempt to auto-detect for relevant controls."
            # Auto-detection for default LAW (e.g., containing 'security')
            # This is a best-effort detection if not specified.
            # local detected_law=$(az monitor log-analytics workspace list --query "[?contains(name, 'security')].name" -o tsv | head -n 1)
            # if [ -n "$detected_law" ]; then
            #     LOG_ANALYTICS_WORKSPACE=$detected_law
            #     echo -e "${BLUE}[INFO]${NC} Auto-detected Log Analytics workspace: $LOG_ANALYTICS_WORKSPACE"
            # fi
        fi
    fi
    
    if [ -z "$KEY_VAULT_NAME" ]; then
        KEY_VAULT_NAME=${AZURE_KEY_VAULT_NAME:-""}
        if [ -z "$KEY_VAULT_NAME" ]; then
            echo -e "${YELLOW}[WARN]${NC} Key Vault name not specified. Some Key Vault checks might be skipped or require specific targetScope."
            # Auto-detection for a default KV
            # local detected_kv=$(az keyvault list --query "[0].name" -o tsv 2>/dev/null)
            # if [ -n "$detected_kv" ]; then
            #     KEY_VAULT_NAME=$detected_kv
            #     echo -e "${BLUE}[INFO]${NC} Auto-detected Key Vault: $KEY_VAULT_NAME"
            # fi
        fi
    fi
}

# START OF DATA-DRIVEN CHECK FUNCTIONS (NEW MODEL)

# Helper function to parse integer, returns default if input is not a valid int
parseInt() {
    local input=$1
    local default_val=$2
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        echo "$input"
    else
        echo "$default_val"
    fi
}

# Example: check_key_vault_sku "MyKeyVault" "Premium"
check_key_vault_sku() {
    local kv_name=$1
    local expected_sku=$2
    local finding_status="Compliant"
    local finding_message="Key Vault $kv_name SKU is $expected_sku as expected."

    local actual_sku=$(az keyvault show --name "$kv_name" --resource-group "$RESOURCE_GROUP" --query "properties.sku.name" -o tsv 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$actual_sku" ]; then
        finding_status="Error"
        finding_message="Key Vault $kv_name: Could not retrieve SKU. Ensure KV exists and RG ('$RESOURCE_GROUP') is correct."
    elif [ "$actual_sku" != "$expected_sku" ]; then
        finding_status="Non-Compliant"
        finding_message="Key Vault $kv_name: Expected SKU '$expected_sku', but found '$actual_sku'."
    fi
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
}

# Example: check_key_vault_property "MyKeyVault" "enableSoftDelete" "true"
check_key_vault_property() {
    local kv_name=$1
    local property_name=$2 # e.g. enableSoftDelete, enablePurgeProtection
    local expected_value=$3
    local finding_status="Compliant"
    local finding_message="Key Vault $kv_name property '$property_name' is '$expected_value' as expected."

    local actual_value=$(az keyvault show --name "$kv_name" --resource-group "$RESOURCE_GROUP" --query "properties.$property_name" -o tsv 2>/dev/null)
     if [ $? -ne 0 ] || [ -z "$actual_value" ]; then # Check if command failed or value is empty
        finding_status="Error"
        finding_message="Key Vault $kv_name: Could not retrieve property '$property_name'. Ensure KV exists, RG ('$RESOURCE_GROUP') is correct, and permissions are adequate."
    elif [ "$actual_value" != "$expected_value" ]; then
        finding_status="Non-Compliant"
        finding_message="Key Vault $kv_name: Expected property '$property_name' to be '$expected_value', but found '$actual_value'."
    fi
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
}

# Check if all subnets have an NSG attached
# Expects RG to be set. If VNET_NAME is empty, will try to check all VNETs in RG.
check_subnet_nsg_attachment() {
    local vnet_name_filter=$1 # Optional: specific vnet name
    local expected_nsg_attached_str=$(echo "$2" | jq -r '.nsgAttached') # from expectedConfiguration: {"nsgAttached": true}
    local overall_status="Compliant"
    local findings_array=()

    local vnets_to_check
    if [ -n "$vnet_name_filter" ]; then
        vnets_to_check="$vnet_name_filter"
    else
        echo -e "${BLUE}[INFO]${NC} Listing VNETs in RG: $RESOURCE_GROUP"
        vnets_to_check=$(az network vnet list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv 2>/dev/null)
        if [ $? -ne 0 ] || [ -z "$vnets_to_check" ]; then
            echo "{\"status\": \"Error\", \"message\": \"Could not list VNETs in resource group '$RESOURCE_GROUP'.\"}"
            return
        fi
    fi

    for vnet_name in $vnets_to_check; do
        echo -e "${BLUE}[INFO]${NC} Checking subnets in VNet: $vnet_name (Resource Group: $RESOURCE_GROUP)"
        local subnets_json=$(az network vnet subnet list --resource-group "$RESOURCE_GROUP" --vnet-name "$vnet_name" --query "[].{name:name, nsg:networkSecurityGroup.id}" -o json 2>/dev/null)
        if [ $? -ne 0 ] || [ -z "$subnets_json" ]; then
            findings_array+=("{\"subnet\": \"$vnet_name/AllSubnets\", \"status\": \"Error\", \"message\": \"Could not list subnets for VNet '$vnet_name' or VNet has no subnets.\"}")
            overall_status="Error" # Or Non-Compliant if subnets are expected
            continue
        fi

        echo "$subnets_json" | jq -c '.[]' | while IFS= read -r subnet_obj_json; do
            local subnet_name=$(echo "$subnet_obj_json" | jq -r '.name')
            local nsg_id=$(echo "$subnet_obj_json" | jq -r '.nsg')
            local current_finding_status="Compliant"
            local current_message="Subnet $vnet_name/$subnet_name: NSG attachment is as expected."

            if [ "$expected_nsg_attached_str" == "true" ]; then
                if [ -z "$nsg_id" ] || [ "$nsg_id" == "null" ]; then
                    current_finding_status="Non-Compliant"
                    current_message="Subnet $vnet_name/$subnet_name: Expected an NSG to be attached, but none found."
                    overall_status="Non-Compliant"
                fi
            elif [ "$expected_nsg_attached_str" == "false" ]; then # Explicitly expect no NSG
                 if [ -n "$nsg_id" ] && [ "$nsg_id" != "null" ]; then
                    current_finding_status="Non-Compliant"
                    current_message="Subnet $vnet_name/$subnet_name: Expected no NSG to be attached, but found '$nsg_id'."
                    overall_status="Non-Compliant"
                fi
            fi
            findings_array+=("{\"subnet\": \"$vnet_name/$subnet_name\", \"status\": \"$current_finding_status\", \"message\": \"$current_message\"}")
        done
    done
    
    local all_findings_json=$(printf '%s\n' "${findings_array[@]}" | jq -s '.')
    echo "{\"status\": \"$overall_status\", \"message\": \"Subnet NSG attachment validation complete.\", \"details\": $all_findings_json}"
}

# Check NSG for default deny rule
# az network nsg show --name "$nsg_name" --resource-group "$RESOURCE_GROUP" --query "securityRules[?direction=='Inbound' && access=='Deny' && priority>=4000].name" -o tsv
check_nsg_default_deny_rule() {
    local nsg_name=$1
    # expected_config_json: e.g. {"defaultInboundRule": {"access": "Deny", "protocol": "*", "direction": "Inbound", "priorityRange": "4000-4096"}}
    local expected_config_json=$2
    local finding_status="Non-Compliant" # Assume non-compliant until proven otherwise
    local finding_message="NSG $nsg_name: No matching default deny rule found."

    local expected_direction=$(echo "$expected_config_json" | jq -r '.defaultInboundRule.direction // "Inbound"')
    local expected_access=$(echo "$expected_config_json" | jq -r '.defaultInboundRule.access // "Deny"')
    local expected_protocol=$(echo "$expected_config_json" | jq -r '.defaultInboundRule.protocol // "*"')
    # Priority range handling
    local min_priority=$(echo "$expected_config_json" | jq -r '.defaultInboundRule.priorityRange' | cut -d'-' -f1)
    local max_priority=$(echo "$expected_config_json" | jq -r '.defaultInboundRule.priorityRange' | cut -d'-' -f2)

    # Construct the JMESPath query dynamically based on expected config
    # Basic query parts
    local query_parts=()
    query_parts+=("direction=='$expected_direction'")
    query_parts+=("access=='$expected_access'")
    query_parts+=("protocol=='$expected_protocol'")
    # Add priority check: priority >= min_priority && priority <= max_priority
    query_parts+=("priority>=$min_priority")
    query_parts+=("priority<=$max_priority")

    # Join query parts with ' && '
    local jmespath_query="securityRules[?$(IFS=' && '; echo "${query_parts[*]}")]"
    
    # echo -e "${BLUE}[DEBUG]${NC} NSG Deny Rule JMESPath for $nsg_name: $jmespath_query"
    local matching_rules_json=$(az network nsg show --name "$nsg_name" --resource-group "$RESOURCE_GROUP" --query "$jmespath_query" -o json 2>/dev/null)

    if [ $? -ne 0 ]; then
        finding_status="Error"
        finding_message="NSG $nsg_name: Could not retrieve rules. Ensure NSG exists in RG '$RESOURCE_GROUP'."
    elif [ -n "$matching_rules_json" ] && [ "$(echo "$matching_rules_json" | jq 'length > 0')" == "true" ]; then
        local rule_names=$(echo "$matching_rules_json" | jq -r '.[].name')
        finding_status="Compliant"
        finding_message="NSG $nsg_name: Found matching default deny rule(s): $rule_names."
    fi
    
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
}

# Check NSG for overly permissive "Any" or "Internet" rules
check_nsg_no_any_allow_rules() {
    local nsg_name=$1
    # rule_criteria_json: e.g. {"access": "Allow", "sourceAddressPrefixes": ["Any", "Internet", "0.0.0.0/0", "::/0"], "destinationPortRange": ["22", "3389"]}
    local rule_criteria_json=$2
    # expected_result: e.g. "NotExists"
    local expected_result_from_control=$3

    local finding_status="Error" # Default to Error
    local finding_message="NSG $nsg_name: Could not verify rule criteria."

    local access_crit=$(echo "$rule_criteria_json" | jq -r '.access')
    # Source Prefixes is an array in JSON: ["Any", "Internet"]
    local source_prefixes_jq_array=$(echo "$rule_criteria_json" | jq -r '.sourceAddressPrefixes | map("\"" + . + "\"") | join(",")') # Creates "Any","Internet"
    # Dest Ports is an array in JSON: ["22", "3389"]
    local dest_ports_jq_array=$(echo "$rule_criteria_json" | jq -r '.destinationPortRange | map("\"" + . + "\"") | join(",")') # Creates "22","3389"

    # Construct JMESPath query
    # This query looks for rules that HAVE the problematic characteristics.
    
    local query="securityRules[?access=='$access_crit' && ("
    local prefix_conditions=()
    for prefix in $(echo "$rule_criteria_json" | jq -r '.sourceAddressPrefixes[]'); do
        prefix_conditions+=("sourceAddressPrefix=='$prefix'")
    done
    query+=$(IFS=' || '; echo "${prefix_conditions[*]}")
    query+=" || contains([${source_prefixes_jq_array}], sourceAddressPrefix))" # Check single sourceAddressPrefix against list

    if [ -n "$dest_ports_jq_array" ]; then
        query+=" && contains([${dest_ports_jq_array}], destinationPortRange)"
    fi
    query+="]"
    
    local permissive_rules_json=$(az network nsg show --name "$nsg_name" --resource-group "$RESOURCE_GROUP" --query "$query" -o json 2>/dev/null)

    if [ $? -ne 0 ]; then
        finding_message="NSG $nsg_name: Could not retrieve rules. Ensure NSG exists in RG '$RESOURCE_GROUP'."
    else
        if [ -n "$permissive_rules_json" ] && [ "$(echo "$permissive_rules_json" | jq 'length > 0')" == "true" ]; then
            local rule_names=$(echo "$permissive_rules_json" | jq -r '.[].name')
            if [ "$expected_result_from_control" == "NotExists" ]; then
                finding_status="Non-Compliant"
                finding_message="NSG $nsg_name: Found overly permissive rule(s) matching criteria: $rule_names."
            else
                finding_status="Compliant"
                finding_message="NSG $nsg_name: Permissive rule(s) found as expected (though unusual for 'NotExists' control): $rule_names."
            fi
        else
            if [ "$expected_result_from_control" == "NotExists" ]; then
                finding_status="Compliant"
                finding_message="NSG $nsg_name: No overly permissive rules matching criteria found."
            else
                finding_status="Non-Compliant"
                finding_message="NSG $nsg_name: Expected permissive rule(s) to exist, but none found."
            fi
        fi
    fi
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
}

# Check Key Vault Key Expiration
check_key_vault_key_expiration() {
    local kv_name=$1
    local key_name=$2
    local expected_config_json=$3

    local finding_status="Error"
    local finding_message="Key '$key_name' in Vault '$kv_name': Could not verify expiration."

    local key_details_json=$(az keyvault key show --vault-name "$kv_name" --name "$key_name" -o json 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$key_details_json" ]; then
        finding_message="Key '$key_name' in Vault '$kv_name': Could not retrieve key details."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local expected_key_types_json=$(echo "$expected_config_json" | jq -r '.keyTypes // []')
    local actual_key_type=$(echo "$key_details_json" | jq -r '.key.kty')
    if [ "$(echo "$expected_key_types_json" | jq '. | length')" -gt 0 ]; then
        if ! echo "$expected_key_types_json" | jq -e --arg akt "$actual_key_type" '.[] | select(. == $akt)' > /dev/null; then
            finding_status="Non-Compliant"
            finding_message="Key '$key_name' type '$actual_key_type' is not among expected types: $(echo "$expected_key_types_json" | jq -r '. | join(", ")')."
            echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
            return
        fi
    fi

    local expected_enabled=$(echo "$expected_config_json" | jq -r '.attributes.enabled // "true"')
    local actual_enabled=$(echo "$key_details_json" | jq -r '.attributes.enabled')

    if [ "$actual_enabled" != "$expected_enabled" ]; then
        finding_status="Non-Compliant"
        finding_message="Key '$key_name': Expected enabled status to be '$expected_enabled', but found '$actual_enabled'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local expect_expiration_set=$(echo "$expected_config_json" | jq -r '.attributes.expires // "true"')
    local actual_expiration_date=$(echo "$key_details_json" | jq -r '.attributes.expires')

    if [ "$expect_expiration_set" == "true" ]; then
        if [ -z "$actual_expiration_date" ] || [ "$actual_expiration_date" == "null" ]; then
            finding_status="Non-Compliant"
            finding_message="Key '$key_name': Expected to have an expiration date set, but it does not."
        else
            local max_validity_days=$(echo "$expected_config_json" | jq -r '.attributes.maxValidityDays // 365')
            local expiration_ts=$actual_expiration_date
            local now_ts=$(date +%s)
            
            if [ "$expiration_ts" -le "$now_ts" ]; then
                finding_status="Non-Compliant"
                finding_message="Key '$key_name': Is expired. Expiration date: $(date -d "@$expiration_ts" -u --iso-8601=seconds)."
            else
                local validity_seconds=$((expiration_ts - now_ts))
                local validity_days=$((validity_seconds / 86400))
                
                if [ "$validity_days" -gt "$max_validity_days" ]; then
                    finding_status="Non-Compliant"
                    finding_message="Key '$key_name': Expiration date $(date -d "@$expiration_ts" -u --iso-8601=seconds) exceeds maximum validity of $max_validity_days days. Current validity: $validity_days days."
                else
                    finding_status="Compliant"
                    finding_message="Key '$key_name': Expiration date $(date -d "@$expiration_ts" -u --iso-8601=seconds) is within $max_validity_days days (actual: $validity_days days)."
                fi
            fi
        fi
    else
        if [ -n "$actual_expiration_date" ] && [ "$actual_expiration_date" != "null" ]; then
            finding_status="Non-Compliant"
            finding_message="Key '$key_name': Expected to NOT have an expiration date set, but it does: $(date -d "@$actual_expiration_date" -u --iso-8601=seconds)."
        else
            finding_status="Compliant"
            finding_message="Key '$key_name': Correctly does not have an expiration date set."
        fi
    fi
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
}

# Check Storage Account Encryption (CMK)
check_storage_account_encryption() {
    local sa_name=$1
    local expected_config_json=$2
    local finding_status="Error"
    local finding_message="Storage Account '$sa_name': Could not verify encryption settings."

    local sa_details_json=$(az storage account show --name "$sa_name" --resource-group "$RESOURCE_GROUP" --query "encryption" -o json 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$sa_details_json" ]; then
        finding_message="Storage Account '$sa_name': Could not retrieve encryption details. Ensure SA exists in RG '$RESOURCE_GROUP'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local actual_key_source=$(echo "$sa_details_json" | jq -r '.keySource')
    local expected_key_source=$(echo "$expected_config_json" | jq -r '.encryption.keySource')

    if [ "$actual_key_source" != "$expected_key_source" ]; then
        finding_status="Non-Compliant"
        finding_message="Storage Account '$sa_name': Expected keySource to be '$expected_key_source', but found '$actual_key_source'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local expected_blob_key_type=$(echo "$expected_config_json" | jq -r '.encryption.services.blob.keyType')
    local actual_blob_enabled=$(echo "$sa_details_json" | jq -r '.services.blob.enabled // "false"')
    local actual_blob_key_type=$(echo "$sa_details_json" | jq -r '.services.blob.keyType')

    if [ "$actual_blob_enabled" != "true" ]; then
        finding_status="Non-Compliant"
        finding_message="Storage Account '$sa_name': Blob service encryption is not enabled."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi
    if [ "$actual_blob_key_type" != "$expected_blob_key_type" ]; then
        finding_status="Non-Compliant"
        finding_message="Storage Account '$sa_name': Blob service expected keyType '$expected_blob_key_type', found '$actual_blob_key_type'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local expected_file_key_type=$(echo "$expected_config_json" | jq -r '.encryption.services.file.keyType')
    local actual_file_enabled=$(echo "$sa_details_json" | jq -r '.services.file.enabled // "false"')
    local actual_file_key_type=$(echo "$sa_details_json" | jq -r '.services.file.keyType')

    if [ "$actual_file_enabled" != "true" ]; then
        finding_status="Non-Compliant"
        finding_message="Storage Account '$sa_name': File service encryption is not enabled."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi
    if [ "$actual_file_key_type" != "$expected_file_key_type" ]; then
        finding_status="Non-Compliant"
        finding_message="Storage Account '$sa_name': File service expected keyType '$expected_file_key_type', found '$actual_file_key_type'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi
    
    finding_status="Compliant"
    finding_message="Storage Account '$sa_name': Encryption settings are compliant with expected CMK configuration."
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
}

# Check RBAC assignments against a maximum count
check_rbac_assignments() {
    local scope=$1
    local role_definition_id_or_name=$2
    local max_assignments_str=$3
    local principal_types_to_count_jq_array=${4:-'["User", "Group", "ServicePrincipal"]'}

    local finding_status="Error"
    local finding_message="RBAC check for role '$role_definition_id_or_name' at scope '$scope': Could not verify assignments."

    local assignments_json=$(az role assignment list --role "$role_definition_id_or_name" --scope "$scope" --query "[]" -o json 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        finding_message="RBAC check for role '$role_definition_id_or_name' at scope '$scope': Failed to list role assignments. Check scope and permissions."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local relevant_assignments_count=$(echo "$assignments_json" | jq --argjson types "$principal_types_to_count_jq_array" '[.[] | select(.principalType as $pt | $types | index($pt))] | length')

    if [ -z "$relevant_assignments_count" ]; then
        relevant_assignments_count=0
    fi

    local max_assignments=$(parseInt "$max_assignments_str" "-1")
    if [ "$max_assignments" -lt 0 ]; then
         finding_message="RBAC check for role '$role_definition_id_or_name' at scope '$scope': Invalid max_assignments value '$max_assignments_str'."
         echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
         return
    fi

    if [ "$relevant_assignments_count" -gt "$max_assignments" ]; then
        finding_status="Non-Compliant"
        local principal_names=$(echo "$assignments_json" | jq --argjson types "$principal_types_to_count_jq_array" '[.[] | select(.principalType as $pt | $types | index($pt))] | .principalName' | jq -s 'join(", ")')
        finding_message="Role '$role_definition_id_or_name' at scope '$scope' has $relevant_assignments_count assignments (max allowed: $max_assignments). Principals: $principal_names."
    else
        finding_status="Compliant"
        finding_message="Role '$role_definition_id_or_name' at scope '$scope' has $relevant_assignments_count assignments, which is within the limit of $max_assignments."
    fi

    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\", \"count\": $relevant_assignments_count, \"limit\": $max_assignments}"
}

# Check custom roles for prohibited wildcard permissions
check_custom_role_permissions() {
    local scope=$1
    local prohibited_permissions_jq_array_str=$2

    local finding_status="Error"
    local finding_message="Custom role check for prohibited permissions at scope '$scope': Could not verify roles."
    local non_compliant_roles_details=()

    local custom_roles_json=$(az role definition list --custom-role-only true --scope "$scope" -o json 2>/dev/null)

    if [ $? -ne 0 ]; then
        finding_message="Custom role check at scope '$scope': Failed to list custom role definitions. Check scope and permissions."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    if [ -z "$custom_roles_json" ] || [ "$(echo "$custom_roles_json" | jq '. | length')" == "0" ]; then
        finding_status="Compliant"
        finding_message="No custom roles found at scope '$scope'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    finding_status="Compliant"
    finding_message="All custom roles at scope '$scope' are compliant."

    echo "$custom_roles_json" | jq -c '.[]' | while IFS= read -r role_definition_json; do
        local role_name=$(echo "$role_definition_json" | jq -r '.roleName')
        local role_id=$(echo "$role_definition_json" | jq -r '.name')
        local has_prohibited_permission=false

        echo "$role_definition_json" | jq -c '.permissions[].actions[] // empty' | while IFS= read -r action_permission_str_jq; do
            local action_permission_str=$(echo "$action_permission_str_jq" | jq -r '.')
            if echo "$prohibited_permissions_jq_array_str" | jq -e --arg act_perm "$action_permission_str" '.[] | select(. == $act_perm)' > /dev/null; then
                has_prohibited_permission=true
                break
            fi
        done

        if $has_prohibited_permission; then
             non_compliant_roles_details+=("{\"roleName\": \"$role_name\", \"roleId\": \"$role_id\", \"prohibitedActionFound\": \"$action_permission_str\"}")
             finding_status="Non-Compliant"
             continue
        fi

        echo "$role_definition_json" | jq -c '.permissions[].dataActions[] // empty' | while IFS= read -r data_action_permission_str_jq; do
            local data_action_permission_str=$(echo "$data_action_permission_str_jq" | jq -r '.')
             if echo "$prohibited_permissions_jq_array_str" | jq -e --arg data_act_perm "$data_action_permission_str" '.[] | select(. == $data_act_perm)' > /dev/null; then
                has_prohibited_permission=true
                break
            fi
        done

        if $has_prohibited_permission; then
             non_compliant_roles_details+=("{\"roleName\": \"$role_name\", \"roleId\": \"$role_id\", \"prohibitedDataActionFound\": \"$data_action_permission_str\"}")
             finding_status="Non-Compliant"
        fi
    done

    if [ "$finding_status" == "Non-Compliant" ]; then
        local details_json_array=$(printf '%s\n' "${non_compliant_roles_details[@]}" | jq -s '.')
        finding_message="Found custom roles with prohibited wildcard permissions at scope '$scope'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\", \"details\": $details_json_array}"
    else
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
    fi
}

# Check Diagnostic Settings for a resource
check_diagnostic_settings() {
    local resource_uri=$1
    local required_logs_jq_array_str=$2
    local required_metrics_jq_array_str=$3
    local min_retention_days_str=$4
    local diagnostic_setting_name_filter_str=$5

    local finding_status="Error"
    local finding_message="Diagnostic settings check for '$resource_uri': Could not verify settings."
    local compliant_setting_found=false
    local checked_settings_details=()

    local diagnostic_settings_list_json=$(az monitor diagnostic-settings list --resource "$resource_uri" -o json 2>/dev/null)

    if [ $? -ne 0 ]; then
        finding_message="Diagnostic settings check for '$resource_uri': Failed to list diagnostic settings. URI correct? Permissions?"
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    if [ -z "$diagnostic_settings_list_json" ] || [ "$(echo "$diagnostic_settings_list_json" | jq '.value | length')" == "0" ]; then
        finding_status="Non-Compliant"
        finding_message="No diagnostic settings found for resource '$resource_uri'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi
    
    local min_retention_days=$(parseInt "$min_retention_days_str" "0")

    echo "$diagnostic_settings_list_json" | jq -c '.value[]' | while IFS= read -r setting_json; do
        local setting_name=$(echo "$setting_json" | jq -r '.name')
        local current_setting_findings=()
        local current_setting_is_compliant_candidate=true

        if [ -n "$diagnostic_setting_name_filter_str" ] && [ "$setting_name" != "$diagnostic_setting_name_filter_str" ]; then
            checked_settings_details+=("{\"settingName\": \"$setting_name\", \"status\": \"Skipped\", \"message\": \"Not the target setting.\"}")
            continue
        fi

        echo "$required_logs_jq_array_str" | jq -r '.[]' | while IFS= read -r req_log_category; do
            local log_enabled=$(echo "$setting_json" | jq -r --arg cat "$req_log_category" '.logs[] | select(.category == $cat or .categoryGroup == $cat) | .enabled // "false"')
            if [ "$log_enabled" != "true" ]; then
                current_setting_is_compliant_candidate=false
                current_setting_findings+=("Log category '$req_log_category' not enabled or not found.")
            fi
        done

        local required_metrics_count=$(echo "$required_metrics_jq_array_str" | jq '. | length')
        if [ "$required_metrics_count" -gt 0 ]; then
             echo "$required_metrics_jq_array_str" | jq -r '.[]' | while IFS= read -r req_metric_category; do
                local metric_enabled=$(echo "$setting_json" | jq -r --arg cat "$req_metric_category" '.metrics[] | select(.category == $cat or .categoryGroup == $cat) | .enabled // "false"')
                if [ "$metric_enabled" != "true" ]; {
                    current_setting_is_compliant_candidate=false
                    current_setting_findings+=("Metric category '$req_metric_category' not enabled or not found.")
                }
                fi
            done
        fi
        
        if [ "$min_retention_days" -gt 0 ]; then
            local retention_enabled=$(echo "$setting_json" | jq -r '.retentionPolicy.enabled // "false"')
            local retention_days=$(echo "$setting_json" | jq -r '.retentionPolicy.days // "0"')
            if [ "$retention_enabled" != "true" ]; then
                current_setting_is_compliant_candidate=false
                current_setting_findings+=("Retention policy not enabled.")
            elif [ "$(parseInt "$retention_days" "0")" -lt "$min_retention_days" ]; then
                current_setting_is_compliant_candidate=false
                current_setting_findings+=("Retention policy days '$retention_days' is less than minimum '$min_retention_days'.")
            fi
        fi

        if $current_setting_is_compliant_candidate; then
            compliant_setting_found=true
            checked_settings_details+=("{\"settingName\": \"$setting_name\", \"status\": \"Compliant\", \"message\": \"This setting meets all criteria.\"}")
            if [ -n "$diagnostic_setting_name_filter_str" ]; then break; fi
        else
            local finding_msg_combined=$(printf '%s; ' "${current_setting_findings[@]}")
            checked_settings_details+=("{\"settingName\": \"$setting_name\", \"status\": \"NonCompliant\", \"message\": \"$finding_msg_combined\"}")
        fi
    done < <(echo "$diagnostic_settings_list_json" | jq -c '.value[]')

    local details_json_array=$(printf '%s\n' "${checked_settings_details[@]}" | jq -s '.')
    if $compliant_setting_found; then
        finding_status="Compliant"
        finding_message="At least one diagnostic setting for '$resource_uri' is compliant."
    else
        finding_status="Non-Compliant"
        if [ -n "$diagnostic_setting_name_filter_str" ]; then
             finding_message="Diagnostic setting '$diagnostic_setting_name_filter_str' for '$resource_uri' is not compliant or not found."
        else
             finding_message="No diagnostic setting for '$resource_uri' meets all criteria."
        fi
    fi
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\", \"details\": $details_json_array}"
}

# Check Log Analytics Workspace Settings
check_la_workspace_settings() {
    local ws_name=$1
    local ws_rg=$2
    # expected_config_json: e.g. {"retentionInDays": ">=365"}
    local expected_config_json=$3
    local finding_status="Error"
    local finding_message="Log Analytics Workspace '$ws_name' in RG '$ws_rg': Could not verify settings."

    local ws_details_json=$(az monitor log-analytics workspace show --name "$ws_name" --resource-group "$ws_rg" -o json 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$ws_details_json" ]; then
        finding_message="Log Analytics Workspace '$ws_name' in RG '$ws_rg': Could not retrieve details."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    # Check retentionInDays
    local expected_retention_op_val=$(echo "$expected_config_json" | jq -r '.retentionInDays') # e.g. ">=365"
    local actual_retention=$(echo "$ws_details_json" | jq -r '.retentionInDays')

    if [[ "$expected_retention_op_val" == ">="* ]]; then
        local expected_min_retention=$(echo "$expected_retention_op_val" | sed 's/>=//')
        if [ "$(parseInt "$actual_retention" "0")" -lt "$(parseInt "$expected_min_retention" "0")" ]; then
            finding_status="Non-Compliant"
            finding_message="Workspace '$ws_name': Retention $actual_retention days is less than minimum $expected_min_retention days."
        else
            finding_status="Compliant"
            finding_message="Workspace '$ws_name': Retention $actual_retention days meets minimum $expected_min_retention days."
        fi
    elif [ "$actual_retention" != "$(echo "$expected_retention_op_val" | sed 's/==//')" ]; then # Allow == or just value
        finding_status="Non-Compliant"
        finding_message="Workspace '$ws_name': Expected retention to be '$expected_retention_op_val', found '$actual_retention'."
    else
        finding_status="Compliant"
        finding_message="Workspace '$ws_name': Retention is '$actual_retention' as expected."
    fi
    
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\", \"actualRetention\": $actual_retention}"
}

# Check if Sentinel (SecurityInsights solution) is enabled on a Log Analytics Workspace
check_sentinel_on_workspace() {
    local ws_name=$1
    local ws_rg=$2
    # expected_config_json: e.g. {"enabled": true}
    local expected_config_json=$3
    local finding_status="Error"
    local finding_message="Sentinel check for Workspace '$ws_name' in RG '$ws_rg': Could not verify."

    local expected_enabled_bool=$(echo "$expected_config_json" | jq -r '.enabled // "true"')

    # Query for the SecurityInsights solution
    local sentinel_solution_json=$(az monitor log-analytics solution list --workspace-name "$ws_name" --resource-group "$ws_rg" --query "[?plan.product=='OMSGallery/SecurityInsights']" -o json 2>/dev/null)

    if [ $? -ne 0 ]; then
        finding_message="Sentinel check for Workspace '$ws_name' in RG '$ws_rg': Failed to query solutions."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local sentinel_is_present=false
    if [ -n "$sentinel_solution_json" ] && [ "$(echo "$sentinel_solution_json" | jq '. | length')" -gt 0 ]; then
        sentinel_is_present=true
    fi

    if [ "$expected_enabled_bool" == "true" ]; then
        if $sentinel_is_present; then
            finding_status="Compliant"
            finding_message="Sentinel (SecurityInsights solution) is enabled on Workspace '$ws_name'."
        else
            finding_status="Non-Compliant"
            finding_message="Sentinel (SecurityInsights solution) is NOT enabled on Workspace '$ws_name'."
        fi
    else # expected_enabled_bool is false
        if ! $sentinel_is_present; then
            finding_status="Compliant"
            finding_message="Sentinel (SecurityInsights solution) is correctly NOT enabled on Workspace '$ws_name'."
        else
            finding_status="Non-Compliant"
            finding_message="Sentinel (SecurityInsights solution) IS ENABLED on Workspace '$ws_name', but was expected to be disabled."
        fi
    fi
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\", \"sentinelPresent\": $sentinel_is_present}"
}

# Check Log Analytics Workspace Settings
check_la_workspace_settings() {
    local ws_name=$1
    local ws_rg=$2
    # expected_config_json: e.g. {"retentionInDays": ">=365"}
    local expected_config_json=$3
    local finding_status="Error"
    local finding_message="Log Analytics Workspace '$ws_name' in RG '$ws_rg': Could not verify settings."

    local ws_details_json=$(az monitor log-analytics workspace show --name "$ws_name" --resource-group "$ws_rg" -o json 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$ws_details_json" ]; then
        finding_message="Log Analytics Workspace '$ws_name' in RG '$ws_rg': Could not retrieve details."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    # Check retentionInDays
    local expected_retention_op_val=$(echo "$expected_config_json" | jq -r '.retentionInDays') # e.g. ">=365"
    local actual_retention=$(echo "$ws_details_json" | jq -r '.retentionInDays')

    if [[ "$expected_retention_op_val" == ">="* ]]; then
        local expected_min_retention=$(echo "$expected_retention_op_val" | sed 's/>=//')
        if [ "$(parseInt "$actual_retention" "0")" -lt "$(parseInt "$expected_min_retention" "0")" ]; then
            finding_status="Non-Compliant"
            finding_message="Workspace '$ws_name': Retention $actual_retention days is less than minimum $expected_min_retention days."
        else
            finding_status="Compliant"
            finding_message="Workspace '$ws_name': Retention $actual_retention days meets minimum $expected_min_retention days."
        fi
    elif [ "$actual_retention" != "$(echo "$expected_retention_op_val" | sed 's/==//')" ]; then # Allow == or just value
        finding_status="Non-Compliant"
        finding_message="Workspace '$ws_name': Expected retention to be '$expected_retention_op_val', found '$actual_retention'."
    else
        finding_status="Compliant"
        finding_message="Workspace '$ws_name': Retention is '$actual_retention' as expected."
    fi
    
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\", \"actualRetention\": $actual_retention}"
}

# Check if Sentinel (SecurityInsights solution) is enabled on a Log Analytics Workspace
check_sentinel_on_workspace() {
    local ws_name=$1
    local ws_rg=$2
    # expected_config_json: e.g. {"enabled": true}
    local expected_config_json=$3
    local finding_status="Error"
    local finding_message="Sentinel check for Workspace '$ws_name' in RG '$ws_rg': Could not verify."

    local expected_enabled_bool=$(echo "$expected_config_json" | jq -r '.enabled // "true"')

    # Query for the SecurityInsights solution
    local sentinel_solution_json=$(az monitor log-analytics solution list --workspace-name "$ws_name" --resource-group "$ws_rg" --query "[?plan.product=='OMSGallery/SecurityInsights']" -o json 2>/dev/null)

    if [ $? -ne 0 ]; then
        finding_message="Sentinel check for Workspace '$ws_name' in RG '$ws_rg': Failed to query solutions."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local sentinel_is_present=false
    if [ -n "$sentinel_solution_json" ] && [ "$(echo "$sentinel_solution_json" | jq '. | length')" -gt 0 ]; then
        sentinel_is_present=true
    fi

    if [ "$expected_enabled_bool" == "true" ]; then
        if $sentinel_is_present; then
            finding_status="Compliant"
            finding_message="Sentinel (SecurityInsights solution) is enabled on Workspace '$ws_name'."
        else
            finding_status="Non-Compliant"
            finding_message="Sentinel (SecurityInsights solution) is NOT enabled on Workspace '$ws_name'."
        fi
    else # expected_enabled_bool is false
        if ! $sentinel_is_present; then
            finding_status="Compliant"
            finding_message="Sentinel (SecurityInsights solution) is correctly NOT enabled on Workspace '$ws_name'."
        else
            finding_status="Non-Compliant"
            finding_message="Sentinel (SecurityInsights solution) IS ENABLED on Workspace '$ws_name', but was expected to be disabled."
        fi
    fi
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\", \"sentinelPresent\": $sentinel_is_present}"
}

# Check Subscription Log Profile settings
check_subscription_log_profile() {
    # expected_config_json: e.g. {"storageAccountId": "NotNull", "retentionPolicy": {"enabled": true, "days": ">=365"}, "categories": ["Administrative", "Security"]}
    local expected_config_json=$1
    local subscription_scope="/subscriptions/$SUBSCRIPTION_ID" # Assuming current subscription context

    local finding_status="Error"
    local finding_message="Subscription Log Profile check for '$subscription_scope': Could not verify settings."
    local log_profiles_json=$(az monitor log-profiles list --query "value" -o json 2>/dev/null) # az monitor log-profiles list is subscription wide already

    if [ $? -ne 0 ]; then
        finding_message="Subscription Log Profile check for '$subscription_scope': Failed to list log profiles."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    if [ -z "$log_profiles_json" ] || [ "$(echo "$log_profiles_json" | jq '. | length')" == "0" ]; then
        finding_status="Non-Compliant"
        finding_message="No log profiles found for subscription '$subscription_scope'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local compliant_profile_found=false
    local checked_profiles_details=()

    echo "$log_profiles_json" | jq -c '.[]' | while IFS= read -r profile_json; do
        local profile_name=$(echo "$profile_json" | jq -r '.name')
        local current_profile_findings=()
        local current_profile_is_compliant_candidate=true

        # Check storageAccountId
        local expected_storage_not_null=$(echo "$expected_config_json" | jq -r '.storageAccountId // "NotNull"') # Default to NotNull
        local actual_storage_id=$(echo "$profile_json" | jq -r '.storageAccountId')
        if [ "$expected_storage_not_null" == "NotNull" ] && ([ -z "$actual_storage_id" ] || [ "$actual_storage_id" == "null" ]); then
            current_profile_is_compliant_candidate=false
            current_profile_findings+=("StorageAccountID is null or not set.")
        fi
        
        # Check retention policy
        local expected_ret_enabled=$(echo "$expected_config_json" | jq -r '.retentionPolicy.enabled // "true"')
        local expected_ret_days_op_val=$(echo "$expected_config_json" | jq -r '.retentionPolicy.days // ">=365"')

        local actual_ret_enabled=$(echo "$profile_json" | jq -r '.retentionPolicy.enabled // "false"')
        local actual_ret_days=$(echo "$profile_json" | jq -r '.retentionPolicy.days // "0"')

        if [ "$expected_ret_enabled" == "true" ] && [ "$actual_ret_enabled" != "true" ]; then
            current_profile_is_compliant_candidate=false
            current_profile_findings+=("Retention policy not enabled.")
        elif [ "$expected_ret_enabled" == "true" ]; then # Only check days if retention is expected and enabled
            if [[ "$expected_ret_days_op_val" == ">="* ]]; then
                local expected_min_days=$(echo "$expected_ret_days_op_val" | sed 's/>=//')
                if [ "$(parseInt "$actual_ret_days" "0")" -lt "$(parseInt "$expected_min_days" "0")" ]; then
                    current_profile_is_compliant_candidate=false
                    current_profile_findings+=("Retention $actual_ret_days days is less than minimum $expected_min_days days.")
                fi
            elif [ "$actual_ret_days" != "$(echo "$expected_ret_days_op_val" | sed 's/==//')" ]; then
                 current_profile_is_compliant_candidate=false
                 current_profile_findings+=("Expected retention days '$expected_ret_days_op_val', found '$actual_ret_days'.")
            fi
        fi

        # Check categories
        local expected_categories_jq_array=$(echo "$expected_config_json" | jq -c '.categories // []')
        local actual_categories_jq_array=$(echo "$profile_json" | jq -c '.categories // []')

        echo "$expected_categories_jq_array" | jq -r '.[]' | while IFS= read -r req_category; do
            if ! echo "$actual_categories_jq_array" | jq -e --arg cat "$req_category" '.[] | select(. == $cat)' > /dev/null; then
                current_profile_is_compliant_candidate=false
                current_profile_findings+=("Required category '$req_category' not found in profile.")
            fi
        done


        if $current_profile_is_compliant_candidate; then
            compliant_profile_found=true
            checked_profiles_details+=("{\"profileName\": \"$profile_name\", \"status\": \"Compliant\", \"message\": \"This log profile meets all criteria.\"}")
            break
        else
            local finding_msg_combined=$(printf '%s; ' "${current_profile_findings[@]}")
            checked_profiles_details+=("{\"profileName\": \"$profile_name\", \"status\": \"NonCompliant\", \"message\": \"$finding_msg_combined\"}")
        fi
    done < <(echo "$log_profiles_json" | jq -c '.[]')

    local details_json_array=$(printf '%s\n' "${checked_profiles_details[@]}" | jq -s '.')
    if $compliant_profile_found; then
        finding_status="Compliant"
        finding_message="At least one subscription log profile is compliant for '$subscription_scope'."
    else
        finding_status="Non-Compliant"
        finding_message="No subscription log profile meets all criteria for '$subscription_scope'."
    fi
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\", \"details\": $details_json_array}"
}

# Check NSG Flow Log settings
check_nsg_flow_logs() {
    local nsg_id=$1
    local nsg_name=$2
    local expected_config_json=$3

    local finding_status="Error"
    local finding_message="NSG '$nsg_name' Flow Logs: Could not verify settings."

    local nsg_location=$(az network nsg show --ids "$nsg_id" --query "location" -o tsv 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$nsg_location" ]; then
        finding_message="NSG '$nsg_name' Flow Logs: Could not retrieve NSG location for ID '$nsg_id'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local watcher_info=$(az network watcher list --query "[?location=='$nsg_location'].{Name:name, RG:resourceGroup}" -o tsv 2>/dev/null | head -n 1)
    if [ -z "$watcher_info" ]; then
        finding_status="Skipped"
        finding_message="NSG '$nsg_name' Flow Logs: Could not find Network Watcher for region '$nsg_location'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi
    local watcher_name=$(echo "$watcher_info" | cut -f1)
    local watcher_rg=$(echo "$watcher_info" | cut -f2)

    if [ -z "$watcher_name" ] || [ -z "$watcher_rg" ]; then
        finding_status="Skipped"
        finding_message="NSG '$nsg_name' Flow Logs: Could not parse Network Watcher name/RG for region '$nsg_location'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi
    
    local flow_log_settings_json=$(az network watcher flow-log list --location "$nsg_location" --resource-group "$watcher_rg" --query "value[?targetResourceId=='$nsg_id']" -o json 2>/dev/null)

    if [ $? -ne 0 ]; then
        finding_message="NSG '$nsg_name' Flow Logs: Error listing flow logs via Watcher '$watcher_name' (RG: '$watcher_rg')."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    if [ -z "$flow_log_settings_json" ] || [ "$(echo "$flow_log_settings_json" | jq '. | length')" == "0" ]; then
        if [ "$(echo "$expected_config_json" | jq -r '.enabled // "false"')" == "true" ]; then
            finding_status="Non-Compliant"
            finding_message="NSG '$nsg_name' Flow Logs: Expected to be enabled, but no flow log configuration found."
        else
            finding_status="Compliant"
            finding_message="NSG '$nsg_name' Flow Logs: Correctly not configured (as expected to be disabled)."
        fi
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    local flow_log_setting=$(echo "$flow_log_settings_json" | jq '.[0]')
    local actual_enabled=$(echo "$flow_log_setting" | jq -r '.enabled // "false"')
    local expected_enabled=$(echo "$expected_config_json" | jq -r '.enabled // "true"')

    if [ "$actual_enabled" != "$expected_enabled" ]; then
        finding_status="Non-Compliant"
        finding_message="NSG '$nsg_name' Flow Logs: Expected enabled status '$expected_enabled', found '$actual_enabled'."
        echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
        return
    fi

    if [ "$expected_enabled" == "true" ]; then
        local expected_ret_enabled=$(echo "$expected_config_json" | jq -r '.retentionPolicy.enabled // "true"')
        local expected_ret_days_op_val=$(echo "$expected_config_json" | jq -r '.retentionPolicy.days // ">=0"')

        local actual_ret_enabled=$(echo "$flow_log_setting" | jq -r '.retentionPolicy.enabled // "false"')
        local actual_ret_days=$(echo "$flow_log_setting" | jq -r '.retentionPolicy.days // "0"')

        if [ "$expected_ret_enabled" == "true" ] && [ "$actual_ret_enabled" != "true" ]; then
            finding_status="Non-Compliant"
            finding_message="NSG '$nsg_name' Flow Logs: Retention policy expected to be enabled, but it's not."
        elif [ "$expected_ret_enabled" == "true" ]; then
            if [[ "$expected_ret_days_op_val" == ">="* ]]; then
                local expected_min_days=$(echo "$expected_ret_days_op_val" | sed 's/>=//')
                if [ "$(parseInt "$actual_ret_days" "0")" -lt "$(parseInt "$expected_min_days" "0")" ]; then
                    finding_status="Non-Compliant"
                    finding_message="NSG '$nsg_name' Flow Logs: Retention $actual_ret_days days is less than minimum $expected_min_days days."
                else
                    finding_status="Compliant"
                    finding_message="NSG '$nsg_name' Flow Logs: Enabled and retention policy meets criteria (Actual: $actual_ret_days days)."
                fi
            elif [ "$actual_ret_days" != "$(echo "$expected_ret_days_op_val" | sed 's/==//')" ]; then
                 finding_status="Non-Compliant"
                 finding_message="NSG '$nsg_name' Flow Logs: Expected retention days '$expected_ret_days_op_val', found '$actual_ret_days'."
            else
                 finding_status="Compliant"
                 finding_message="NSG '$nsg_name' Flow Logs: Enabled and retention policy meets criteria (Actual: $actual_ret_days days)."
            fi
        else
            finding_status="Compliant"
            finding_message="NSG '$nsg_name' Flow Logs: Retention policy correctly not enabled as expected."
        fi
    else
        finding_status="Compliant"
        finding_message="NSG '$nsg_name' Flow Logs: Correctly disabled as expected."
    fi
    
    echo "{\"status\": \"$finding_status\", \"message\": \"$finding_message\"}"
}


# Generic function to execute a control check
# Takes the control object (as JSON string) as input
execute_control_check() {
    local control_json="$1" # Control object as a JSON string
    local control_id=$(echo "$control_json" | jq -r '.id')
    local control_type=$(echo "$control_json" | jq -r '.controlType')
    local control_desc=$(echo "$control_json" | jq -r '.description')
    local target_scope=$(echo "$control_json" | jq -r '.targetScope') # AllKeyVaults, AllSubnets, SpecificResource, etc.
    local expected_config_json=$(echo "$control_json" | jq '.expectedConfiguration') # Keep as JSON object
    local rule_criteria_json=$(echo "$control_json" | jq '.ruleCriteria') # For checks like NET_NSG_NO_ANY_ALLOW
    local expected_result_value=$(echo "$control_json" | jq -r '.expectedResult') # For checks where we expect non-existence

    echo -e "${BLUE}[INFO]${NC} Executing Check ID: $control_id - Type: $control_type"
    echo -e "${BLUE}[INFO]${NC} Description: $control_desc"

    local check_result_json
    # Default to Error status, specific checks should override
    # check_result_json="{\"status\": \"Error\", \"message\": \"Control type '$control_type' not implemented or invalid target scope for $control_id.\"}"


    # Determine Resource Group for the check.
    # This logic might need to be enhanced based on control-specific needs or if a control can target resources outside $RESOURCE_GROUP
    local current_resource_group="$RESOURCE_GROUP" # Use the global one by default.
     # TODO: Add logic if control can specify its own RG or subscription.

    case "$control_type" in
        "KeyVaultProperties")
            local kv_name_to_check # Determine KV name
            # Simplified: Assumes targetScope is a specific Key Vault name or uses the global KEY_VAULT_NAME
            # For "AllKeyVaults", this would need a loop.
            if [[ "$target_scope" == "SpecificResource:"* ]]; then
                 kv_name_to_check=$(echo "$target_scope" | cut -d':' -f2)
            elif [ -n "$KEY_VAULT_NAME" ]; then # Fallback to global if set
                 kv_name_to_check="$KEY_VAULT_NAME"
            else
                 check_result_json="{\"status\": \"Skipped\", \"message\": \"Control $control_id (KeyVaultProperties): No specific Key Vault name in targetScope ('$target_scope') and no global KEY_VAULT_NAME set.\"}"
                 echo "$check_result_json" | jq --arg id "$control_id" --arg desc "$control_desc" --arg cat "$(echo "$control_json" | jq -r '.category')" '. | .controlId = $id | .description = $desc | .category = $cat'
                 return
            fi

            if [ -z "$kv_name_to_check" ]; then
                 check_result_json="{\"status\": \"Skipped\", \"message\": \"Control $control_id: Key Vault name could not be determined for scope '$target_scope'.\"}"
            elif [ "$control_id" == "ENC_KV_SKU_PREMIUM" ]; then
                local expected_sku=$(echo "$expected_config_json" | jq -r '.sku')
                check_result_json=$(check_key_vault_sku "$kv_name_to_check" "$expected_sku")
            elif [ "$control_id" == "ENC_KV_SOFT_DELETE" ]; then
                local expected_soft_delete=$(echo "$expected_config_json" | jq -r '.enableSoftDelete')
                check_result_json=$(check_key_vault_property "$kv_name_to_check" "enableSoftDelete" "$expected_soft_delete")
            elif [ "$control_id" == "ENC_KV_PURGE_PROTECTION" ]; then
                local expected_purge_protection=$(echo "$expected_config_json" | jq -r '.enablePurgeProtection')
                check_result_json=$(check_key_vault_property "$kv_name_to_check" "enablePurgeProtection" "$expected_purge_protection")
            else
                check_result_json="{\"status\": \"Skipped\", \"message\": \"Control ID $control_id of type KeyVaultProperties not specifically handled.\"}"
            fi
            ;;
        "CustomRoleCheck")
            if [ "$control_id" == "IAM_NO_WILDCARD_CUSTOM_ROLES" ]; then
                local scope_to_check_custom_roles # Determine scope from target_scope or default
                if [[ "$target_scope" == "Subscription" ]]; then
                    scope_to_check_custom_roles="/subscriptions/$SUBSCRIPTION_ID"
                # Add other scope options like ManagementGroup if needed
                elif [ -n "$target_scope" ] && [[ "$target_scope" == /* ]]; then # Assume it's a full path
                    scope_to_check_custom_roles="$target_scope"
                else
                    scope_to_check_custom_roles="/subscriptions/$SUBSCRIPTION_ID" # Default
                    echo -e "${YELLOW}[WARN]${NC} targetScope for $control_id is '$target_scope', defaulting to subscription scope for custom role check."
                fi

                local prohibited_perms_jq_arr_str=$(echo "$control_json" | jq -r '.prohibitedPermissions // "[]"' | jq -c '.')
                check_result_json=$(check_custom_role_permissions "$scope_to_check_custom_roles" "$prohibited_perms_jq_arr_str")
            else
                check_result_json="{\"status\": \"Skipped\", \"message\": \"Control ID '$control_id' of type '$control_type' not specifically handled.\"}"
            fi
            ;;
        "ActivityLogAlerts") # This is for LOG_ACTIVITY_LOG_RETENTION
            if [ "$control_id" == "LOG_ACTIVITY_LOG_RETENTION" ]; then
                if [[ "$target_scope" == "Subscription" ]]; then
                    check_result_json=$(check_subscription_log_profile "$expected_config_json")
                else
                    check_result_json="{\"status\": \"Skipped\", \"message\": \"LOG_ACTIVITY_LOG_RETENTION control only supports targetScope 'Subscription'.\"}"
                fi
            else
                check_result_json="{\"status\": \"Skipped\", \"message\": \"Control ID '$control_id' of type '$control_type' not specifically handled.\"}"
            fi
            ;;
        "NSGFlowLogs")
            if [ "$control_id" == "LOG_NSG_FLOWLOGS" ]; then
                if [[ "$target_scope" == "AllNSGs" ]]; then
                    local nsgs_json=$(az network nsg list --resource-group "$current_resource_group" --query "[].{name:name, id:id}" -o json 2>/dev/null)
                    if [ $? -ne 0 ] || [ -z "$nsgs_json" ] || [ "$(echo "$nsgs_json" | jq '. | length')" == "0" ]; then
                        check_result_json="{\"status\": \"Skipped\", \"message\": \"No NSGs found in RG '$current_resource_group' for $control_id.\"}"
                    else
                        local all_nsg_flowlog_findings=()
                        local overall_nsg_flowlog_status="Compliant"
                        echo "$nsgs_json" | jq -c '.[]' | while IFS= read -r nsg_obj_json; do
                            local nsg_name_iter=$(echo "$nsg_obj_json" | jq -r '.name')
                            local nsg_id_iter=$(echo "$nsg_obj_json" | jq -r '.id')
                            echo -e "${BLUE}[INFO]${NC} Checking NSG Flow Logs for '$nsg_name_iter' (ID: $nsg_id_iter) for $control_id..."
                            local flowlog_check_result_json=$(check_nsg_flow_logs "$nsg_id_iter" "$nsg_name_iter" "$expected_config_json")
                            all_nsg_flowlog_findings+=("$(echo "$flowlog_check_result_json" | jq --arg nsgid "$nsg_id_iter" '. + {resourceId: $nsgid}')")
                            local current_flowlog_check_status=$(echo "$flowlog_check_result_json" | jq -r '.status')
                            if [ "$current_flowlog_check_status" == "Error" ]; then overall_nsg_flowlog_status="Error"; break; fi
                            if [ "$current_flowlog_check_status" == "Non-Compliant" ] && [ "$overall_nsg_flowlog_status" != "Error" ]; then overall_nsg_flowlog_status="Non-Compliant"; fi
                        done < <(echo "$nsgs_json" | jq -c '.[]')
                        local findings_json_array=$(printf '%s\n' "${all_nsg_flowlog_findings[@]}" | jq -s '.')
                        check_result_json="{\"status\": \"$overall_nsg_flowlog_status\", \"message\": \"NSG Flow Log check for all NSGs in RG '$current_resource_group' complete.\", \"details\": $findings_json_array}"
                    fi
                elif [[ "$target_scope" == "SpecificResource:"* ]]; then
                    local nsg_name_to_check=$(echo "$target_scope" | cut -d':' -f2)
                    local nsg_id_spec=$(az network nsg show --name "$nsg_name_to_check" --resource-group "$current_resource_group" --query "id" -o tsv 2>/dev/null)
                    if [ $? -ne 0 ] || [ -z "$nsg_id_spec" ]; then
                         check_result_json="{\"status\": \"Error\", \"message\": \"Could not get ID for NSG '$nsg_name_to_check' in RG '$current_resource_group'.\"}"
                    else
                        check_result_json=$(check_nsg_flow_logs "$nsg_id_spec" "$nsg_name_to_check" "$expected_config_json")
                    fi
                else
                    check_result_json="{\"status\": \"Skipped\", \"message\": \"Unsupported targetScope '$target_scope' for $control_id ($control_type).\"}"
                fi
            else
                check_result_json="{\"status\": \"Skipped\", \"message\": \"Control ID '$control_id' of type '$control_type' not specifically handled.\"}"
            fi
            ;;
        "LogAnalyticsWorkspace")
            if [ "$control_id" == "LOG_LA_WORKSPACE_RETENTION" ]; then
                # targetScope could be "DefaultWorkspace" or "SpecificResource:WorkspaceName/WorkspaceRG"
                local la_ws_name
                local la_ws_rg="$current_resource_group" # Default to current RG
                if [[ "$target_scope" == "DefaultWorkspace" ]]; then
                    la_ws_name="$LOG_ANALYTICS_WORKSPACE" # Global variable
                    # Attempt to get RG for default workspace if not current_resource_group
                    if [ -n "$la_ws_name" ] && ! az monitor log-analytics workspace show --name "$la_ws_name" --resource-group "$la_ws_rg" &>/dev/null; then
                        local detected_rg=$(az resource list --name "$la_ws_name" --resource-type "Microsoft.OperationalInsights/workspaces" --query "[0].resourceGroup" -o tsv 2>/dev/null)
                        if [ -n "$detected_rg" ]; then la_ws_rg="$detected_rg"; else
                             check_result_json="{\"status\": \"Error\", \"message\": \"Default Log Analytics Workspace '$la_ws_name' not found in default RG '$current_resource_group' and could not auto-detect its RG.\"}"
                             echo "$check_result_json" | jq --arg id "$control_id" --arg desc "$control_desc" --arg cat "$(echo "$control_json" | jq -r '.category')" '. | .controlId = $id | .description = $desc | .category = $cat'
                             return
                        fi
                    fi
                elif [[ "$target_scope" == "SpecificResource:"* ]]; then
                    local path_part=$(echo "$target_scope" | cut -d':' -f2)
                    if [[ "$path_part" == */* ]]; then # Format: WorkspaceName/WorkspaceRG
                        la_ws_name=$(dirname "$path_part")
                        la_ws_rg=$(basename "$path_part")
                    else # Format: WorkspaceName (assume current RG)
                        la_ws_name="$path_part"
                    fi
                else
                     check_result_json="{\"status\": \"Skipped\", \"message\": \"Unsupported targetScope '$target_scope' for $control_id ($control_type). Provide DefaultWorkspace or SpecificResource:WsName[/WsRG].\"}"
                     echo "$check_result_json" | jq --arg id "$control_id" --arg desc "$control_desc" --arg cat "$(echo "$control_json" | jq -r '.category')" '. | .controlId = $id | .description = $desc | .category = $cat'
                     return
                fi

                if [ -z "$la_ws_name" ]; then
                    check_result_json="{\"status\": \"Skipped\", \"message\": \"Log Analytics Workspace name not determined for $control_id. Global var LOG_ANALYTICS_WORKSPACE may be empty.\"}"
                else
                    check_result_json=$(check_la_workspace_settings "$la_ws_name" "$la_ws_rg" "$expected_config_json")
                fi
            else
                check_result_json="{\"status\": \"Skipped\", \"message\": \"Control ID '$control_id' of type '$control_type' not specifically handled.\"}"
            fi
            ;;
        "SentinelCheck")
            if [ "$control_id" == "LOG_SENTINEL_ENABLED" ]; then
                 # Similar logic to LogAnalyticsWorkspace for targetScope
                local sentinel_ws_name
                local sentinel_ws_rg="$current_resource_group"
                if [[ "$target_scope" == "PrimaryLogAnalyticsWorkspace" ]] || [[ "$target_scope" == "DefaultWorkspace" ]]; then
                    sentinel_ws_name="$LOG_ANALYTICS_WORKSPACE"
                     if [ -n "$sentinel_ws_name" ] && ! az monitor log-analytics workspace show --name "$sentinel_ws_name" --resource-group "$sentinel_ws_rg" &>/dev/null; then
                        local detected_rg=$(az resource list --name "$sentinel_ws_name" --resource-type "Microsoft.OperationalInsights/workspaces" --query "[0].resourceGroup" -o tsv 2>/dev/null)
                        if [ -n "$detected_rg" ]; then sentinel_ws_rg="$detected_rg"; else
                            check_result_json="{\"status\": \"Error\", \"message\": \"Default Log Analytics Workspace '$sentinel_ws_name' for Sentinel check not found in default RG '$current_resource_group' and could not auto-detect its RG.\"}"
                            echo "$check_result_json" | jq --arg id "$control_id" --arg desc "$control_desc" --arg cat "$(echo "$control_json" | jq -r '.category')" '. | .controlId = $id | .description = $desc | .category = $cat'
                            return
                        fi
                    fi
                elif [[ "$target_scope" == "SpecificResource:"* ]]; then
                    local path_part=$(echo "$target_scope" | cut -d':' -f2)
                    if [[ "$path_part" == */* ]]; then sentinel_ws_name=$(dirname "$path_part"); sentinel_ws_rg=$(basename "$path_part"); else sentinel_ws_name="$path_part"; fi
                else
                     check_result_json="{\"status\": \"Skipped\", \"message\": \"Unsupported targetScope '$target_scope' for $control_id ($control_type).\"}"
                     echo "$check_result_json" | jq --arg id "$control_id" --arg desc "$control_desc" --arg cat "$(echo "$control_json" | jq -r '.category')" '. | .controlId = $id | .description = $desc | .category = $cat'
                     return
                fi

                if [ -z "$sentinel_ws_name" ]; then
                    check_result_json="{\"status\": \"Skipped\", \"message\": \"Log Analytics Workspace name for Sentinel check not determined for $control_id. Global var LOG_ANALYTICS_WORKSPACE may be empty.\"}"
                else
                     check_result_json=$(check_sentinel_on_workspace "$sentinel_ws_name" "$sentinel_ws_rg" "$expected_config_json")
                fi
            else
                 check_result_json="{\"status\": \"Skipped\", \"message\": \"Control ID '$control_id' of type '$control_type' not specifically handled.\"}"
            fi
            ;;
        "DiagnosticSettings")
            if [ "$control_id" == "LOG_KV_DIAGNOSTICS" ]; then
                local target_res_type=$(echo "$control_json" | jq -r '.targetResourceType') # e.g. "Microsoft.KeyVault/vaults"
                local res_name # Determine resource name from targetScope
                local target_res_uri

                if [[ "$target_scope" == "SpecificResource:"* ]]; then
                    res_name=$(echo "$target_scope" | cut -d':' -f2)
                    target_res_uri="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$current_resource_group/providers/$target_res_type/$res_name"

                    local req_logs=$(echo "$control_json" | jq -c '.requiredLogs // []')
                    local req_metrics=$(echo "$control_json" | jq -c '.requiredMetrics // []')
                    local min_ret=$(echo "$control_json" | jq -r '.minRetentionDays // "0"')
                    local diag_filter_name=$(echo "$control_json" | jq -r '.diagnosticSettingNameFilter // ""')

                    check_result_json=$(check_diagnostic_settings "$target_res_uri" "$req_logs" "$req_metrics" "$min_ret" "$diag_filter_name")

                elif [[ "$target_scope" == "AllResourcesOfTypeInRG" ]]; then
                     # List all resources of target_res_type in current_resource_group
                    local resources_in_rg_json=$(az resource list --resource-group "$current_resource_group" --resource-type "$target_res_type" --query "[].id" -o json 2>/dev/null)
                    if [ $? -ne 0 ] || [ -z "$resources_in_rg_json" ] || [ "$(echo "$resources_in_rg_json" | jq '. | length')" == "0" ]; then
                        check_result_json="{\"status\": \"Skipped\", \"message\": \"No resources of type '$target_res_type' found in RG '$current_resource_group' for $control_id.\"}"
                    else
                        local all_res_findings=()
                        local overall_res_status="Compliant"
                        echo "$resources_in_rg_json" | jq -r '.[]' | while IFS= read -r res_id; do
                            local res_name_from_id=$(basename "$res_id")
                            echo -e "${BLUE}[INFO]${NC} Checking Diagnostics for '$res_name_from_id' ($target_res_type) for $control_id..."
                            local req_logs=$(echo "$control_json" | jq -c '.requiredLogs // []')
                            local req_metrics=$(echo "$control_json" | jq -c '.requiredMetrics // []')
                            local min_ret=$(echo "$control_json" | jq -r '.minRetentionDays // "0"')
                            local diag_filter_name=$(echo "$control_json" | jq -r '.diagnosticSettingNameFilter // ""')

                            local res_check_result_json=$(check_diagnostic_settings "$res_id" "$req_logs" "$req_metrics" "$min_ret" "$diag_filter_name")
                            all_res_findings+=("$(echo "$res_check_result_json" | jq --arg resid "$res_id" '. + {resourceId: $resid}')")
                            local current_res_check_status=$(echo "$res_check_result_json" | jq -r '.status')
                            if [ "$current_res_check_status" == "Error" ]; then overall_res_status="Error"; break; fi
                            if [ "$current_res_check_status" == "Non-Compliant" ] && [ "$overall_res_status" != "Error" ]; then overall_res_status="Non-Compliant"; fi
                        done < <(echo "$resources_in_rg_json" | jq -r '.[]')

                        local findings_json_array=$(printf '%s\n' "${all_res_findings[@]}" | jq -s '.')
                        check_result_json="{\"status\": \"$overall_res_status\", \"message\": \"Diagnostic settings check for all '$target_res_type' in RG '$current_resource_group' complete.\", \"details\": $findings_json_array}"
                    fi
                else
                     check_result_json="{\"status\": \"Skipped\", \"message\": \"Unsupported targetScope '$target_scope' for $control_id ($control_type).\"}"
                fi
            else
                check_result_json="{\"status\": \"Skipped\", \"message\": \"Control ID '$control_id' of type '$control_type' not specifically handled.\"}"
            fi
            ;;
        "RBACCheck")
            if [ "$control_id" == "IAM_LIMIT_OWNER_ROLES" ]; then
                local scope_to_check # Determine scope from target_scope or default
                if [[ "$target_scope" == "Subscription" ]]; then
                    scope_to_check="/subscriptions/$SUBSCRIPTION_ID"
                elif [[ "$target_scope" == "ResourceGroup:"* ]]; then
                    local rg_name_for_rbac=$(echo "$target_scope" | cut -d':' -f2)
                    scope_to_check="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$rg_name_for_rbac"
                elif [ -n "$target_scope" ] && [[ "$target_scope" == /* ]]; then # Assume it's a full path
                    scope_to_check="$target_scope"
                else # Default to current subscription if target_scope is not specific enough
                    scope_to_check="/subscriptions/$SUBSCRIPTION_ID"
                    echo -e "${YELLOW}[WARN]${NC} targetScope for $control_id is '$target_scope', defaulting to subscription scope. Specify 'Subscription' or '/subscriptions/subId' or 'ResourceGroup:rgName'."
                fi

                local role_def_id=$(echo "$control_json" | jq -r '.roleDefinitionId')
                local max_assign=$(echo "$control_json" | jq -r '.maxAssignments')
                # Optional: principal types to consider, from control definition if exists
                local principal_types_jq_arr=$(echo "$control_json" | jq -r '.principalTypes // ["User", "Group", "ServicePrincipal"]' | jq -c '.')


                check_result_json=$(check_rbac_assignments "$scope_to_check" "$role_def_id" "$max_assign" "$principal_types_jq_arr")
            else
                check_result_json="{\"status\": \"Skipped\", \"message\": \"Control ID '$control_id' of type '$control_type' not specifically handled.\"}"
            fi
            ;;
        "NSGConfig")
             # Placeholder for NSG specific checks (e.g. default deny rule, no any-any allow)
             # This would typically iterate over NSGs identified by target_scope
             check_result_json="{\"status\": \"Skipped\", \"message\": \"Control Type 'NSGConfig' for $control_id is not fully implemented yet.\"}"
            ;;
        "SubnetConfig")
            if [ "$control_id" == "NET_NSG_SUBNET_ATTACHMENT" ]; then
                # targetScope could be "AllSubnets" (implying current RG) or "VNet:myVnetName" or "AllSubnetsInRG:someOtherRG"
                local vnet_filter=""
                if [[ "$target_scope" == "VNet:"* ]]; then
                    vnet_filter=$(echo "$target_scope" | cut -d':' -f2)
                fi
                # Pass expected_config_json directly as it contains {"nsgAttached": true/false}
                check_result_json=$(check_subnet_nsg_attachment "$vnet_filter" "$expected_config_json")
            else
                check_result_json="{\"status\": \"Skipped\", \"message\": \"Control ID $control_id of type SubnetConfig not specifically handled.\"}"
            fi
            ;;
        *)
            check_result_json="{\"status\": \"Skipped\", \"message\": \"Control Type '$control_type' for ID '$control_id' is not implemented.\"}"
            ;;
    esac

    # Augment the result with control_id, description, and category before returning
    # Ensure valid JSON is formed if check_result_json is empty or malformed from the specific check function
    if ! echo "$check_result_json" | jq -e . > /dev/null 2>&1; then
        # This case should ideally not be hit if check functions always return valid JSON
        check_result_json="{\"status\": \"FrameworkError\", \"message\": \"Malformed or empty JSON response from check function for $control_id. Output: $check_result_json\"}"
    fi
    
    echo "$check_result_json" | jq --arg id "$control_id" --arg desc "$control_desc" --arg cat "$(echo "$control_json" | jq -r '.category')" \
    '. | .controlId = $id | .description = $desc | .category = $cat'

}


# Generate compliance report based on executed controls
generate_compliance_report_from_controls() {
    local control_results_json_array="$1" # Expecting a JSON array string of results

    echo -e "${BLUE}[INFO]${NC} Generating compliance report from control checks..."

    local overall_status="Compliant"
    # Check if any control result is Non-Compliant or Error
    if echo "$control_results_json_array" | jq -e '.[] | select(.status=="Non-Compliant" or .status=="Error")' > /dev/null; then
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
    "controlResults": $control_results_json_array
  }
}
EOF
)
    
    # Save the report to a file
    echo "$report" | jq . > "$REPORT_FILE"
    echo -e "${GREEN}[SUCCESS]${NC} Compliance report generated: $REPORT_FILE"

    # Print summary
    echo -e "\n${BLUE}=== Compliance Summary (Data-Driven) ===${NC}"
    echo -e "Overall Status: $(if [ "$overall_status" == "Compliant" ]; then echo -e "${GREEN}$overall_status${NC}"; else echo -e "${RED}$overall_status${NC}"; fi)"

    # Summarize by category if desired, or list non-compliant controls
    echo "$control_results_json_array" | jq -r '.[] | select(.status != "Compliant" and .status != "Skipped") | "[\(.status)] \(.controlId) - \(.description): \(.message)"' | while read -r line; do
        if [[ "$line" == *"[Non-Compliant]"* ]]; then
            echo -e "${RED}$line${NC}"
        elif [[ "$line" == *"[Error]"* ]]; then
            echo -e "${YELLOW}$line${NC}"
        else
            echo "$line"
        fi
    done
    
    return 0
}


# Main function (Data-Driven)
main_data_driven() {
    echo -e "${BLUE}=== Secure Landing Zone Compliance Verification (Data-Driven) ===${NC}"
    echo -e "${BLUE}=== $(date) ===${NC}\n"

    check_prerequisites
    load_configuration "$@"

    # Load critical controls from JSON file
    if [ ! -f "$CRITICAL_CONTROLS_FILE" ]; then
        echo -e "${RED}[ERROR]${NC} Critical controls file not found: $CRITICAL_CONTROLS_FILE"
        return 1
    fi
    local controls_json=$(jq '.' "$CRITICAL_CONTROLS_FILE")
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Failed to parse critical controls file: $CRITICAL_CONTROLS_FILE"
        return 1
    fi

    local all_control_results=() # Array to store JSON results of each control

    # Iterate over each control defined in the JSON
    echo "$controls_json" | jq -c '.criticalControls[]' | while IFS= read -r control_obj_json; do
        local result_json=$(execute_control_check "$control_obj_json")
        all_control_results+=("$result_json")
    done
    
    # Combine all results into a single JSON array
    local combined_results_json="["
    for i in "${!all_control_results[@]}"; do
        combined_results_json+="${all_control_results[$i]}"
        if [ $i -lt $((${#all_control_results[@]} - 1)) ]; then
            combined_results_json+=","
        fi
    done
    combined_results_json+="]"

    generate_compliance_report_from_controls "$combined_results_json"

    # Return exit code based on compliance status
    if grep -q '"overallStatus": "Non-Compliant"' "$REPORT_FILE"; then
        echo -e "\n${RED}[ALERT]${NC} Compliance verification failed. Please review the report."
        return 1
    else
        echo -e "\n${GREEN}[SUCCESS]${NC} Compliance verification passed."
        return 0
    fi
}

# Run the main function
main_data_driven "$@" # Run new data-driven main
# End of script.