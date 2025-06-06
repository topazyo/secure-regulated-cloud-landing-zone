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

# Helper function to normalize a single protocol:port entry
# Input: "Tcp:80", "Udp:500-600", "Any:123", "*:123", "123" (implies Any:123), "Tcp:*"
# Output: "protocol:start_port:end_port" e.g., "Tcp:80:80", "Udp:500:600", "Any:123:123", "Tcp:0:65535"
_normalize_protocol_port_entry() {
    local entry="$1"
    local proto="Any" # Default protocol
    local port_def=""

    if [[ "$entry" == *":"* ]]; then
        proto=$(echo "$entry" | cut -d':' -f1)
        port_def=$(echo "$entry" | cut -d':' -f2)
    else
        port_def="$entry" # Entry is just a port or port range or *
    fi

    if [[ "$proto" == "*" ]]; then proto="Any"; fi # Normalize protocol wildcard

    local start_port
    local end_port

    if [[ "$port_def" == "*" ]] || [[ -z "$port_def" ]]; then
        start_port="0"
        end_port="65535"
    elif [[ "$port_def" == *-* ]]; then
        start_port=$(echo "$port_def" | cut -d'-' -f1)
        end_port=$(echo "$port_def" | cut -d'-' -f2)
        # Basic validation for range values
        if ! [[ "$start_port" =~ ^[0-9]+$ && "$end_port" =~ ^[0-9]+$ && $start_port -le $end_port ]]; then
            log "WARNING" "Invalid port range in _normalize_protocol_port_entry: $port_def. Defaulting to 0-65535 for this part."
            start_port="0"; end_port="65535"
        fi
    else
        # Basic validation for single port value
        if ! [[ "$port_def" =~ ^[0-9]+$ ]]; then
             log "WARNING" "Invalid port value in _normalize_protocol_port_entry: $port_def. Defaulting to 0-65535 for this part."
             start_port="0"; end_port="65535"
        else
            start_port="$port_def"
            end_port="$port_def"
        fi
    fi

    # Ensure protocol is not empty if it was parsed as such (e.g. from ":80")
    if [[ -z "$proto" ]]; then proto="Any"; fi

    echo "${proto}:${start_port}:${end_port}"
}

# Helper function to parse an array of protocol/port definitions (from network_requirements.json)
# Input: JSON array string like '["Tcp:80", "Udp:500-600", "3000"]'
# Output: Space-separated string of normalized entries "Tcp:80:80 Udp:500:600 Any:3000:3000"
_parse_protocol_port_definitions() {
    local json_array_str="$1"
    local normalized_defs=""

    echo "$json_array_str" | jq -r '.[]?' | while IFS= read -r entry; do
        if [[ -n "$entry" ]]; then
            normalized_defs+="$(_normalize_protocol_port_entry "$entry") "
        fi
    done
    echo "$normalized_defs" | sed 's/ $//' # Remove trailing space
}

# Helper function to parse protocols and ports from an NSG rule JSON object
# Input: NSG rule JSON object string
# Output: Space-separated string of normalized entries "Protocol:StartPort:EndPort"
_parse_nsg_rule_protocols_ports() {
    local rule_json_str="$1"
    local normalized_rule_ports=""

    local protocol=$(echo "$rule_json_str" | jq -r '.protocol') # This is "Tcp", "Udp", "Icmp", "*" etc.
    local dest_port_range_single=$(echo "$rule_json_str" | jq -r '.destinationPortRange // ""')
    local dest_port_ranges_array=$(echo "$rule_json_str" | jq -c '.destinationPortRanges // []')

    # If destinationPortRanges has entries, it's preferred.
    if [[ $(echo "$dest_port_ranges_array" | jq '. | length') -gt 0 ]]; then
        echo "$dest_port_ranges_array" | jq -r '.[]?' | while IFS= read -r port_range_item; do
            if [[ -n "$port_range_item" ]]; then # port_range_item is "80", "100-200", etc.
                normalized_rule_ports+="$(_normalize_protocol_port_entry "${protocol}:${port_range_item}") "
            fi
        done
    # Else, use destinationPortRange (single value or "*")
    elif [[ -n "$dest_port_range_single" ]]; then
         normalized_rule_ports+="$(_normalize_protocol_port_entry "${protocol}:${dest_port_range_single}") "
    # If neither is present (should be rare for rules allowing traffic), treat as all ports for the protocol
    else
        normalized_rule_ports+="$(_normalize_protocol_port_entry "${protocol}:*") "
    fi

    echo "$normalized_rule_ports" | sed 's/ $//' # Remove trailing space
}

# Helper function to check for overlap between a required/prohibited entry and an actual rule entry
# Inputs: req_norm_entry ("Proto:Start:End"), rule_norm_entry ("Proto:Start:End")
# Output: "true" if overlap, "false" otherwise
_check_protocol_port_overlap() {
    local req_entry="$1"
    local rule_entry="$2"

    IFS=':' read -r req_proto req_start_port req_end_port <<< "$req_entry"
    IFS=':' read -r rule_proto rule_start_port rule_end_port <<< "$rule_entry"

    local proto_match=false
    # Using Azure's convention for wildcard protocol: "*"
    if [[ "$req_proto" == "Any" ]] || [[ "$rule_proto" == "*" ]] || \
       [[ "$req_proto" == "$rule_proto" ]]; then
        # Case-insensitive protocol match:
        # local req_proto_lower=$(echo "$req_proto" | tr '[:upper:]' '[:lower:]')
        # local rule_proto_lower=$(echo "$rule_proto" | tr '[:upper:]' '[:lower:]')
        # if [[ "$req_proto_lower" == "any" ]] || [[ "$rule_proto_lower" == "*" ]] || [[ "$rule_proto_lower" == "any" ]] || \
        #    [[ "$req_proto_lower" == "$rule_proto_lower" ]]; then
        proto_match=true
        # fi
    fi

    if ! $proto_match; then
        echo "false"
        return
    fi

    # Port overlap check: max(start1, start2) <= min(end1, end2)
    # Ensure values are treated as integers for comparison
    req_start_port=${req_start_port:-0}
    req_end_port=${req_end_port:-0}
    rule_start_port=${rule_start_port:-0}
    rule_end_port=${rule_end_port:-0}

    local max_start=$(( req_start_port > rule_start_port ? req_start_port : rule_start_port ))
    local min_end=$(( req_end_port < rule_end_port ? req_end_port : rule_end_port ))

    if (( max_start <= min_end )); then
        echo "true"
    else
        echo "false"
    fi
}

# Helper function to check address prefix overlap (simplified for Bash)
# Input1: JSON array string of required prefixes/tags (e.g., '["10.0.0.0/16", "VirtualNetwork"]')
# Input2: Single address prefix/tag from NSG rule (e.g., "10.0.1.0/24", "Internet")
# Input3: JSON array string of address prefixes/tags from NSG rule e.g. '["10.0.1.0/24", "AzureLoadBalancer"]'
# Output: "true" if a match/overlap is found, "false" otherwise
_check_address_overlap() {
    local required_prefixes_json_array_str="$1"
    local rule_single_prefix_str="$2"
    local rule_prefixes_json_array_str="$3"
    local match_found="false"

    # Normalize "Any" to "*" for comparison with Azure's typical wildcard representation
    if [[ "$rule_single_prefix_str" == "Any" ]]; then rule_single_prefix_str="*"; fi
    # TODO: Could normalize items within rule_prefixes_json_array_str as well if "Any" is used there.

    # Create a combined list of actual rule prefixes to check
    local rule_prefixes_to_check=()
    if [[ -n "$rule_single_prefix_str" && "$rule_single_prefix_str" != "null" ]]; then
        rule_prefixes_to_check+=("$rule_single_prefix_str")
    fi
    if [[ -n "$rule_prefixes_json_array_str" ]] && [[ "$rule_prefixes_json_array_str" != "[]" ]]; then
        echo "$rule_prefixes_json_array_str" | jq -r '.[]?' | while IFS= read -r item; do
             if [[ "$item" == "Any" ]]; then item="*"; fi # Normalize
             rule_prefixes_to_check+=("$item")
        done
    fi

    # If the rule has no specific prefixes (e.g. implicit any from old rule formats), treat as "*"
    if [[ ${#rule_prefixes_to_check[@]} -eq 0 ]]; then
        rule_prefixes_to_check+=("*")
    fi

    echo "$required_prefixes_json_array_str" | jq -r '.[]?' | while IFS= read -r req_prefix; do
        if [[ -z "$req_prefix" ]]; then continue; fi
        local normalized_req_prefix="$req_prefix"
        if [[ "$req_prefix" == "Any" ]]; then normalized_req_prefix="*"; fi

        for rule_prefix in "${rule_prefixes_to_check[@]}"; do
            # Case 1: Exact match
            if [[ "$normalized_req_prefix" == "$rule_prefix" ]]; then
                match_found="true"; break
            fi
            # Case 2: Required prefix is a wildcard that covers any rule_prefix
            if [[ "$normalized_req_prefix" == "*" ]] || [[ "$normalized_req_prefix" == "Internet" && "$rule_prefix" != "VirtualNetwork" && "$rule_prefix" != "AzureLoadBalancer" ]]; then # "Internet" req covers specific IPs unless rule is more restrictive like VNet only
                 match_found="true"; break
            fi
            # Case 3: Rule prefix is a wildcard that covers the required prefix
            if [[ "$rule_prefix" == "*" ]] || [[ "$rule_prefix" == "Internet" && "$normalized_req_prefix" != "VirtualNetwork" && "$normalized_req_prefix" != "AzureLoadBalancer" ]]; then
                 match_found="true"; break
            fi
            # Case 4: Specific tags that imply broader coverage
            if [[ "$normalized_req_prefix" == "VirtualNetwork" && "$rule_prefix" == "*" ]]; then # Rule allows Any, covers VNet
                 match_found="true"; break
            fi
             if [[ "$normalized_req_prefix" == "AzureLoadBalancer" && "$rule_prefix" == "*" ]]; then # Rule allows Any, covers LB
                 match_found="true"; break
            fi
            # Add more sophisticated CIDR logic here if possible in Bash, though it's hard.
            # For now, exact match or wildcards are the primary logic.
            # Example (very basic CIDR subset check - not robust):
            # if [[ $rule_prefix == ${normalized_req_prefix}* ]]; then # Rule is more specific than or equal to required.
            #    match_found="true"; break
            # fi
        done
        if [[ "$match_found" == "true" ]]; then break; fi
    done < <(echo "$required_prefixes_json_array_str" | jq -r '.[]?') # Ensure while loop runs in current shell context

    echo "$match_found"
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

function check_network_segmentation {
    log "INFO" "Checking network segmentation..."

    # Helper function to process a single subnet (either from config or dynamic discovery)
    # Parameters: $1: vnet_name, $2: vnet_rg (can be empty if using full ID from config), $3: subnet_name, $4: subnet_id (can be empty), $5: nsg_id_from_config (can be empty)
    _process_subnet_for_segmentation_check() {
        local vnet_name="$1"
        local vnet_rg="$2" # May not be needed if nsg_id_from_config is a full ID
        local subnet_name="$3"
        # local subnet_id="$4" # Currently unused in this refactor, but kept for potential future use
        local nsg_id_from_config="$5"
        
        local nsg_id_to_check="$nsg_id_from_config"
        local nsg_name
        local nsg_rg

        if [[ -z "$nsg_id_to_check" ]]; then
            # If NSG ID not from config (dynamic discovery path), try to get it using subnet details
            # This part is more relevant for the fallback dynamic mode
            local subnet_details_json=$(az network vnet subnet show --vnet-name "$vnet_name" --resource-group "$vnet_rg" --name "$subnet_name" --query "{nsgId:networkSecurityGroup.id}" -o json 2>/dev/null)
            nsg_id_to_check=$(echo "$subnet_details_json" | jq -r '.nsgId // empty')
        fi

        if [[ -n "$nsg_id_to_check" ]]; then
            nsg_name=$(echo "$nsg_id_to_check" | awk -F'/' '{print $NF}')
            # Attempt to extract RG from NSG ID, assuming standard ID format
            # /subscriptions/<sub_id>/resourceGroups/<rg_name>/providers/Microsoft.Network/networkSecurityGroups/<nsg_name>
            nsg_rg=$(echo "$nsg_id_to_check" | awk -F'/' '{if (NF>=9 && $(NF-4)=="resourceGroups") print $(NF-3); else print ""}')
            if [[ -z "$nsg_rg" && -n "$vnet_rg" ]]; then # Fallback to VNet's RG if NSG's RG not in ID or parsing failed
                log "WARNING" "Could not determine NSG resource group from ID '$nsg_id_to_check' for NSG '$nsg_name'. Assuming VNet's resource group '$vnet_rg'."
                nsg_rg="$vnet_rg"
            elif [[ -z "$nsg_rg" && -z "$vnet_rg" ]]; then # If VNet RG also not available (e.g. pure config mode with bad NSG ID)
                 log "ERROR" "Cannot determine resource group for NSG '$nsg_name' (ID: $nsg_id_to_check). Skipping rule validation for this NSG."
                 record_result "Network" "NSG-RuleValidation-$vnet_name-$subnet_name" "FAILED" "Cannot determine RG for NSG '$nsg_name' attached to subnet $subnet_name in VNet $vnet_name." "Ensure NSG ID in config is complete or NSG is in VNet's RG if VNet RG is also from config."
                 return
            fi
        fi

        if [[ -z "$nsg_id_to_check" ]]; then
            record_result "Network" "NSG-Attached-$vnet_name-$subnet_name" "FAILED" "Subnet $subnet_name in VNet $vnet_name does not have an NSG attached (or specified in config)" "Attach an NSG to the subnet or define in network_config.json."
        else
            record_result "Network" "NSG-Attached-$vnet_name-$subnet_name" "PASSED" "Subnet $subnet_name in VNet $vnet_name has an NSG attached/specified: $nsg_name" ""

            if [[ -n "$NETWORK_REQUIREMENTS_JSON" ]] && [[ -n "$nsg_name" ]] && [[ -n "$nsg_rg" ]]; then
                local subnet_req_json=$(get_subnet_requirements "$subnet_name") # NETWORK_REQUIREMENTS_JSON is global

                if [[ -n "$subnet_req_json" ]]; then
                    log "INFO" "Applying specific requirements from network_requirements.json for subnet pattern matching '$subnet_name' using NSG '$nsg_name' (RG: '$nsg_rg')."
                    local nsg_rules_json=$(az network nsg rule list --nsg-name "$nsg_name" --resource-group "$nsg_rg" -o json 2>/dev/null)
                    if [ $? -ne 0 ] || [[ -z "$nsg_rules_json" ]]; then
                        log "ERROR" "Failed to fetch rules for NSG '$nsg_name' in RG '$nsg_rg'."
                        record_result "Network" "NSG-RuleFetch-$nsg_name" "FAILED" "Could not fetch rules for NSG '$nsg_name'." "Check NSG existence and permissions."
                        return
                    fi

                    local prohibited_sources_jq=$(echo "$subnet_req_json" | jq -c '.prohibitedInboundSources // []')
                    if [[ $(echo "$prohibited_sources_jq" | jq '. | length') -gt 0 ]]; then
                        echo "$nsg_rules_json" | jq -c '.[] | select(.direction == "Inbound")' | while IFS= read -r rule_json; do
                            local rule_name=$(echo "$rule_json" | jq -r '.name')
                            local source_prefix=$(echo "$rule_json" | jq -r '.sourceAddressPrefix // "Any"')
                            local source_prefixes_array=$(echo "$rule_json" | jq -c '.sourceAddressPrefixes // []')

                            if echo "$prohibited_sources_jq" | jq -e --arg sp "$source_prefix" '.[] | select(. == $sp)' > /dev/null; then
                                 record_result "Network" "Subnet-$subnet_name-NSGRule-$rule_name-ProhibitedSource" "FAILED" "NSG rule '$rule_name' allows prohibited source '$source_prefix' for subnet '$subnet_name'." "Review NSG rule."
                                 continue
                            fi
                            echo "$source_prefixes_array" | jq -r '.[]' | while IFS= read -r sp_item; do
                                if echo "$prohibited_sources_jq" | jq -e --arg sp_item_arg "$sp_item" '.[] | select(. == $sp_item_arg)' > /dev/null; then
                                    record_result "Network" "Subnet-$subnet_name-NSGRule-$rule_name-ProhibitedSourceArray" "FAILED" "NSG rule '$rule_name' allows prohibited source '$sp_item' (from array) for subnet '$subnet_name'." "Review NSG rule."
                                fi
                            done
                        done
                    fi

                    local prohibited_ports_jq=$(echo "$subnet_req_json" | jq -c '.prohibitedPorts // []')
                    if [[ $(echo "$prohibited_ports_jq" | jq '. | length') -gt 0 ]]; then
                        log "INFO" "Checking prohibited ports for subnet '$subnet_name' (NSG: '$nsg_name'). Prohibited definition: $(echo "$prohibited_ports_jq" | jq -r 'join(", ")')"

                        local normalized_prohibited_defs=$(_parse_protocol_port_definitions "$prohibited_ports_jq")

                        echo "$nsg_rules_json" | jq -c '.[]' | while IFS= read -r rule_json_obj_str; do
                            local rule_name=$(echo "$rule_json_obj_str" | jq -r '.name')
                            local rule_direction=$(echo "$rule_json_obj_str" | jq -r '.direction') # For context in messages
                            local rule_access=$(echo "$rule_json_obj_str" | jq -r '.access') # Only check Allow rules for prohibited ports

                            if [[ "$rule_access" != "Allow" ]]; then
                                continue # Skip Deny rules when checking for prohibited allowed ports
                            fi

                            local normalized_rule_entries=$(_parse_nsg_rule_protocols_ports "$rule_json_obj_str")

                            # For each normalized prohibited definition
                            for req_norm_entry in $normalized_prohibited_defs; do
                                # For each normalized port/protocol the current NSG rule allows
                                for rule_norm_entry in $normalized_rule_entries; do
                                    if [[ $(_check_protocol_port_overlap "$req_norm_entry" "$rule_norm_entry") == "true" ]]; then
                                        record_result "Network" "Subnet-$subnet_name-NSGRule-$rule_name-ProhibitedPortProtocol" "FAILED" "NSG rule '$rule_name' (Direction: $rule_direction, Access: $rule_access) allows traffic on '${rule_norm_entry}', which overlaps with prohibited entry '${req_norm_entry}' for subnet '$subnet_name'." "Review NSG rule '$rule_name'."
                                        # Could 'break 2' here to stop checking this rule if one violation is enough,
                                        # or continue to find all overlaps for this rule. For now, report first overlap.
                                        break # Stop checking this rule_norm_entry against other req_norm_entry
                                    fi
                                done # end loop rule_norm_entry
                                # If an overlap was found for req_norm_entry, the inner 'break' would have been hit.
                                # To break outer loop as well if an overlap is found for the rule:
                                # local last_status_key="Network:Subnet-$subnet_name-NSGRule-$rule_name-ProhibitedPortProtocol"
                                # if [[ -n "${COMPLIANCE_RESULTS[$last_status_key]}" ]] && [[ $(echo "${COMPLIANCE_RESULTS[$last_status_key]}" | jq -r .status) == "FAILED" ]]; then
                                #    break # Stop checking this req_norm_entry against further rule_norm_entries if already failed.
                                # fi
                            done # end loop req_norm_entry
                        done < <(echo "$nsg_rules_json" | jq -c '.[]') # Ensure while loop runs in current shell context for record_result
                    fi

                    # Check for allowedInboundTraffic
                    local allowed_inbound_jq=$(echo "$subnet_req_json" | jq -c '.allowedInboundTraffic // []')
                    if [[ $(echo "$allowed_inbound_jq" | jq '. | length') -gt 0 ]]; then
                        log "INFO" "Checking allowedInboundTraffic for subnet '$subnet_name' (NSG: '$nsg_name')."
                        echo "$allowed_inbound_jq" | jq -c '.[]' | while IFS= read -r allowed_req_item_json; do
                            local req_name=$(echo "$allowed_req_item_json" | jq -r '.name // "Unnamed Allowed Inbound Rule"')
                            local req_protocol_defs_jq=$(echo "$allowed_req_item_json" | jq -c '.ports // []') # Assuming 'ports' contains array like ["Tcp:443", "Tcp:80"]
                            local req_source_prefixes_jq=$(echo "$allowed_req_item_json" | jq -c '.sourcePrefixes // []')

                            local normalized_req_protocol_ports=$(_parse_protocol_port_definitions "$req_protocol_defs_jq")
                            local found_satisfying_nsg_rule_for_this_req=false

                            for req_norm_prot_port_entry in $normalized_req_protocol_ports; do
                                # For each actual NSG rule
                                echo "$nsg_rules_json" | jq -c '.[]' | while IFS= read -r rule_json_obj_str; do
                                    local nsg_rule_access=$(echo "$rule_json_obj_str" | jq -r '.access')
                                    local nsg_rule_direction=$(echo "$rule_json_obj_str" | jq -r '.direction')

                                    if [[ "$nsg_rule_access" == "Allow" && "$nsg_rule_direction" == "Inbound" ]]; then
                                        local normalized_nsg_rule_entries=$(_parse_nsg_rule_protocols_ports "$rule_json_obj_str")
                                        local nsg_rule_source_prefix=$(echo "$rule_json_obj_str" | jq -r '.sourceAddressPrefix // ""')
                                        local nsg_rule_source_prefixes_array=$(echo "$rule_json_obj_str" | jq -c '.sourceAddressPrefixes // []')

                                        for nsg_norm_entry in $normalized_nsg_rule_entries; do
                                            if [[ $(_check_protocol_port_overlap "$req_norm_prot_port_entry" "$nsg_norm_entry") == "true" ]]; then
                                                if [[ $(_check_address_overlap "$req_source_prefixes_jq" "$nsg_rule_source_prefix" "$nsg_rule_source_prefixes_array") == "true" ]]; then
                                                    found_satisfying_nsg_rule_for_this_req=true; break 2 # Found rule for this prot_port_entry, break from nsg_rule and prot_port_entry loops
                                                fi
                                            fi
                                        done # end nsg_norm_entry loop
                                    fi
                                done < <(echo "$nsg_rules_json" | jq -c '.[]') # nsg_rules_json loop context
                                if $found_satisfying_nsg_rule_for_this_req; then break; fi # Break from req_norm_prot_port_entry loop
                            done # end req_norm_prot_port_entry loop

                            if ! $found_satisfying_nsg_rule_for_this_req; then
                                record_result "Network" "Subnet-$subnet_name-MissingAllowedInbound-$req_name" "FAILED" "Required allowed inbound traffic rule '$req_name' (Ports/Proto: $normalized_req_protocol_ports, Sources: $(echo "$req_source_prefixes_jq" | jq -r .)) for subnet '$subnet_name' is not satisfied by any NSG rule." "Ensure NSG '$nsg_name' has a corresponding Allow rule."
                            else
                                record_result "Network" "Subnet-$subnet_name-AllowedInboundMet-$req_name" "PASSED" "Required allowed inbound traffic rule '$req_name' for subnet '$subnet_name' is satisfied." ""
                            fi
                        done < <(echo "$allowed_inbound_jq" | jq -c '.[]') # allowed_inbound_jq loop context
                    fi

                    # Check for allowedOutboundTraffic
                    local allowed_outbound_jq=$(echo "$subnet_req_json" | jq -c '.allowedOutboundTraffic // []')
                    if [[ $(echo "$allowed_outbound_jq" | jq '. | length') -gt 0 ]]; then
                        log "INFO" "Checking allowedOutboundTraffic for subnet '$subnet_name' (NSG: '$nsg_name')."
                        echo "$allowed_outbound_jq" | jq -c '.[]' | while IFS= read -r allowed_req_item_json; do
                            local req_name=$(echo "$allowed_req_item_json" | jq -r '.name // "Unnamed Allowed Outbound Rule"')
                            # Assuming 'ports' in requirements combines protocol and port, e.g., ["Tcp:443", "Udp:*"]
                            # Or, if protocol is separate: local req_protocol=$(echo "$allowed_req_item_json" | jq -r '.protocol')
                            local req_port_protocol_defs_jq=$(echo "$allowed_req_item_json" | jq -c '.ports // []')
                            local req_dest_prefixes_jq=$(echo "$allowed_req_item_json" | jq -c '.destinationPrefixes // []')

                            local normalized_req_port_protocols=$(_parse_protocol_port_definitions "$req_port_protocol_defs_jq")
                            local found_satisfying_nsg_rule_for_this_req=false

                            # Iterate over each normalized required protocol/port entry derived from the current allowed traffic requirement
                            for req_norm_prot_port_entry in $normalized_req_port_protocols; do
                                # For each actual NSG rule
                                echo "$nsg_rules_json" | jq -c '.[]' | while IFS= read -r rule_json_obj_str; do
                                    local nsg_rule_access=$(echo "$rule_json_obj_str" | jq -r '.access')
                                    local nsg_rule_direction=$(echo "$rule_json_obj_str" | jq -r '.direction')

                                    if [[ "$nsg_rule_access" == "Allow" && "$nsg_rule_direction" == "Outbound" ]]; then
                                        local normalized_nsg_rule_entries=$(_parse_nsg_rule_protocols_ports "$rule_json_obj_str")
                                        # For NSG outbound rules, we check rule's destinationAddressPrefix(es)
                                        local nsg_rule_dest_prefix=$(echo "$rule_json_obj_str" | jq -r '.destinationAddressPrefix // ""')
                                        local nsg_rule_dest_prefixes_array=$(echo "$rule_json_obj_str" | jq -c '.destinationAddressPrefixes // []')

                                        # For each normalized port/protocol the current NSG rule allows
                                        for nsg_norm_entry in $normalized_nsg_rule_entries; do
                                            if [[ $(_check_protocol_port_overlap "$req_norm_prot_port_entry" "$nsg_norm_entry") == "true" ]]; then
                                                # Protocol and Port overlap, now check Address
                                                if [[ $(_check_address_overlap "$req_dest_prefixes_jq" "$nsg_rule_dest_prefix" "$nsg_rule_dest_prefixes_array") == "true" ]]; then
                                                    found_satisfying_nsg_rule_for_this_req=true; break 2 # Found rule for this prot_port_entry, break from nsg_rule and prot_port_entry loops
                                                fi
                                            fi
                                        done # end nsg_norm_entry loop
                                    fi
                                done < <(echo "$nsg_rules_json" | jq -c '.[]') # nsg_rules_json loop context for current NSG rule
                                if $found_satisfying_nsg_rule_for_this_req; then break; fi # Break from req_norm_prot_port_entry loop if already satisfied
                            done # end req_norm_prot_port_entry loop for current allowed requirement

                            if ! $found_satisfying_nsg_rule_for_this_req; then
                                record_result "Network" "Subnet-$subnet_name-MissingAllowedOutbound-$req_name" "FAILED" "Required allowed outbound traffic rule '$req_name' (Ports/Proto: $normalized_req_port_protocols, Destinations: $(echo "$req_dest_prefixes_jq" | jq -r .)) for subnet '$subnet_name' is not satisfied by any NSG rule." "Ensure NSG '$nsg_name' has a corresponding Allow rule for outbound traffic."
                            else
                                record_result "Network" "Subnet-$subnet_name-AllowedOutboundMet-$req_name" "PASSED" "Required allowed outbound traffic rule '$req_name' for subnet '$subnet_name' is satisfied." ""
                            fi
                        done < <(echo "$allowed_outbound_jq" | jq -c '.[]') # allowed_outbound_jq loop context
                    fi
                else
                    log "INFO" "No specific network requirements found for subnet pattern matching '$subnet_name'. Standard NSG rules apply if any generic checks are defined later."
                fi
            else
                 if [[ -z "$NETWORK_REQUIREMENTS_JSON" ]]; then
                    log "WARNING" "NETWORK_REQUIREMENTS_JSON not loaded. Skipping detailed NSG rule validation for $nsg_name."
                 elif [[ -z "$nsg_name" ]] || [[ -z "$nsg_rg" ]]; then
                    log "WARNING" "NSG name or RG could not be determined for subnet $subnet_name. Skipping detailed NSG rule validation."
                 fi
            fi
        fi
    } # End of _process_subnet_for_segmentation_check helper

    if [[ -n "$NETWORK_CONFIG_JSON" ]]; then
        log "INFO" "Using network_config.json for network segmentation checks."
        echo "$NETWORK_CONFIG_JSON" | jq -c '.virtualNetworks[]?' | while IFS= read -r vnet_config_row; do
            local vnet_name_cfg=$(echo "$vnet_config_row" | jq -r '.name')
            # VNet RG might be part of VNet config or assumed globally.
            # If NSG IDs in config are full Azure IDs, vnet_rg_cfg might not be strictly needed for NSG rule fetching.
            # However, it's good practice to have it or derive it if possible.
            local vnet_rg_cfg=$(echo "$vnet_config_row" | jq -r '.resourceGroup // ""')
            if [[ -z "$vnet_rg_cfg" ]]; then
                # Attempt to derive from VNet ID if present in config, otherwise use global default
                local vnet_id_cfg=$(echo "$vnet_config_row" | jq -r '.id // ""')
                if [[ -n "$vnet_id_cfg" ]]; then
                     vnet_rg_cfg=$(echo "$vnet_id_cfg" | awk -F'/' '{if (NF>=9 && $(NF-4)=="resourceGroups") print $(NF-3); else print ""}')
                fi
                if [[ -z "$vnet_rg_cfg" ]]; then # If still empty, fallback to global $RESOURCE_GROUP
                    vnet_rg_cfg="$RESOURCE_GROUP" # Global script parameter
                    log "INFO" "VNet '$vnet_name_cfg' from config does not specify resourceGroup, using global script parameter: '$vnet_rg_cfg'."
                fi
            fi
            log "INFO" "Checking VNet (from config): $vnet_name_cfg in RG: ${vnet_rg_cfg:-'Not Specified, will derive or use default'}"

            echo "$vnet_config_row" | jq -c '.subnets[]?' | while IFS= read -r subnet_config_row; do
                local subnet_name_cfg=$(echo "$subnet_config_row" | jq -r '.name')
                local subnet_id_cfg=$(echo "$subnet_config_row" | jq -r '.id // empty')
                # Try to find NSG reference, accommodate common variations like 'networkSecurityGroupRef.id' or 'networkSecurityGroup.id'
                local nsg_id_cfg=$(echo "$subnet_config_row" | jq -r '.networkSecurityGroupRef.id // .networkSecurityGroup.id // .nsgRef // .nsg.id // empty')

                _process_subnet_for_segmentation_check "$vnet_name_cfg" "$vnet_rg_cfg" "$subnet_name_cfg" "$subnet_id_cfg" "$nsg_id_cfg"
            done
        done
    else
        log "INFO" "network_config.json not loaded or empty. Falling back to dynamic discovery of network resources."
        local vnets_dynamic=$(az network vnet list --query "[].{name:name, resourceGroup:resourceGroup}" -o json 2>/dev/null)
        if [ $? -ne 0 ] || [[ -z "$vnets_dynamic" ]]; then
            log "ERROR" "Failed to list VNets dynamically."
            record_result "Network" "VNetListing" "FAILED" "Could not list VNets dynamically for segmentation checks." "Check Azure CLI permissions and connectivity."
            return
        fi

        for vnet_row_dyn in $(echo "$vnets_dynamic" | jq -c '.[]'); do
            local vnet_name_dyn=$(echo "$vnet_row_dyn" | jq -r '.name')
            local vnet_rg_dyn=$(echo "$vnet_row_dyn" | jq -r '.resourceGroup')
            log "INFO" "Checking VNet (dynamic): $vnet_name_dyn in resource group: $vnet_rg_dyn"

            local subnets_json_dyn=$(az network vnet subnet list --vnet-name "$vnet_name_dyn" --resource-group "$vnet_rg_dyn" -o json 2>/dev/null)
            if [ $? -ne 0 ] || [[ -z "$subnets_json_dyn" ]]; then
                 log "WARNING" "Failed to list subnets for VNet '$vnet_name_dyn' or VNet has no subnets."
                 continue
            fi

            for subnet_row_dyn in $(echo "$subnets_json_dyn" | jq -c '.[]'); do
                local subnet_name_dyn=$(echo "$subnet_row_dyn" | jq -r '.name')
                local subnet_id_dyn=$(echo "$subnet_row_dyn" | jq -r '.id')
                local nsg_id_dyn=$(echo "$subnet_row_dyn" | jq -r '.networkSecurityGroup.id // empty')
                _process_subnet_for_segmentation_check "$vnet_name_dyn" "$vnet_rg_dyn" "$subnet_name_dyn" "$subnet_id_dyn" "$nsg_id_dyn"
            done
        done
    fi
    
    # General "overly permissive rules" check (can be kept or refined - currently outside config-driven loop)
    # This part needs to decide if it uses config-defined NSGs or all NSGs.
    # For now, let's keep it as a general sweep, but it could be integrated.
    log "INFO" "Performing general check for overly permissive NSG rules across all NSGs (dynamic discovery)..."
    local all_nsgs_json=$(az network nsg list --query "[].{name:name, resourceGroup:resourceGroup, securityRules:securityRules}" -o json 2>/dev/null)
    if [ $? -eq 0 ] && [[ -n "$all_nsgs_json" ]]; then
        echo "$all_nsgs_json" | jq -c '.[]' | while IFS= read -r nsg_row; do
            local nsg_name=$(echo "$nsg_row" | jq -r '.name')
            local nsg_rg=$(echo "$nsg_row" | jq -r '.resourceGroup')

            echo "$nsg_row" | jq -c '.securityRules[]? | select(.sourceAddressPrefix == "*" and .access == "Allow" and .direction == "Inbound")' | while IFS= read -r permissive_rule_json; do
                 if [[ -n "$permissive_rule_json" ]]; then
                    local rule_name=$(echo "$permissive_rule_json" | jq -r '.name')
                    record_result "Network" "GenericPermissiveRule-$nsg_name-$rule_name" "WARNING" "NSG $nsg_name (RG: $nsg_rg) rule '$rule_name' allows * source for Inbound traffic." "Restrict source address for rule '$rule_name'."
                 fi
            done
        done
    else
        log "WARNING" "Could not list all NSGs for general permissive rule check or no NSGs found."
    fi
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