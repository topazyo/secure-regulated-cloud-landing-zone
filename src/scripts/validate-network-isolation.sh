#!/bin/bash
# validate-network-isolation.sh
#
# This script validates network isolation for regulated workloads in Azure
# It performs comprehensive testing of network security groups, firewalls,
# and microsegmentation to ensure compliance with security requirements.
#
# Usage: ./validate-network-isolation.sh [--resource-group <name>] [--subscription <id>] [--verbose]

set -e

# Default values
RESOURCE_GROUP=""
SUBSCRIPTION_ID=""
VERBOSE=false
OUTPUT_FILE="network-isolation-report-$(date +%Y%m%d-%H%M%S).json"
LOG_FILE="network-validation-$(date +%Y%m%d-%H%M%S).log"
CRITICAL_ZONES=("swift-network" "pci-network" "payment-processing")
TEMP_DIR=$(mktemp -d)

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --resource-group)
      RESOURCE_GROUP="$2"
      shift
      shift
      ;;
    --subscription)
      SUBSCRIPTION_ID="$2"
      shift
      shift
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    --help)
      echo "Usage: ./validate-network-isolation.sh [--resource-group <name>] [--subscription <id>] [--verbose]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: ./validate-network-isolation.sh [--resource-group <name>] [--subscription <id>] [--verbose]"
      exit 1
      ;;
  esac
done

# Function to log messages
log() {
  local level=$1
  local message=$2
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  
  echo -e "[$timestamp] [$level] $message" >> "$LOG_FILE"
  
  if [[ "$VERBOSE" == "true" || "$level" == "ERROR" ]]; then
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
    esac
  fi
}

# Function to check prerequisites
check_prerequisites() {
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
  
  # Check Azure CLI login status
  az account show &> /dev/null
  if [ $? -ne 0 ]; then
    log "ERROR" "Not logged in to Azure. Please run 'az login' first."
    exit 1
  }
  
  # Set subscription if provided
  if [ -n "$SUBSCRIPTION_ID" ]; then
    log "INFO" "Setting subscription to $SUBSCRIPTION_ID"
    az account set --subscription "$SUBSCRIPTION_ID"
    if [ $? -ne 0 ]; then
      log "ERROR" "Failed to set subscription. Please check the subscription ID."
      exit 1
    fi
  else
    # Get current subscription
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    log "INFO" "Using current subscription: $SUBSCRIPTION_ID"
  }
  
  # Prompt for resource group if not provided
  if [ -z "$RESOURCE_GROUP" ]; then
    log "INFO" "No resource group specified. Listing available resource groups..."
    az group list --query "[].name" -o tsv
    
    read -p "Enter resource group name: " RESOURCE_GROUP
    if [ -z "$RESOURCE_GROUP" ]; then
      log "ERROR" "Resource group name cannot be empty."
      exit 1
    fi
  }
  
  # Verify resource group exists
  az group show --name "$RESOURCE_GROUP" &> /dev/null
  if [ $? -ne 0 ]; then
    log "ERROR" "Resource group '$RESOURCE_GROUP' not found."
    exit 1
  }
  
  log "SUCCESS" "Prerequisites check completed successfully."
}

# Function to get all virtual networks in the resource group
get_virtual_networks() {
  log "INFO" "Retrieving virtual networks in resource group $RESOURCE_GROUP..."
  
  VNETS=$(az network vnet list \
    --resource-group "$RESOURCE_GROUP" \
    --query "[].{name:name, id:id, addressSpace:addressSpace.addressPrefixes[0]}" \
    -o json)
  
  echo "$VNETS" > "$TEMP_DIR/vnets.json"
  
  VNET_COUNT=$(echo "$VNETS" | jq length)
  log "INFO" "Found $VNET_COUNT virtual networks."
  
  return 0
}

# Function to get all subnets in each virtual network
get_subnets() {
  log "INFO" "Retrieving subnets for all virtual networks..."
  
  VNETS=$(cat "$TEMP_DIR/vnets.json")
  
  for i in $(seq 0 $(($(echo "$VNETS" | jq length) - 1))); do
    VNET_NAME=$(echo "$VNETS" | jq -r ".[$i].name")
    log "INFO" "Getting subnets for VNet: $VNET_NAME"
    
    SUBNETS=$(az network vnet subnet list \
      --resource-group "$RESOURCE_GROUP" \
      --vnet-name "$VNET_NAME" \
      --query "[].{name:name, addressPrefix:addressPrefix, nsgId:networkSecurityGroup.id}" \
      -o json)
    
    echo "$SUBNETS" > "$TEMP_DIR/subnets_$VNET_NAME.json"
    
    SUBNET_COUNT=$(echo "$SUBNETS" | jq length)
    log "INFO" "Found $SUBNET_COUNT subnets in VNet $VNET_NAME."
  done
  
  return 0
}

# Function to validate NSG rules for each subnet
validate_nsg_rules() {
  log "INFO" "Validating NSG rules for all subnets..."
  
  VNETS=$(cat "$TEMP_DIR/vnets.json")
  
  for i in $(seq 0 $(($(echo "$VNETS" | jq length) - 1))); do
    VNET_NAME=$(echo "$VNETS" | jq -r ".[$i].name")
    SUBNETS=$(cat "$TEMP_DIR/subnets_$VNET_NAME.json")
    
    for j in $(seq 0 $(($(echo "$SUBNETS" | jq length) - 1))); do
      SUBNET_NAME=$(echo "$SUBNETS" | jq -r ".[$j].name")
      NSG_ID=$(echo "$SUBNETS" | jq -r ".[$j].nsgId")
      
      if [ "$NSG_ID" == "null" ]; then
        log "WARNING" "Subnet $SUBNET_NAME in VNet $VNET_NAME has no NSG attached!"
        echo "{\"vnet\":\"$VNET_NAME\",\"subnet\":\"$SUBNET_NAME\",\"issue\":\"No NSG attached\",\"severity\":\"High\"}" >> "$TEMP_DIR/issues.json"
        continue
      }
      
      NSG_NAME=$(echo "$NSG_ID" | awk -F'/' '{print $NF}')
      log "INFO" "Validating NSG $NSG_NAME for subnet $SUBNET_NAME"
      
      # Get NSG rules
      NSG_RULES=$(az network nsg show \
        --name "$NSG_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query "securityRules" \
        -o json)
      
      echo "$NSG_RULES" > "$TEMP_DIR/nsg_rules_${VNET_NAME}_${SUBNET_NAME}.json"
      
      # Check for critical issues in NSG rules
      validate_critical_nsg_rules "$VNET_NAME" "$SUBNET_NAME" "$NSG_RULES"
    done
  done
  
  return 0
}

# Function to validate critical NSG rules
validate_critical_nsg_rules() {
  local vnet_name=$1
  local subnet_name=$2
  local nsg_rules=$3
  
  # Check if this is a critical zone that needs special validation
  is_critical=false
  for zone in "${CRITICAL_ZONES[@]}"; do
    if [[ "$subnet_name" == *"$zone"* ]]; then
      is_critical=true
      break
    fi
  done
  
  # Validate default deny rule exists
  has_default_deny=$(echo "$nsg_rules" | jq '[.[] | select(.direction=="Inbound" and .access=="Deny" and .priority>=4000)] | length')
  if [ "$has_default_deny" -eq 0 ]; then
    log "WARNING" "Subnet $subnet_name in VNet $vnet_name has no default deny rule!"
    echo "{\"vnet\":\"$vnet_name\",\"subnet\":\"$subnet_name\",\"issue\":\"No default deny rule\",\"severity\":\"Medium\"}" >> "$TEMP_DIR/issues.json"
  fi
  
  # For critical zones, perform additional checks
  if [ "$is_critical" = true ]; then
    log "INFO" "Performing enhanced validation for critical zone: $subnet_name"
    
    # Check for any allow rules from Internet
    internet_allow=$(echo "$nsg_rules" | jq '[.[] | select(.direction=="Inbound" and .access=="Allow" and (.sourceAddressPrefix=="Internet" or .sourceAddressPrefix=="*"))] | length')
    if [ "$internet_allow" -gt 0 ]; then
      log "ERROR" "Critical subnet $subnet_name in VNet $vnet_name allows Internet traffic!"
      echo "{\"vnet\":\"$vnet_name\",\"subnet\":\"$subnet_name\",\"issue\":\"Internet traffic allowed to critical subnet\",\"severity\":\"Critical\"}" >> "$TEMP_DIR/issues.json"
    fi
    
    # Check for any allow rules with * destination port
    wildcard_port=$(echo "$nsg_rules" | jq '[.[] | select(.direction=="Inbound" and .access=="Allow" and .destinationPortRange=="*")] | length')
    if [ "$wildcard_port" -gt 0 ]; then
      log "WARNING" "Critical subnet $subnet_name in VNet $vnet_name has rules with wildcard destination ports!"
      echo "{\"vnet\":\"$vnet_name\",\"subnet\":\"$subnet_name\",\"issue\":\"Wildcard destination ports in allow rules\",\"severity\":\"High\"}" >> "$TEMP_DIR/issues.json"
    fi
  fi
}

# Function to validate network peering isolation
validate_peering() {
  log "INFO" "Validating network peering configurations..."
  
  VNETS=$(cat "$TEMP_DIR/vnets.json")
  
  for i in $(seq 0 $(($(echo "$VNETS" | jq length) - 1))); do
    VNET_NAME=$(echo "$VNETS" | jq -r ".[$i].name")
    
    # Get peering configurations
    PEERINGS=$(az network vnet peering list \
      --resource-group "$RESOURCE_GROUP" \
      --vnet-name "$VNET_NAME" \
      -o json)
    
    echo "$PEERINGS" > "$TEMP_DIR/peerings_$VNET_NAME.json"
    
    # Check for critical zone peering issues
    for zone in "${CRITICAL_ZONES[@]}"; do
      if [[ "$VNET_NAME" == *"$zone"* ]]; then
        log "INFO" "Checking peering for critical VNet: $VNET_NAME"
        
        # Check if critical VNet allows gateway transit
        gateway_transit=$(echo "$PEERINGS" | jq '[.[] | select(.allowGatewayTransit==true)] | length')
        if [ "$gateway_transit" -gt 0 ]; then
          log "WARNING" "Critical VNet $VNET_NAME allows gateway transit!"
          echo "{\"vnet\":\"$VNET_NAME\",\"issue\":\"Gateway transit allowed in critical VNet\",\"severity\":\"High\"}" >> "$TEMP_DIR/issues.json"
        fi
        
        # Check if critical VNet uses remote gateways
        remote_gateway=$(echo "$PEERINGS" | jq '[.[] | select(.useRemoteGateways==true)] | length')
        if [ "$remote_gateway" -gt 0 ]; then
          log "WARNING" "Critical VNet $VNET_NAME uses remote gateways!"
          echo "{\"vnet\":\"$VNET_NAME\",\"issue\":\"Remote gateways used in critical VNet\",\"severity\":\"High\"}" >> "$TEMP_DIR/issues.json"
        fi
      fi
    done
  done
  
  return 0
}

# Function to validate Azure Firewall rules
validate_firewall_rules() {
  log "INFO" "Validating Azure Firewall rules..."
  
  # Check if Azure Firewall exists
  FIREWALLS=$(az network firewall list \
    --resource-group "$RESOURCE_GROUP" \
    --query "[].{name:name, id:id}" \
    -o json)
  
  FIREWALL_COUNT=$(echo "$FIREWALLS" | jq length)
  
  if [ "$FIREWALL_COUNT" -eq 0 ]; then
    log "WARNING" "No Azure Firewall found in resource group $RESOURCE_GROUP"
    echo "{\"issue\":\"No Azure Firewall deployed\",\"severity\":\"Medium\"}" >> "$TEMP_DIR/issues.json"
    return 0
  }
  
  for i in $(seq 0 $(($(echo "$FIREWALLS" | jq length) - 1))); do
    FIREWALL_NAME=$(echo "$FIREWALLS" | jq -r ".[$i].name")
    log "INFO" "Validating rules for Firewall: $FIREWALL_NAME"
    
    # Get network rules
    NETWORK_RULES=$(az network firewall network-rule list \
      --resource-group "$RESOURCE_GROUP" \
      --firewall-name "$FIREWALL_NAME" \
      -o json)
    
    echo "$NETWORK_RULES" > "$TEMP_DIR/firewall_network_rules.json"
    
    # Get application rules
    APP_RULES=$(az network firewall application-rule list \
      --resource-group "$RESOURCE_GROUP" \
      --firewall-name "$FIREWALL_NAME" \
      -o json)
    
    echo "$APP_RULES" > "$TEMP_DIR/firewall_app_rules.json"
    
    # Validate critical firewall rules
    validate_critical_firewall_rules "$NETWORK_RULES" "$APP_RULES"
  done
  
  return 0
}

# Function to validate critical firewall rules
validate_critical_firewall_rules() {
  local network_rules=$1
  local app_rules=$2
  
  # Check for overly permissive network rules
  permissive_rules=$(echo "$network_rules" | jq '[.[] | select(.rules[].destinationAddresses[] == "*" and .rules[].destinationPorts[] == "*")] | length')
  if [ "$permissive_rules" -gt 0 ]; then
    log "WARNING" "Firewall has overly permissive network rules!"
    echo "{\"issue\":\"Overly permissive firewall network rules\",\"severity\":\"High\"}" >> "$TEMP_DIR/issues.json"
  fi
  
  # Check for rules allowing traffic to critical zones
  for zone in "${CRITICAL_ZONES[@]}"; do
    critical_zone_rules=$(echo "$network_rules" | jq "[.[] | select(.rules[].destinationAddresses[] | contains(\"$zone\"))] | length")
    if [ "$critical_zone_rules" -gt 0 ]; then
      log "INFO" "Validating rules for critical zone: $zone"
      
      # Check for rules allowing traffic from Internet to critical zones
      internet_to_critical=$(echo "$network_rules" | jq "[.[] | select(.rules[].sourceAddresses[] | contains(\"Internet\") or contains(\"*\")) | select(.rules[].destinationAddresses[] | contains(\"$zone\"))] | length")
      if [ "$internet_to_critical" -gt 0 ]; then
        log "ERROR" "Firewall allows Internet traffic to critical zone $zone!"
        echo "{\"issue\":\"Internet traffic allowed to $zone\",\"severity\":\"Critical\"}" >> "$TEMP_DIR/issues.json"
      fi
    fi
  done
}

# Function to validate service endpoints
validate_service_endpoints() {
  log "INFO" "Validating service endpoints..."
  
  VNETS=$(cat "$TEMP_DIR/vnets.json")
  
  for i in $(seq 0 $(($(echo "$VNETS" | jq length) - 1))); do
    VNET_NAME=$(echo "$VNETS" | jq -r ".[$i].name")
    SUBNETS=$(cat "$TEMP_DIR/subnets_$VNET_NAME.json")
    
    for j in $(seq 0 $(($(echo "$SUBNETS" | jq length) - 1))); do
      SUBNET_NAME=$(echo "$SUBNETS" | jq -r ".[$j].name")
      
      # Get service endpoints
      SERVICE_ENDPOINTS=$(az network vnet subnet show \
        --resource-group "$RESOURCE_GROUP" \
        --vnet-name "$VNET_NAME" \
        --name "$SUBNET_NAME" \
        --query "serviceEndpoints" \
        -o json)
      
      echo "$SERVICE_ENDPOINTS" > "$TEMP_DIR/service_endpoints_${VNET_NAME}_${SUBNET_NAME}.json"
      
      # Check for critical zones
      for zone in "${CRITICAL_ZONES[@]}"; do
        if [[ "$SUBNET_NAME" == *"$zone"* ]]; then
          log "INFO" "Checking service endpoints for critical subnet: $SUBNET_NAME"
          
          # Check if Key Vault service endpoint is enabled for critical subnets
          keyvault_endpoint=$(echo "$SERVICE_ENDPOINTS" | jq '[.[] | select(.service=="Microsoft.KeyVault")] | length')
          if [ "$keyvault_endpoint" -eq 0 ]; then
            log "WARNING" "Critical subnet $SUBNET_NAME does not have KeyVault service endpoint enabled!"
            echo "{\"vnet\":\"$VNET_NAME\",\"subnet\":\"$SUBNET_NAME\",\"issue\":\"KeyVault service endpoint not enabled\",\"severity\":\"Medium\"}" >> "$TEMP_DIR/issues.json"
          fi
          
          # Check if Storage service endpoint is enabled for critical subnets
          storage_endpoint=$(echo "$SERVICE_ENDPOINTS" | jq '[.[] | select(.service=="Microsoft.Storage")] | length')
          if [ "$storage_endpoint" -eq 0 ]; then
            log "WARNING" "Critical subnet $SUBNET_NAME does not have Storage service endpoint enabled!"
            echo "{\"vnet\":\"$VNET_NAME\",\"subnet\":\"$SUBNET_NAME\",\"issue\":\"Storage service endpoint not enabled\",\"severity\":\"Medium\"}" >> "$TEMP_DIR/issues.json"
          fi
        fi
      done
    done
  done
  
  return 0
}

# Function to generate final report
generate_report() {
  log "INFO" "Generating final network isolation validation report..."
  
  # Initialize issues array if it doesn't exist
  if [ ! -f "$TEMP_DIR/issues.json" ]; then
    echo "[]" > "$TEMP_DIR/issues.json"
  else
    # Convert individual JSON objects to an array
    echo "[" > "$TEMP_DIR/issues_array.json"
    cat "$TEMP_DIR/issues.json" | sed 's/}{/},{/g' >> "$TEMP_DIR/issues_array.json"
    echo "]" >> "$TEMP_DIR/issues_array.json"
    mv "$TEMP_DIR/issues_array.json" "$TEMP_DIR/issues.json"
  fi
  
  # Count issues by severity
  CRITICAL_COUNT=$(cat "$TEMP_DIR/issues.json" | jq '[.[] | select(.severity=="Critical")] | length')
  HIGH_COUNT=$(cat "$TEMP_DIR/issues.json" | jq '[.[] | select(.severity=="High")] | length')
  MEDIUM_COUNT=$(cat "$TEMP_DIR/issues.json" | jq '[.[] | select(.severity=="Medium")] | length')
  
  # Determine overall status
  if [ "$CRITICAL_COUNT" -gt 0 ]; then
    OVERALL_STATUS="Failed"
  elif [ "$HIGH_COUNT" -gt 0 ]; then
    OVERALL_STATUS="Warning"
  else
    OVERALL_STATUS="Passed"
  fi
  
  # Create final report
  cat > "$OUTPUT_FILE" << EOF
{
  "reportMetadata": {
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "resourceGroup": "$RESOURCE_GROUP",
    "subscriptionId": "$SUBSCRIPTION_ID"
  },
  "summary": {
    "overallStatus": "$OVERALL_STATUS",
    "issueCount": {
      "critical": $CRITICAL_COUNT,
      "high": $HIGH_COUNT,
      "medium": $MEDIUM_COUNT,
      "total": $(($CRITICAL_COUNT + $HIGH_COUNT + $MEDIUM_COUNT))
    }
  },
  "issues": $(cat "$TEMP_DIR/issues.json"),
  "networkDetails": {
    "virtualNetworks": $(cat "$TEMP_DIR/vnets.json")
  }
}
EOF
  
  log "SUCCESS" "Report generated successfully: $OUTPUT_FILE"
  
  # Print summary
  echo -e "\n${BLUE}=== Network Isolation Validation Summary ===${NC}"
  echo -e "Resource Group: $RESOURCE_GROUP"
  echo -e "Overall Status: $(if [ "$OVERALL_STATUS" == "Passed" ]; then echo -e "${GREEN}PASSED${NC}"; elif [ "$OVERALL_STATUS" == "Warning" ]; then echo -e "${YELLOW}WARNING${NC}"; else echo -e "${RED}FAILED${NC}"; fi)"
  echo -e "Issues Found: $(($CRITICAL_COUNT + $HIGH_COUNT + $MEDIUM_COUNT))"
  echo -e "  - Critical: $CRITICAL_COUNT"
  echo -e "  - High: $HIGH_COUNT"
  echo -e "  - Medium: $MEDIUM_COUNT"
  echo -e "Report Location: $OUTPUT_FILE"
  echo -e "Log File: $LOG_FILE"
  
  return 0
}

# Function to clean up temporary files
cleanup() {
  log "INFO" "Cleaning up temporary files..."
  rm -rf "$TEMP_DIR"
  log "INFO" "Cleanup completed."
}

# Main execution
main() {
  echo -e "${BLUE}=== Azure Network Isolation Validation ===${NC}"
  echo -e "This script validates network isolation for regulated workloads in Azure."
  echo -e "It will check NSGs, firewalls, and network configurations for security issues.\n"
  
  # Initialize issues file
  echo "" > "$TEMP_DIR/issues.json"
  
  # Execute validation steps
  check_prerequisites
  get_virtual_networks
  get_subnets
  validate_nsg_rules
  validate_peering
  validate_firewall_rules
  validate_service_endpoints
  generate_report
  cleanup
  
  # Exit with appropriate code
  if [ "$OVERALL_STATUS" == "Failed" ]; then
    exit 1
  else
    exit 0
  fi
}

# Execute main function
main