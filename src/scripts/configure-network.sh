#!/bin/bash
set -e

# Secure Network Configuration Script for Regulated Industries
# This script configures network segmentation, security groups, and validates compliance
# for regulated workloads including SWIFT SCR and PCI-DSS environments.

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration file paths
CONFIG_FILE="./config/network/network_config.json"
COMPLIANCE_CONFIG="./config/compliance/network_requirements.json"

# Log file
LOG_FILE="./logs/network_configuration_$(date +%Y%m%d_%H%M%S).log"
mkdir -p ./logs

# Function to log messages
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
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
    
    # Check if user is logged in to Azure
    if ! az account show &> /dev/null; then
        log "ERROR" "Not logged in to Azure. Please run 'az login' first."
        exit 1
    }
    
    # Check if configuration files exist
    if [ ! -f "$CONFIG_FILE" ]; then
        log "ERROR" "Configuration file not found: $CONFIG_FILE"
        exit 1
    }
    
    if [ ! -f "$COMPLIANCE_CONFIG" ]; then
        log "ERROR" "Compliance configuration file not found: $COMPLIANCE_CONFIG"
        exit 1
    }
    
    log "INFO" "${GREEN}All prerequisites met.${NC}"
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --subscription)
                SUBSCRIPTION_ID="$2"
                shift 2
                ;;
            --resource-group)
                RESOURCE_GROUP="$2"
                shift 2
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --validate-only)
                VALIDATE_ONLY=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Set defaults if not provided
    SUBSCRIPTION_ID=${SUBSCRIPTION_ID:-$(az account show --query id -o tsv)}
    ENVIRONMENT=${ENVIRONMENT:-"production"}
    VALIDATE_ONLY=${VALIDATE_ONLY:-false}
    FORCE=${FORCE:-false}
    
    # Validate required parameters
    if [ -z "$RESOURCE_GROUP" ]; then
        log "ERROR" "Resource group is required. Use --resource-group parameter."
        exit 1
    fi
}

# Function to show help
show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --subscription ID        Azure subscription ID"
    echo "  --resource-group NAME    Resource group name (required)"
    echo "  --environment ENV        Environment (default: production)"
    echo "  --validate-only          Validate configuration without applying changes"
    echo "  --force                  Force configuration without confirmation"
    echo "  --help                   Show this help message"
}

# Function to load configuration
load_configuration() {
    log "INFO" "Loading network configuration for ${BLUE}$ENVIRONMENT${NC} environment..."
    
    # Set Azure subscription
    az account set --subscription "$SUBSCRIPTION_ID"
    
    # Load network configuration based on environment
    NETWORK_CONFIG=$(jq ".environments.$ENVIRONMENT" "$CONFIG_FILE")
    if [ "$NETWORK_CONFIG" == "null" ]; then
        log "ERROR" "Environment '$ENVIRONMENT' not found in configuration file."
        exit 1
    fi
    
    # Extract configuration values
    VNET_NAME=$(echo "$NETWORK_CONFIG" | jq -r '.vnet_name')
    VNET_ADDRESS_SPACE=$(echo "$NETWORK_CONFIG" | jq -r '.address_space')
    LOCATION=$(echo "$NETWORK_CONFIG" | jq -r '.location')
    
    # Extract subnet configurations
    SUBNETS=$(echo "$NETWORK_CONFIG" | jq -r '.subnets')
    
    log "INFO" "Configuration loaded successfully."
    log "INFO" "Virtual Network: ${BLUE}$VNET_NAME${NC}"
    log "INFO" "Address Space: ${BLUE}$VNET_ADDRESS_SPACE${NC}"
    log "INFO" "Location: ${BLUE}$LOCATION${NC}"
}

# Function to create or update virtual network
configure_virtual_network() {
    log "INFO" "Configuring virtual network..."
    
    # Check if virtual network exists
    if az network vnet show --name "$VNET_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log "INFO" "Virtual network ${BLUE}$VNET_NAME${NC} already exists. Updating configuration..."
        
        # Update virtual network
        az network vnet update \
            --name "$VNET_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --address-prefixes "$VNET_ADDRESS_SPACE" \
            --output none
    else
        log "INFO" "Creating virtual network ${BLUE}$VNET_NAME${NC}..."
        
        # Create virtual network
        az network vnet create \
            --name "$VNET_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --address-prefixes "$VNET_ADDRESS_SPACE" \
            --output none
    fi
    
    log "INFO" "${GREEN}Virtual network configured successfully.${NC}"
}

# Function to configure subnets
configure_subnets() {
    log "INFO" "Configuring subnets..."
    
    # Get number of subnets
    SUBNET_COUNT=$(echo "$SUBNETS" | jq 'length')
    
    for ((i=0; i<SUBNET_COUNT; i++)); do
        SUBNET=$(echo "$SUBNETS" | jq -r ".[$i]")
        SUBNET_NAME=$(echo "$SUBNET" | jq -r '.name')
        SUBNET_PREFIX=$(echo "$SUBNET" | jq -r '.address_prefix')
        SUBNET_TYPE=$(echo "$SUBNET" | jq -r '.type')
        
        log "INFO" "Configuring subnet ${BLUE}$SUBNET_NAME${NC} ($SUBNET_TYPE)..."
        
        # Check if subnet exists
        if az network vnet subnet show --name "$SUBNET_NAME" --vnet-name "$VNET_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
            log "INFO" "Subnet ${BLUE}$SUBNET_NAME${NC} already exists. Updating configuration..."
            
            # Update subnet
            az network vnet subnet update \
                --name "$SUBNET_NAME" \
                --vnet-name "$VNET_NAME" \
                --resource-group "$RESOURCE_GROUP" \
                --address-prefix "$SUBNET_PREFIX" \
                --output none
        else
            log "INFO" "Creating subnet ${BLUE}$SUBNET_NAME${NC}..."
            
            # Create subnet
            az network vnet subnet create \
                --name "$SUBNET_NAME" \
                --vnet-name "$VNET_NAME" \
                --resource-group "$RESOURCE_GROUP" \
                --address-prefix "$SUBNET_PREFIX" \
                --output none
        fi
        
        # Configure service endpoints if specified
        SERVICE_ENDPOINTS=$(echo "$SUBNET" | jq -r '.service_endpoints[]?' 2>/dev/null)
        if [ -n "$SERVICE_ENDPOINTS" ] && [ "$SERVICE_ENDPOINTS" != "null" ]; then
            log "INFO" "Configuring service endpoints for ${BLUE}$SUBNET_NAME${NC}..."
            
            # Convert service endpoints to array
            ENDPOINT_ARRAY=()
            while IFS= read -r endpoint; do
                ENDPOINT_ARRAY+=("$endpoint")
            done <<< "$SERVICE_ENDPOINTS"
            
            # Update subnet with service endpoints
            az network vnet subnet update \
                --name "$SUBNET_NAME" \
                --vnet-name "$VNET_NAME" \
                --resource-group "$RESOURCE_GROUP" \
                --service-endpoints "${ENDPOINT_ARRAY[@]}" \
                --output none
        fi
    done
    
    log "INFO" "${GREEN}Subnets configured successfully.${NC}"
}

# Function to configure network security groups
configure_network_security_groups() {
    log "INFO" "Configuring network security groups..."
    
    # Get number of subnets
    SUBNET_COUNT=$(echo "$SUBNETS" | jq 'length')
    
    for ((i=0; i<SUBNET_COUNT; i++)); do
        SUBNET=$(echo "$SUBNETS" | jq -r ".[$i]")
        SUBNET_NAME=$(echo "$SUBNET" | jq -r '.name')
        SUBNET_TYPE=$(echo "$SUBNET" | jq -r '.type')
        NSG_NAME="${SUBNET_NAME}-nsg"
        
        log "INFO" "Configuring NSG for ${BLUE}$SUBNET_NAME${NC}..."
        
        # Create or update NSG
        if az network nsg show --name "$NSG_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
            log "INFO" "NSG ${BLUE}$NSG_NAME${NC} already exists."
        else
            log "INFO" "Creating NSG ${BLUE}$NSG_NAME${NC}..."
            
            # Create NSG
            az network nsg create \
                --name "$NSG_NAME" \
                --resource-group "$RESOURCE_GROUP" \
                --location "$LOCATION" \
                --output none
        fi
        
        # Configure NSG rules based on subnet type
        configure_nsg_rules "$NSG_NAME" "$SUBNET_TYPE"
        
        # Associate NSG with subnet
        log "INFO" "Associating NSG with subnet ${BLUE}$SUBNET_NAME${NC}..."
        az network vnet subnet update \
            --name "$SUBNET_NAME" \
            --vnet-name "$VNET_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --network-security-group "$NSG_NAME" \
            --output none
    done
    
    log "INFO" "${GREEN}Network security groups configured successfully.${NC}"
}

# Function to configure NSG rules based on subnet type
configure_nsg_rules() {
    local nsg_name=$1
    local subnet_type=$2
    
    log "INFO" "Configuring security rules for ${BLUE}$nsg_name${NC} ($subnet_type)..."
    
    # Clear existing rules (except default rules)
    local existing_rules=$(az network nsg rule list --nsg-name "$nsg_name" --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    for rule in $existing_rules; do
        if [[ "$rule" != "AllowVnetInBound" && "$rule" != "AllowAzureLoadBalancerInBound" && "$rule" != "DenyAllInBound" && "$rule" != "AllowVnetOutBound" && "$rule" != "AllowInternetOutBound" && "$rule" != "DenyAllOutBound" ]]; then
            log "INFO" "Removing rule ${YELLOW}$rule${NC}..."
            az network nsg rule delete \
                --name "$rule" \
                --nsg-name "$nsg_name" \
                --resource-group "$RESOURCE_GROUP" \
                --output none
        fi
    done
    
    # Load rules based on subnet type from compliance configuration
    local rules=$(jq -r ".subnet_types.$subnet_type.rules" "$COMPLIANCE_CONFIG")
    
    if [ "$rules" == "null" ]; then
        log "WARNING" "No predefined rules found for subnet type: ${YELLOW}$subnet_type${NC}"
        return
    fi
    
    # Get number of rules
    local rule_count=$(echo "$rules" | jq 'length')
    
    for ((j=0; j<rule_count; j++)); do
        local rule=$(echo "$rules" | jq -r ".[$j]")
        local rule_name=$(echo "$rule" | jq -r '.name')
        local priority=$(echo "$rule" | jq -r '.priority')
        local direction=$(echo "$rule" | jq -r '.direction')
        local access=$(echo "$rule" | jq -r '.access')
        local protocol=$(echo "$rule" | jq -r '.protocol')
        local source_port_range=$(echo "$rule" | jq -r '.source_port_range')
        local destination_port_range=$(echo "$rule" | jq -r '.destination_port_range')
        local source_address_prefix=$(echo "$rule" | jq -r '.source_address_prefix')
        local destination_address_prefix=$(echo "$rule" | jq -r '.destination_address_prefix')
        
        log "INFO" "Adding rule ${BLUE}$rule_name${NC} to NSG ${BLUE}$nsg_name${NC}..."
        
        # Create NSG rule
        az network nsg rule create \
            --name "$rule_name" \
            --nsg-name "$nsg_name" \
            --resource-group "$RESOURCE_GROUP" \
            --priority "$priority" \
            --direction "$direction" \
            --access "$access" \
            --protocol "$protocol" \
            --source-port-range "$source_port_range" \
            --destination-port-range "$destination_port_range" \
            --source-address-prefix "$source_address_prefix" \
            --destination-address-prefix "$destination_address_prefix" \
            --output none
    done
}

# Function to configure route tables
configure_route_tables() {
    log "INFO" "Configuring route tables..."
    
    # Get number of subnets
    SUBNET_COUNT=$(echo "$SUBNETS" | jq 'length')
    
    for ((i=0; i<SUBNET_COUNT; i++)); do
        SUBNET=$(echo "$SUBNETS" | jq -r ".[$i]")
        SUBNET_NAME=$(echo "$SUBNET" | jq -r '.name')
        SUBNET_TYPE=$(echo "$SUBNET" | jq -r '.type')
        ROUTE_TABLE_NAME="${SUBNET_NAME}-rt"
        
        # Check if subnet needs custom routing
        NEEDS_ROUTING=$(jq -r ".subnet_types.$SUBNET_TYPE.custom_routing" "$COMPLIANCE_CONFIG")
        
        if [ "$NEEDS_ROUTING" == "true" ]; then
            log "INFO" "Configuring route table for ${BLUE}$SUBNET_NAME${NC}..."
            
            # Create or update route table
            if az network route-table show --name "$ROUTE_TABLE_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
                log "INFO" "Route table ${BLUE}$ROUTE_TABLE_NAME${NC} already exists."
            else
                log "INFO" "Creating route table ${BLUE}$ROUTE_TABLE_NAME${NC}..."
                
                # Create route table
                az network route-table create \
                    --name "$ROUTE_TABLE_NAME" \
                    --resource-group "$RESOURCE_GROUP" \
                    --location "$LOCATION" \
                    --disable-bgp-route-propagation true \
                    --output none
            fi
            
            # Configure routes based on subnet type
            configure_routes "$ROUTE_TABLE_NAME" "$SUBNET_TYPE"
            
            # Associate route table with subnet
            log "INFO" "Associating route table with subnet ${BLUE}$SUBNET_NAME${NC}..."
            az network vnet subnet update \
                --name "$SUBNET_NAME" \
                --vnet-name "$VNET_NAME" \
                --resource-group "$RESOURCE_GROUP" \
                --route-table "$ROUTE_TABLE_NAME" \
                --output none
        fi
    done
    
    log "INFO" "${GREEN}Route tables configured successfully.${NC}"
}

# Function to configure routes based on subnet type
configure_routes() {
    local route_table_name=$1
    local subnet_type=$2
    
    log "INFO" "Configuring routes for ${BLUE}$route_table_name${NC} ($subnet_type)..."
    
    # Clear existing routes
    local existing_routes=$(az network route-table route list --route-table-name "$route_table_name" --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    for route in $existing_routes; do
        log "INFO" "Removing route ${YELLOW}$route${NC}..."
        az network route-table route delete \
            --name "$route" \
            --route-table-name "$route_table_name" \
            --resource-group "$RESOURCE_GROUP" \
            --output none
    done
    
    # Load routes based on subnet type from compliance configuration
    local routes=$(jq -r ".subnet_types.$subnet_type.routes" "$COMPLIANCE_CONFIG")
    
    if [ "$routes" == "null" ]; then
        log "WARNING" "No predefined routes found for subnet type: ${YELLOW}$subnet_type${NC}"
        return
    fi
    
    # Get number of routes
    local route_count=$(echo "$routes" | jq 'length')
    
    for ((j=0; j<route_count; j++)); do
        local route=$(echo "$routes" | jq -r ".[$j]")
        local route_name=$(echo "$route" | jq -r '.name')
        local address_prefix=$(echo "$route" | jq -r '.address_prefix')
        local next_hop_type=$(echo "$route" | jq -r '.next_hop_type')
        local next_hop_ip_address=$(echo "$route" | jq -r '.next_hop_ip_address // ""')
        
        log "INFO" "Adding route ${BLUE}$route_name${NC} to route table ${BLUE}$route_table_name${NC}..."
        
        # Create route
        if [ -n "$next_hop_ip_address" ] && [ "$next_hop_ip_address" != "null" ]; then
            az network route-table route create \
                --name "$route_name" \
                --route-table-name "$route_table_name" \
                --resource-group "$RESOURCE_GROUP" \
                --address-prefix "$address_prefix" \
                --next-hop-type "$next_hop_type" \
                --next-hop-ip-address "$next_hop_ip_address" \
                --output none
        else
            az network route-table route create \
                --name "$route_name" \
                --route-table-name "$route_table_name" \
                --resource-group "$RESOURCE_GROUP" \
                --address-prefix "$address_prefix" \
                --next-hop-type "$next_hop_type" \
                --output none
        fi
    done
}

# Function to validate network configuration
validate_network_configuration() {
    log "INFO" "Validating network configuration against compliance requirements..."
    
    # Load compliance requirements
    local requirements=$(jq -r '.compliance_requirements' "$COMPLIANCE_CONFIG")
    local requirement_count=$(echo "$requirements" | jq 'length')
    local validation_errors=0
    
    for ((i=0; i<requirement_count; i++)); do
        local requirement=$(echo "$requirements" | jq -r ".[$i]")
        local req_name=$(echo "$requirement" | jq -r '.name')
        local req_type=$(echo "$requirement" | jq -r '.type')
        
        log "INFO" "Validating requirement: ${BLUE}$req_name${NC}..."
        
        case "$req_type" in
            "subnet_isolation")
                local source_subnet=$(echo "$requirement" | jq -r '.source_subnet')
                local destination_subnet=$(echo "$requirement" | jq -r '.destination_subnet')
                local expected_access=$(echo "$requirement" | jq -r '.expected_access')
                
                # Validate subnet isolation
                if validate_subnet_isolation "$source_subnet" "$destination_subnet" "$expected_access"; then
                    log "INFO" "${GREEN}✓ Validation passed: $req_name${NC}"
                else
                    log "ERROR" "${RED}✗ Validation failed: $req_name${NC}"
                    validation_errors=$((validation_errors + 1))
                fi
                ;;
                
            "internet_access")
                local subnet=$(echo "$requirement" | jq -r '.subnet')
                local expected_access=$(echo "$requirement" | jq -r '.expected_access')
                
                # Validate internet access
                if validate_internet_access "$subnet" "$expected_access"; then
                    log "INFO" "${GREEN}✓ Validation passed: $req_name${NC}"
                else
                    log "ERROR" "${RED}✗ Validation failed: $req_name${NC}"
                    validation_errors=$((validation_errors + 1))
                fi
                ;;
                
            "service_endpoints")
                local subnet=$(echo "$requirement" | jq -r '.subnet')
                local required_endpoints=$(echo "$requirement" | jq -r '.required_endpoints')
                
                # Validate service endpoints
                if validate_service_endpoints "$subnet" "$required_endpoints"; then
                    log "INFO" "${GREEN}✓ Validation passed: $req_name${NC}"
                else
                    log "ERROR" "${RED}✗ Validation failed: $req_name${NC}"
                    validation_errors=$((validation_errors + 1))
                fi
                ;;
                
            *)
                log "WARNING" "Unknown validation type: ${YELLOW}$req_type${NC}"
                ;;
        esac
    done
    
    if [ $validation_errors -eq 0 ]; then
        log "INFO" "${GREEN}All validation checks passed successfully.${NC}"
        return 0
    else
        log "ERROR" "${RED}Validation failed with $validation_errors errors.${NC}"
        return 1
    fi
}

# Function to validate subnet isolation
validate_subnet_isolation() {
    local source_subnet=$1
    local destination_subnet=$2
    local expected_access=$3
    
    # Implementation of subnet isolation validation
    # This would typically involve checking NSG rules and route tables
    
    # For demonstration purposes, we'll simulate the validation
    local source_subnet_id=$(az network vnet subnet show --name "$source_subnet" --vnet-name "$VNET_NAME" --resource-group "$RESOURCE_GROUP" --query id -o tsv 2>/dev/null)
    local destination_subnet_id=$(az network vnet subnet show --name "$destination_subnet" --vnet-name "$VNET_NAME" --resource-group "$RESOURCE_GROUP" --query id -o tsv 2>/dev/null)
    
    if [ -z "$source_subnet_id" ] || [ -z "$destination_subnet_id" ]; then
        log "ERROR" "Subnet not found: ${RED}$source_subnet${NC} or ${RED}$destination_subnet${NC}"
        return 1
    fi
    
    # Check NSG rules
    local source_nsg="${source_subnet}-nsg"
    local destination_nsg="${destination_subnet}-nsg"
    
    # Simplified validation logic - in a real implementation, this would be more comprehensive
    if [ "$expected_access" == "allowed" ]; then
        # Check if there's no explicit deny rule
        local deny_rule=$(az network nsg rule list --nsg-name "$destination_nsg" --resource-group "$RESOURCE_GROUP" --query "[?access=='Deny' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='VirtualNetwork')].name" -o tsv)
        
        if [ -n "$deny_rule" ]; then
            log "ERROR" "Found deny rule ${RED}$deny_rule${NC} that blocks access from $source_subnet to $destination_subnet"
            return 1
        fi
        
        return 0
    else
        # Check if there's an explicit deny rule
        local deny_rule=$(az network nsg rule list --nsg-name "$destination_nsg" --resource-group "$RESOURCE_GROUP" --query "[?access=='Deny' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='VirtualNetwork')].name" -o tsv)
        
        if [ -n "$deny_rule" ]; then
            return 0
        else
            log "ERROR" "No deny rule found to block access from $source_subnet to $destination_subnet"
            return 1
        fi
    fi
}

# Function to validate internet access
validate_internet_access() {
    local subnet=$1
    local expected_access=$2
    
    # Implementation of internet access validation
    # This would typically involve checking NSG rules and route tables
    
    # For demonstration purposes, we'll simulate the validation
    local subnet_id=$(az network vnet subnet show --name "$subnet" --vnet-name "$VNET_NAME" --resource-group "$RESOURCE_GROUP" --query id -o tsv 2>/dev/null)
    
    if [ -z "$subnet_id" ]; then
        log "ERROR" "Subnet not found: ${RED}$subnet${NC}"
        return 1
    fi
    
    # Check NSG rules
    local nsg="${subnet}-nsg"
    
    # Simplified validation logic
    if [ "$expected_access" == "allowed" ]; then
        # Check if there's no explicit deny rule for internet
        local deny_rule=$(az network nsg rule list --nsg-name "$nsg" --resource-group "$RESOURCE_GROUP" --query "[?access=='Deny' && (destinationAddressPrefix=='Internet' || destinationAddressPrefix=='*')].name" -o tsv)
        
        if [ -n "$deny_rule" ]; then
            log "ERROR" "Found deny rule ${RED}$deny_rule${NC} that blocks internet access from $subnet"
            return 1
        fi
        
        return 0
    else
        # Check if there's an explicit deny rule for internet
        local deny_rule=$(az network nsg rule list --nsg-name "$nsg" --resource-group "$RESOURCE_GROUP" --query "[?access=='Deny' && (destinationAddressPrefix=='Internet' || destinationAddressPrefix=='*')].name" -o tsv)
        
        if [ -n "$deny_rule" ]; then
            return 0
        else
            log "ERROR" "No deny rule found to block internet access from $subnet"
            return 1
        fi
    fi
}

# Function to validate service endpoints
validate_service_endpoints() {
    local subnet=$1
    local required_endpoints=$2
    
    # Implementation of service endpoints validation
    
    # For demonstration purposes, we'll simulate the validation
    local subnet_id=$(az network vnet subnet show --name "$subnet" --vnet-name "$VNET_NAME" --resource-group "$RESOURCE_GROUP" --query id -o tsv 2>/dev/null)
    
    if [ -z "$subnet_id" ]; then
        log "ERROR" "Subnet not found: ${RED}$subnet${NC}"
        return 1
    fi
    
    # Get configured service endpoints
    local configured_endpoints=$(az network vnet subnet show --name "$subnet" --vnet-name "$VNET_NAME" --resource-group "$RESOURCE_GROUP" --query "serviceEndpoints[].service" -o tsv)
    
    # Convert required_endpoints to array
    local required_array=()
    while IFS= read -r endpoint; do
        required_array+=("$endpoint")
    done <<< "$(echo "$required_endpoints" | jq -r '.[]')"
    
    # Check if all required endpoints are configured
    for endpoint in "${required_array[@]}"; do
        if ! echo "$configured_endpoints" | grep -q "$endpoint"; then
            log "ERROR" "Required service endpoint ${RED}$endpoint${NC} not configured for subnet $subnet"
            return 1
        fi
    done
    
    return 0
}

# Function to enable flow logs
enable_flow_logs() {
    log "INFO" "Enabling network flow logs..."
    
    # Check if storage account exists for flow logs
    local storage_account="${VNET_NAME}flowlogs"
    storage_account=$(echo "$storage_account" | tr '[:upper:]' '[:lower:]' | tr -d '-')
    
    if ! az storage account show --name "$storage_account" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log "INFO" "Creating storage account ${BLUE}$storage_account${NC} for flow logs..."
        
        # Create storage account
        az storage account create \
            --name "$storage_account" \
            --resource-group "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --sku "Standard_LRS" \
            --kind "StorageV2" \
            --https-only true \
            --min-tls-version "TLS1_2" \
            --output none
    fi
    
    # Get storage account ID
    local storage_id=$(az storage account show --name "$storage_account" --resource-group "$RESOURCE_GROUP" --query id -o tsv)
    
    # Check if network watcher exists
    local network_watcher_name="NetworkWatcher_${LOCATION}"
    local network_watcher_group="NetworkWatcherRG"
    
    if ! az group show --name "$network_watcher_group" &> /dev/null; then
        log "INFO" "Creating resource group ${BLUE}$network_watcher_group${NC} for network watcher..."
        
        # Create resource group
        az group create \
            --name "$network_watcher_group" \
            --location "$LOCATION" \
            --output none
    fi
    
    if ! az network watcher show --name "$network_watcher_name" --resource-group "$network_watcher_group" &> /dev/null; then
        log "INFO" "Creating network watcher ${BLUE}$network_watcher_name${NC}..."
        
        # Create network watcher
        az network watcher configure \
            --resource-group "$network_watcher_group" \
            --locations "$LOCATION" \
            --enabled true \
            --output none
    fi
    
    # Enable flow logs for each NSG
    local nsgs=$(az network nsg list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv)
    
    for nsg in $nsgs; do
        log "INFO" "Enabling flow logs for NSG ${BLUE}$nsg${NC}..."
        
        # Get NSG ID
        local nsg_id=$(az network nsg show --name "$nsg" --resource-group "$RESOURCE_GROUP" --query id -o tsv)
        
        # Enable flow logs
        az network watcher flow-log create \
            --name "${nsg}-flowlog" \
            --resource-group "$network_watcher_group" \
            --nsg "$nsg_id" \
            --storage-account "$storage_id" \
            --retention 90 \
            --enabled true \
            --format JSON \
            --interval 10 \
            --output none
    done
    
    log "INFO" "${GREEN}Flow logs enabled successfully.${NC}"
}

# Main function
main() {
    echo -e "${BLUE}=== Secure Network Configuration Script ===${NC}"
    echo -e "${BLUE}=== For Regulated Industries ===${NC}"
    echo ""
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Check prerequisites
    check_prerequisites
    
    # Load configuration
    load_configuration
    
    # If validate-only flag is set, only validate the configuration
    if [ "$VALIDATE_ONLY" == "true" ]; then
        log "INFO" "Running in validation-only mode..."
        validate_network_configuration
        exit $?
    fi
    
    # Confirm configuration
    if [ "$FORCE" != "true" ]; then
        echo ""
        echo -e "${YELLOW}You are about to configure the network for ${BLUE}$ENVIRONMENT${YELLOW} environment.${NC}"
        echo -e "${YELLOW}This will create or update the following resources:${NC}"
        echo -e "  - Virtual Network: ${BLUE}$VNET_NAME${NC}"
        echo -e "  - Subnets: $(echo "$SUBNETS" | jq -r '.[].name' | tr '\n' ', ' | sed 's/,$//')"
        echo -e "  - Network Security Groups"
        echo -e "  - Route Tables"
        echo -e "  - Flow Logs"
        echo ""
        read -p "Do you want to continue? (y/n): " confirm
        
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            log "INFO" "Operation cancelled by user."
            exit 0
        fi
    fi
    
    # Configure virtual network
    configure_virtual_network
    
    # Configure subnets
    configure_subnets
    
    # Configure network security groups
    configure_network_security_groups
    
    # Configure route tables
    configure_route_tables
    
    # Enable flow logs
    enable_flow_logs
    
    # Validate network configuration
    validate_network_configuration
    
    log "INFO" "${GREEN}Network configuration completed successfully.${NC}"
}

# Run main function
main "$@"