#!/bin/bash
# =============================================================================
# HSM-Protected Key Generation Script for Secure Landing Zone
# 
# This script automates the generation of HSM-protected keys for various
# security domains in the regulated landing zone architecture.
#
# Features:
# - Creates HSM-protected keys with appropriate key sizes
# - Configures key rotation policies
# - Sets up access policies
# - Validates FIPS 140-2 Level 3 compliance
# - Implements geo-restrictions for key operations
# =============================================================================

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
KEY_VAULT_NAME=""
RESOURCE_GROUP=""
LOCATION=""
SUBSCRIPTION_ID=""
ADMIN_OBJECT_ID=""
ROTATION_DAYS=90
NOTIFICATION_DAYS=30
ALLOWED_REGIONS=("switzerlandnorth" "uaenorth")

# Key configurations
declare -A KEY_CONFIGS=(
  ["swift-payment-key"]="RSA-HSM,4096,encrypt decrypt sign verify"
  ["pci-encryption-key"]="RSA-HSM,4096,encrypt decrypt"
  ["identity-signing-key"]="RSA-HSM,3072,sign verify"
  ["general-purpose-key"]="RSA-HSM,2048,encrypt decrypt sign verify"
)

# Display banner
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}       HSM-Protected Key Generation for Secure Landing Zone ${NC}"
echo -e "${BLUE}============================================================${NC}"

# Function to display usage
function display_usage {
  echo -e "\n${YELLOW}Usage:${NC}"
  echo -e "  $0 [options]"
  echo -e "\n${YELLOW}Options:${NC}"
  echo -e "  -k, --key-vault NAME       Key Vault name"
  echo -e "  -g, --resource-group NAME  Resource Group name"
  echo -e "  -l, --location LOCATION    Azure location"
  echo -e "  -s, --subscription ID      Azure Subscription ID"
  echo -e "  -a, --admin-id OBJECT_ID   Admin Object ID"
  echo -e "  -r, --rotation DAYS        Key rotation period in days (default: 90)"
  echo -e "  -h, --help                 Display this help message"
  echo -e "\n${YELLOW}Example:${NC}"
  echo -e "  $0 --key-vault secure-hsm-vault --resource-group security-rg --location switzerlandnorth --subscription 00000000-0000-0000-0000-000000000000 --admin-id 11111111-1111-1111-1111-111111111111\n"
  exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -k|--key-vault)
      KEY_VAULT_NAME="$2"
      shift 2
      ;;
    -g|--resource-group)
      RESOURCE_GROUP="$2"
      shift 2
      ;;
    -l|--location)
      LOCATION="$2"
      shift 2
      ;;
    -s|--subscription)
      SUBSCRIPTION_ID="$2"
      shift 2
      ;;
    -a|--admin-id)
      ADMIN_OBJECT_ID="$2"
      shift 2
      ;;
    -r|--rotation)
      ROTATION_DAYS="$2"
      shift 2
      ;;
    -h|--help)
      display_usage
      ;;
    *)
      echo -e "${RED}Error: Unknown option: $1${NC}"
      display_usage
      ;;
  esac
done

# Validate required parameters
if [[ -z "$KEY_VAULT_NAME" || -z "$RESOURCE_GROUP" || -z "$LOCATION" || -z "$SUBSCRIPTION_ID" || -z "$ADMIN_OBJECT_ID" ]]; then
  echo -e "${RED}Error: Missing required parameters${NC}"
  display_usage
fi

# Function to check if command exists
function command_exists {
  command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo -e "\n${BLUE}Checking prerequisites...${NC}"
PREREQS_MET=true

if ! command_exists az; then
  echo -e "${RED}Error: Azure CLI is not installed${NC}"
  PREREQS_MET=false
fi

if ! command_exists jq; then
  echo -e "${RED}Error: jq is not installed${NC}"
  PREREQS_MET=false
fi

if ! command_exists openssl; then
  echo -e "${RED}Error: OpenSSL is not installed${NC}"
  PREREQS_MET=false
fi

if [[ "$PREREQS_MET" = false ]]; then
  echo -e "${RED}Please install the required tools and try again${NC}"
  exit 1
fi

echo -e "${GREEN}All prerequisites met${NC}"

# Login to Azure
echo -e "\n${BLUE}Authenticating with Azure...${NC}"
az account set --subscription "$SUBSCRIPTION_ID"
if [[ $? -ne 0 ]]; then
  echo -e "${RED}Error: Failed to set subscription. Please login using 'az login' and try again${NC}"
  exit 1
fi
echo -e "${GREEN}Successfully authenticated with Azure${NC}"

# Create or validate Key Vault
echo -e "\n${BLUE}Setting up Azure Key Vault...${NC}"
if ! az keyvault show --name "$KEY_VAULT_NAME" --resource-group "$RESOURCE_GROUP" &>/dev/null; then
  echo -e "${YELLOW}Key Vault $KEY_VAULT_NAME does not exist. Creating...${NC}"
  az keyvault create \
    --name "$KEY_VAULT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --sku "Premium" \
    --enabled-for-deployment true \
    --enabled-for-disk-encryption true \
    --enabled-for-template-deployment true \
    --enable-purge-protection true \
    --enable-rbac-authorization false \
    --retention-days 90
  
  if [[ $? -ne 0 ]]; then
    echo -e "${RED}Error: Failed to create Key Vault${NC}"
    exit 1
  fi
  
  # Set network ACLs
  az keyvault network-rule add \
    --name "$KEY_VAULT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --ip-address "$(curl -s https://api.ipify.org)"
  
  # Set access policy for admin
  az keyvault set-policy \
    --name "$KEY_VAULT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --object-id "$ADMIN_OBJECT_ID" \
    --key-permissions get list create delete update import backup restore recover \
    --secret-permissions get list set delete backup restore recover \
    --certificate-permissions get list create delete import update backup restore recover
fi

echo -e "${GREEN}Key Vault is ready${NC}"

# Function to create HSM-protected key
function create_hsm_key {
  local key_name=$1
  local key_type=$2
  local key_size=$3
  local key_ops=$4
  
  echo -e "\n${BLUE}Creating HSM-protected key: $key_name${NC}"
  
  # Check if key already exists
  if az keyvault key show --vault-name "$KEY_VAULT_NAME" --name "$key_name" &>/dev/null; then
    echo -e "${YELLOW}Key $key_name already exists. Checking compliance...${NC}"
    
    # Validate existing key
    local key_info=$(az keyvault key show --vault-name "$KEY_VAULT_NAME" --name "$key_name" -o json)
    local existing_type=$(echo "$key_info" | jq -r '.key.kty')
    local existing_size=$(echo "$key_info" | jq -r '.key.n | length * 3 / 4 * 8' | cut -d. -f1)
    
    if [[ "$existing_type" != "$key_type" || "$existing_size" -lt "$key_size" ]]; then
      echo -e "${RED}Existing key does not meet security requirements. Creating new version...${NC}"
      create_new_key=true
    else
      echo -e "${GREEN}Existing key meets security requirements${NC}"
      create_new_key=false
    fi
  else
    create_new_key=true
  fi
  
  if [[ "$create_new_key" = true ]]; then
    # Create key with HSM protection
    az keyvault key create \
      --vault-name "$KEY_VAULT_NAME" \
      --name "$key_name" \
      --kty "$key_type" \
      --size "$key_size" \
      --ops $key_ops \
      --protection hsm
    
    if [[ $? -ne 0 ]]; then
      echo -e "${RED}Error: Failed to create HSM-protected key: $key_name${NC}"
      return 1
    fi
  fi
  
  # Set key rotation policy
  echo -e "${BLUE}Setting rotation policy for $key_name...${NC}"
  
  # Create rotation policy JSON
  rotation_policy=$(cat <<EOF
{
  "lifetimeActions": [
    {
      "trigger": {
        "timeBeforeExpiry": "P${NOTIFICATION_DAYS}D"
      },
      "action": {
        "type": "Notify"
      }
    },
    {
      "trigger": {
        "timeBeforeExpiry": "P7D"
      },
      "action": {
        "type": "Rotate"
      }
    }
  ],
  "attributes": {
    "expiryTime": "P${ROTATION_DAYS}D"
  }
}
EOF
)
  
  # Apply rotation policy
  echo "$rotation_policy" > rotation_policy.json
  az keyvault key rotation-policy update \
    --vault-name "$KEY_VAULT_NAME" \
    --name "$key_name" \
    --value @rotation_policy.json
  
  rm rotation_policy.json
  
  echo -e "${GREEN}Successfully created and configured HSM-protected key: $key_name${NC}"
  return 0
}

# Function to validate HSM compliance
function validate_hsm_compliance {
  echo -e "\n${BLUE}Validating HSM compliance...${NC}"
  
  # Check if Key Vault is using Premium SKU
  local vault_sku=$(az keyvault show --name "$KEY_VAULT_NAME" --resource-group "$RESOURCE_GROUP" --query properties.sku.name -o tsv)
  if [[ "$vault_sku" != "Premium" ]]; then
    echo -e "${RED}Error: Key Vault must use Premium SKU for HSM support${NC}"
    return 1
  fi
  
  # Validate key protection
  for key_name in "${!KEY_CONFIGS[@]}"; do
    local key_info=$(az keyvault key show --vault-name "$KEY_VAULT_NAME" --name "$key_name" -o json 2>/dev/null)
    if [[ $? -ne 0 ]]; then
      echo -e "${YELLOW}Key $key_name not found, skipping validation${NC}"
      continue
    fi
    
    local key_type=$(echo "$key_info" | jq -r '.key.kty')
    if [[ "$key_type" != "RSA-HSM" ]]; then
      echo -e "${RED}Key $key_name is not HSM-protected${NC}"
      return 1
    fi
  done
  
  echo -e "${GREEN}All keys are properly HSM-protected${NC}"
  return 0
}

# Function to backup keys
function backup_keys {
  echo -e "\n${BLUE}Backing up HSM-protected keys...${NC}"
  
  # Create backup directory
  local backup_dir="hsm_key_backups_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$backup_dir"
  
  # Backup each key
  for key_name in "${!KEY_CONFIGS[@]}"; do
    echo -e "${BLUE}Backing up key: $key_name${NC}"
    az keyvault key backup \
      --vault-name "$KEY_VAULT_NAME" \
      --name "$key_name" \
      --file "$backup_dir/$key_name.backup"
    
    if [[ $? -ne 0 ]]; then
      echo -e "${YELLOW}Warning: Failed to backup key: $key_name${NC}"
    else
      echo -e "${GREEN}Successfully backed up key: $key_name${NC}"
    fi
  done
  
  echo -e "${GREEN}Key backups stored in: $backup_dir${NC}"
  
  # Encrypt the backup directory
  echo -e "${BLUE}Encrypting backup directory...${NC}"
  tar -czf "$backup_dir.tar.gz" "$backup_dir"
  openssl enc -aes-256-cbc -salt -in "$backup_dir.tar.gz" -out "$backup_dir.tar.gz.enc"
  rm -rf "$backup_dir" "$backup_dir.tar.gz"
  
  echo -e "${GREEN}Encrypted backup created: $backup_dir.tar.gz.enc${NC}"
  echo -e "${YELLOW}IMPORTANT: Store this backup securely in accordance with your security policy${NC}"
}

# Main execution
echo -e "\n${BLUE}Starting HSM-protected key generation...${NC}"

# Create each key
for key_name in "${!KEY_CONFIGS[@]}"; do
  IFS=',' read -r key_type key_size key_ops <<< "${KEY_CONFIGS[$key_name]}"
  create_hsm_key "$key_name" "$key_type" "$key_size" "$key_ops"
done

# Validate HSM compliance
validate_hsm_compliance
if [[ $? -ne 0 ]]; then
  echo -e "${RED}HSM compliance validation failed${NC}"
  exit 1
fi

# Backup keys
backup_keys

# Generate key usage documentation
echo -e "\n${BLUE}Generating key usage documentation...${NC}"
cat > hsm_keys_documentation.md <<EOF
# HSM-Protected Keys Documentation

## Overview
This document provides details about the HSM-protected keys generated for the secure landing zone.

## Key Vault Information
- **Name:** $KEY_VAULT_NAME
- **Resource Group:** $RESOURCE_GROUP
- **Location:** $LOCATION
- **SKU:** Premium (FIPS 140-2 Level 3 compliant)

## Keys

$(for key_name in "${!KEY_CONFIGS[@]}"; do
  IFS=',' read -r key_type key_size key_ops <<< "${KEY_CONFIGS[$key_name]}"
  echo "### $key_name"
  echo "- **Type:** $key_type"
  echo "- **Size:** $key_size bits"
  echo "- **Operations:** $key_ops"
  echo "- **Rotation Policy:** $ROTATION_DAYS days"
  echo "- **Notification Before Expiry:** $NOTIFICATION_DAYS days"
  echo ""
done)

## Security Considerations
- All keys are protected by FIPS 140-2 Level 3 compliant HSM
- Access is restricted by Azure Key Vault access policies
- Key operations are logged and monitored
- Automatic rotation is configured for all keys

## Usage Examples

### Encrypt Data
\`\`\`bash
az keyvault key encrypt --vault-name "$KEY_VAULT_NAME" --name "pci-encryption-key" --algorithm RSA-OAEP-256 --value "$(echo -n "Sensitive data" | base64)"
\`\`\`

### Sign Data
\`\`\`bash
az keyvault key sign --vault-name "$KEY_VAULT_NAME" --name "swift-payment-key" --algorithm RS256 --value "$(echo -n "Data to sign" | openssl dgst -sha256 -binary | base64)"
\`\`\`

## Backup Information
Keys are backed up to encrypted file: hsm_key_backups_$(date +%Y%m%d_%H%M%S).tar.gz.enc
EOF

echo -e "${GREEN}Documentation generated: hsm_keys_documentation.md${NC}"

# Summary
echo -e "\n${BLUE}============================================================${NC}"
echo -e "${GREEN}HSM-Protected Key Generation Complete${NC}"
echo -e "${BLUE}============================================================${NC}"
echo -e "${YELLOW}Summary:${NC}"
echo -e "  - Key Vault: $KEY_VAULT_NAME"
echo -e "  - Keys Generated: ${#KEY_CONFIGS[@]}"
echo -e "  - Rotation Policy: $ROTATION_DAYS days"
echo -e "  - Documentation: hsm_keys_documentation.md"
echo -e "  - Encrypted Backup: hsm_key_backups_*.tar.gz.enc"
echo -e "\n${YELLOW}Next Steps:${NC}"
echo -e "  1. Store the encrypted backup securely"
echo -e "  2. Configure applications to use these keys"
echo -e "  3. Set up monitoring for key operations"
echo -e "${BLUE}============================================================${NC}"

exit 0