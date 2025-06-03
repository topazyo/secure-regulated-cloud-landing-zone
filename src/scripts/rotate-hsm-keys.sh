#!/bin/bash

# Script to rotate HSM keys in Azure Key Vault

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Check for required arguments
if [ "$#" -ne 2 ]; then
    log_message "ERROR: Incorrect number of arguments."
    echo "Usage: $0 <key_vault_name> <key_name>"
    exit 1
fi

KEY_VAULT_NAME=$1
KEY_NAME=$2

log_message "Starting key rotation for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME'."

# Create a new version of the key
log_message "Attempting to create a new version for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME' (type: HSM)."
AZ_CREATE_OUTPUT=$(az keyvault key create --vault-name "$KEY_VAULT_NAME" --name "$KEY_NAME" --protection hsm 2>&1)

# Check if the Azure CLI command was successful
if [ $? -ne 0 ]; then
    log_message "ERROR: Azure CLI command failed to create new key version."
    log_message "Azure CLI output: $AZ_CREATE_OUTPUT"
    exit 1
fi

NEW_KEY_VERSION=$(echo "$AZ_CREATE_OUTPUT" | grep -oP '"kid":\s*"\K[^"]+/([0-9a-f]+)')
if [ -z "$NEW_KEY_VERSION" ]; then
    # Fallback if grep -oP is not available or pattern fails
    NEW_KEY_VERSION=$(echo "$AZ_CREATE_OUTPUT" | awk -F'"' '/kid/{print $4}' | awk -F'/' '{print $NF}')
fi


if [ -n "$NEW_KEY_VERSION" ]; then
    log_message "Successfully created new version for key '$KEY_NAME'. New version ID fragment: $NEW_KEY_VERSION"
else
    log_message "Successfully initiated creation of new version for key '$KEY_NAME'. Could not parse new version ID from output."
    log_message "Full output: $AZ_CREATE_OUTPUT" # Log full output if parsing fails
fi

log_message "Key rotation process completed for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME'."

exit 0
