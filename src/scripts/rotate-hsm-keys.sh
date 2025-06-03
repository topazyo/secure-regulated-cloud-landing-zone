#!/bin/bash

# Purpose: Creates a new version of a specified HSM-backed key in Azure Key Vault.
# This effectively "rotates" the key by making a new version the current one.
#
# Usage: ./rotate-hsm-keys.sh <key_vault_name> <key_name>
#
# Parameters:
#   <key_vault_name>: The name of the Azure Key Vault.
#   <key_name>: The name of the HSM-backed key to rotate.
#
# Prerequisites:
#   - Azure CLI installed and configured (run `az login`).
#   - Permissions to create new key versions in the specified Key Vault.
#
# Example:
#   ./rotate-hsm-keys.sh "myKeyVault" "myHsmKeyForRotation"
#

# Function to log messages with a timestamp
log_message() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# --- Script Start ---

# Check for correct number of arguments
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <key_vault_name> <key_name>"
  echo "Error: Incorrect number of arguments provided."
  log_message "ERROR: Incorrect number of arguments. Usage: $0 <key_vault_name> <key_name>"
  exit 1
fi

KEY_VAULT_NAME=$1
KEY_NAME=$2

log_message "Starting key rotation for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME'."

# Create new key version using Azure CLI
# --protection hsm: Ensures the new key version is HSM-backed.
# --disabled false: Ensures the new key version is enabled upon creation.
log_message "Executing: az keyvault key create --vault-name \"$KEY_VAULT_NAME\" --name \"$KEY_NAME\" --protection hsm --disabled false"
az keyvault key create --vault-name "$KEY_VAULT_NAME" --name "$KEY_NAME" --protection hsm --disabled false
AZ_EXIT_CODE=$?

if [ $AZ_EXIT_CODE -eq 0 ]; then
  log_message "Successfully created new version for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME'."

  # Retrieve and log the new key version ID (the part after the last '/')
  # Example KID: https://mykeyvault.vault.azure.net/keys/myHsmKeyForRotation/abcdef1234567890abcdef1234567890
  # We want to extract "abcdef1234567890abcdef1234567890"
  NEW_KEY_INFO_JSON=$(az keyvault key show --vault-name "$KEY_VAULT_NAME" --name "$KEY_NAME" -o json 2>/dev/null)
  if [ $? -eq 0 ] && [ -n "$NEW_KEY_INFO_JSON" ]; then
    NEW_KEY_ID=$(echo "$NEW_KEY_INFO_JSON" | jq -r '.key.kid')
    NEW_KEY_VERSION=$(echo "$NEW_KEY_ID" | awk -F'/' '{print $NF}')
    if [ -n "$NEW_KEY_VERSION" ]; then
        log_message "New key version ID is: $NEW_KEY_VERSION (Full KID: $NEW_KEY_ID)"
    else
        log_message "Could not determine new key version ID from KID: $NEW_KEY_ID"
    fi
  else
    log_message "WARNING: Could not retrieve new key version details after creation."
  fi
else
  log_message "ERROR: Failed to create new version for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME'. Azure CLI exit code: $AZ_EXIT_CODE"
  # Attempt to get more detailed error from Azure CLI if possible (stderr might have been captured by AZ_EXIT_CODE context)
  # For robust error handling, one might redirect stderr of the failing command to a temp file to log it.
  exit $AZ_EXIT_CODE
fi

log_message "Key rotation script finished for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME'."

exit 0
