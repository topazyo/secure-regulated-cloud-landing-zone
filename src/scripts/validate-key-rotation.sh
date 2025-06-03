#!/bin/bash

# Purpose: Validates if a specified key in Azure Key Vault has been rotated recently.
# "Rotated recently" means its current version was created within a defined timeframe.
#
# Usage: ./validate-key-rotation.sh <key_vault_name> <key_name> [max_key_age_seconds]
#
# Parameters:
#   <key_vault_name>: The name of the Azure Key Vault.
#   <key_name>: The name of the key to validate.
#   [max_key_age_seconds]: Optional. The maximum age (in seconds) of the key's current
#                          version to be considered "recently rotated".
#                          Defaults to 3600 seconds (1 hour).
#
# Prerequisites:
#   - Azure CLI installed and configured (run `az login`).
#   - `jq` utility installed for parsing JSON output from Azure CLI.
#     The script attempts to install `jq` if it's missing on Debian/RHEL-based systems.
#   - Permissions to read key properties from the specified Key Vault.
#
# Output:
#   - Logs validation steps and results to standard output.
#   - Exits with 0 if the key is considered recently rotated.
#   - Exits with 1 if validation fails, arguments are incorrect, or an error occurs.
#
# Example:
#   # Check if 'myHsmKey' in 'myKeyVault' was rotated in the last hour (default)
#   ./validate-key-rotation.sh "myKeyVault" "myHsmKey"
#
#   # Check if 'myOtherKey' in 'myKeyVault' was rotated in the last 24 hours (86400 seconds)
#   ./validate-key-rotation.sh "myKeyVault" "myOtherKey" 86400
#

# Function to log messages with a timestamp
log_message() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# --- Script Start ---

# Check for jq availability and attempt to install if not present
if ! command -v jq &> /dev/null; then
    log_message "INFO: jq command could not be found. Attempting to install..."
    if command -v apt-get &> /dev/null; then
        # Using DEBIAN_FRONTEND=noninteractive to prevent prompts if possible
        # sudo might still require password depending on sudoers configuration
        if sudo DEBIAN_FRONTEND=noninteractive apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y jq; then
             log_message "INFO: jq installed successfully via apt-get."
        else
             log_message "ERROR: jq installation via apt-get failed. Please install jq manually."
             exit 1
        fi
    elif command -v yum &> /dev/null; then
        if sudo yum install -y jq; then
            log_message "INFO: jq installed successfully via yum."
        else
            log_message "ERROR: jq installation via yum failed. Please install jq manually."
            exit 1
        fi
    elif command -v dnf &> /dev/null; then
        if sudo dnf install -y jq; then
            log_message "INFO: jq installed successfully via dnf."
        else
            log_message "ERROR: jq installation via dnf failed. Please install jq manually."
            exit 1
        fi
    else
        log_message "ERROR: jq is not installed and could not be installed automatically (no apt-get, yum, or dnf). Please install jq manually."
        exit 1
    fi

    if ! command -v jq &> /dev/null; then # Final check
        log_message "ERROR: jq installation attempt finished, but jq is still not found. Please install jq manually."
        exit 1
    fi
fi


# Check for correct number of arguments
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 <key_vault_name> <key_name> [max_key_age_seconds]"
  echo "  max_key_age_seconds: Optional. Maximum age of the current key version in seconds."
  echo "                       Defaults to 3600 (1 hour)."
  log_message "ERROR: Incorrect number of arguments."
  exit 1
fi

KEY_VAULT_NAME=$1
KEY_NAME=$2
MAX_KEY_AGE_SECONDS=${3:-3600} # Default to 3600 seconds (1 hour) if not provided

log_message "INFO: Starting key rotation validation for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME'."
log_message "INFO: Maximum allowed age for the current key version: $MAX_KEY_AGE_SECONDS seconds."

# Get key information. Redirect stderr to stdout to capture potential errors in KEY_INFO_JSON.
KEY_INFO_JSON=$(az keyvault key show --vault-name "$KEY_VAULT_NAME" --name "$KEY_NAME" -o json 2>&1)
AZ_EXIT_CODE=$?

if [ $AZ_EXIT_CODE -ne 0 ]; then
  log_message "ERROR: Failed to retrieve key information for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME'."
  log_message "ERROR: Azure CLI output: $KEY_INFO_JSON"
  exit $AZ_EXIT_CODE
fi

# Ensure KEY_INFO_JSON is valid JSON before proceeding with jq
if ! echo "$KEY_INFO_JSON" | jq -e . > /dev/null 2>&1; then
    log_message "ERROR: Azure CLI output was not valid JSON. Output: $KEY_INFO_JSON"
    exit 1
fi

# Extract key version (kid) and creation timestamp
KEY_ID=$(echo "$KEY_INFO_JSON" | jq -r '.key.kid')
KEY_VERSION=$(echo "$KEY_ID" | awk -F'/' '{print $NF}') # Extracts the last part of the KID path
CREATION_TIMESTAMP_ISO=$(echo "$KEY_INFO_JSON" | jq -r '.attributes.created') # Expected format: YYYY-MM-DDTHH:MM:SSZ

if [ -z "$KEY_ID" ] || [ "$KEY_ID" == "null" ] || [ "$KEY_ID" == "" ]; then
    log_message "ERROR: Could not extract Key ID (kid) from Azure CLI output."
    log_message "DEBUG: Raw JSON output: $KEY_INFO_JSON"
    exit 1
fi

if [ -z "$CREATION_TIMESTAMP_ISO" ] || [ "$CREATION_TIMESTAMP_ISO" == "null" ] || [ "$CREATION_TIMESTAMP_ISO" == "" ]; then
    log_message "ERROR: Could not extract key creation timestamp (attributes.created) from Azure CLI output."
    log_message "DEBUG: Raw JSON output: $KEY_INFO_JSON"
    exit 1
fi

log_message "INFO: Current key version ID (KID): $KEY_ID"
log_message "INFO: Current key version (from KID): $KEY_VERSION"
log_message "INFO: Current key version creation timestamp (UTC): $CREATION_TIMESTAMP_ISO"

# Convert creation timestamp to seconds since epoch
# macOS 'date' command requires a different format for -j -f
if [[ "$(uname)" == "Darwin" ]]; then
  # Ensure the timestamp format matches what 'date -j -f' expects on macOS
  CREATION_TIMESTAMP_SECONDS=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$CREATION_TIMESTAMP_ISO" "+%s" 2>/dev/null)
else # Assuming Linux date (GNU date)
  CREATION_TIMESTAMP_SECONDS=$(date -d "$CREATION_TIMESTAMP_ISO" "+%s" 2>/dev/null)
fi

if [ -z "$CREATION_TIMESTAMP_SECONDS" ]; then
    log_message "ERROR: Could not convert creation timestamp '$CREATION_TIMESTAMP_ISO' to seconds since epoch."
    log_message "ERROR: Please ensure your 'date' command supports the input format."
    exit 1
fi

# Get current timestamp in seconds since epoch
CURRENT_TIMESTAMP_SECONDS=$(date -u "+%s")

# Calculate key age
KEY_AGE_SECONDS=$((CURRENT_TIMESTAMP_SECONDS - CREATION_TIMESTAMP_SECONDS))

if [ $KEY_AGE_SECONDS -lt 0 ]; then
    log_message "WARNING: Key creation timestamp ($CREATION_TIMESTAMP_ISO) is in the future compared to current UTC time ($(date -u -Iseconds)). Check system clock synchronization on this machine and on the Azure Key Vault service region."
    log_message "FAILURE: Key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME' has a creation date in the future."
    exit 1
fi

log_message "INFO: Current key version age: $KEY_AGE_SECONDS seconds."

# Validate key age
if [ $KEY_AGE_SECONDS -le $MAX_KEY_AGE_SECONDS ]; then
  log_message "SUCCESS: Key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME' (Version: $KEY_VERSION) was created recently (Age: $KEY_AGE_SECONDS seconds <= Max allowed: $MAX_KEY_AGE_SECONDS seconds)."
  exit 0
else
  log_message "FAILURE: Key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME' (Version: $KEY_VERSION) is NOT considered recently rotated."
  log_message "FAILURE: Age: $KEY_AGE_SECONDS seconds > Max allowed: $MAX_KEY_AGE_SECONDS seconds."
  exit 1
fi
