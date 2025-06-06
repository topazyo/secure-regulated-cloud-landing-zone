#!/bin/bash

# Script to rotate HSM keys in Azure Key Vault
# Implements idempotency check: if a key version was created very recently,
# a new version will not be created.

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

# Idempotency Check Configuration
# Threshold in seconds. If the latest key version was created within this period, skip rotation.
# 300 seconds = 5 minutes. This could be made an environment variable.
RECENT_ROTATION_THRESHOLD_SECONDS=300

log_message "Initiating key rotation process for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME'."

# Check existing key's creation time for idempotency
log_message "Performing idempotency check for key '$KEY_NAME'..."
KEY_INFO_JSON=$(az keyvault key show --vault-name "$KEY_VAULT_NAME" --name "$KEY_NAME" -o json 2>/dev/null)
AZ_KEY_SHOW_EXIT_CODE=$?

if [ "$AZ_KEY_SHOW_EXIT_CODE" -eq 0 ] && [ -n "$KEY_INFO_JSON" ]; then
    # Key exists, parse its creation timestamp
    # We are interested in 'attributes.created' of the *current* version of the key.
    # 'az keyvault key show' without a --version fetches the latest enabled version.
    KEY_CREATED_TIMESTAMP_ISO=$(echo "$KEY_INFO_JSON" | jq -r '.attributes.created')

    if [ "$KEY_CREATED_TIMESTAMP_ISO" != "null" ] && [ -n "$KEY_CREATED_TIMESTAMP_ISO" ]; then
        # Convert ISO timestamp to seconds since epoch
        # Works on GNU date. For macOS/BSD, date -jf "%Y-%m-%dT%H:%M:%SZ" "$KEY_CREATED_TIMESTAMP_ISO" +%s might be needed.
        KEY_CREATED_SECONDS=$(date -d "$KEY_CREATED_TIMESTAMP_ISO" +%s 2>/dev/null)

        if [ $? -ne 0 ]; then
            log_message "WARNING: Could not parse key creation timestamp '$KEY_CREATED_TIMESTAMP_ISO'. Proceeding with rotation attempt."
        else
            CURRENT_TIME_SECONDS=$(date +%s)
            TIME_DIFFERENCE_SECONDS=$((CURRENT_TIME_SECONDS - KEY_CREATED_SECONDS))

            log_message "Key '$KEY_NAME' current version created at: $KEY_CREATED_TIMESTAMP_ISO (${KEY_CREATED_SECONDS}s epoch)."
            log_message "Current time: $(date -d "@$CURRENT_TIME_SECONDS" '+%Y-%m-%d %H:%M:%S') (${CURRENT_TIME_SECONDS}s epoch)."
            log_message "Time difference: $TIME_DIFFERENCE_SECONDS seconds."

            if [ "$TIME_DIFFERENCE_SECONDS" -lt "$RECENT_ROTATION_THRESHOLD_SECONDS" ]; then
                log_message "Key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME' was already rotated recently (version created at $KEY_CREATED_TIMESTAMP_ISO, which is less than $RECENT_ROTATION_THRESHOLD_SECONDS seconds ago). Skipping new version creation."
                exit 0
            else
                log_message "Key '$KEY_NAME' current version is older than the threshold of $RECENT_ROTATION_THRESHOLD_SECONDS seconds. Proceeding with new version creation."
            fi
        fi
    else
        log_message "WARNING: Could not extract key creation timestamp from 'az keyvault key show' output. Proceeding with rotation attempt."
        log_message "Debug Key Info JSON (first 100 chars): $(echo "$KEY_INFO_JSON" | head -c 100)"
    fi
else
    # 'az keyvault key show' failed or returned empty JSON.
    # This could mean the key does not exist yet, or an error occurred.
    # In either case, we let 'az keyvault key create' handle it.
    if [ "$AZ_KEY_SHOW_EXIT_CODE" -ne 0 ]; then
        log_message "INFO: Key '$KEY_NAME' not found or error during 'az keyvault key show' (exit code $AZ_KEY_SHOW_EXIT_CODE). Proceeding to create it."
    else
        log_message "INFO: Key '$KEY_NAME' not found (empty JSON from 'az keyvault key show'). Proceeding to create it."
    fi
fi

# Create a new version of the key
log_message "Attempting to create a new version for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME' (type: HSM)."
# The original script had --ops sign verify wrapKey unwrapKey encrypt decrypt. Adding them back.
AZ_CREATE_OUTPUT=$(az keyvault key create --vault-name "$KEY_VAULT_NAME" --name "$KEY_NAME" --protection hsm --ops sign verify wrapKey unwrapKey encrypt decrypt 2>&1)
AZ_CREATE_EXIT_CODE=$?

# Check if the Azure CLI command was successful
if [ "$AZ_CREATE_EXIT_CODE" -ne 0 ]; then
    log_message "ERROR: Azure CLI command failed to create new key version for '$KEY_NAME'."
    log_message "Azure CLI output: $AZ_CREATE_OUTPUT"
    exit 1
fi

# Try to parse the new key version from the 'kid' (Key ID)
NEW_KEY_VERSION_FULL_ID=$(echo "$AZ_CREATE_OUTPUT" | jq -r '.key.kid // empty')
NEW_KEY_VERSION=""
if [ -n "$NEW_KEY_VERSION_FULL_ID" ]; then
    NEW_KEY_VERSION=$(basename "$NEW_KEY_VERSION_FULL_ID")
fi

if [ -n "$NEW_KEY_VERSION" ]; then
    log_message "Successfully created new version for key '$KEY_NAME'. New version ID: $NEW_KEY_VERSION"
else
    # Fallback if jq parsing failed or 'kid' was not in the expected place.
    # This fallback might be less reliable.
    LEGACY_PARSED_VERSION=$(echo "$AZ_CREATE_OUTPUT" | grep -oP '"kid":\s*"\K[^"]+/([0-9a-f]+)' | awk -F'/' '{print $NF}')
    if [ -z "$LEGACY_PARSED_VERSION" ]; then
        LEGACY_PARSED_VERSION=$(echo "$AZ_CREATE_OUTPUT" | awk -F'"' '/kid/{print $4}' | awk -F'/' '{print $NF}')
    fi
    if [ -n "$LEGACY_PARSED_VERSION" ]; then
         log_message "Successfully created new version for key '$KEY_NAME'. New version ID fragment (legacy parse): $LEGACY_PARSED_VERSION"
    else
        log_message "Successfully initiated creation of new version for key '$KEY_NAME'. Could not parse new version ID from output."
        log_message "Full Azure CLI output: $AZ_CREATE_OUTPUT"
    fi
fi

log_message "Key rotation process completed for key '$KEY_NAME' in Key Vault '$KEY_VAULT_NAME'."

exit 0
