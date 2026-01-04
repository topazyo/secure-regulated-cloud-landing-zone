# Secure Landing Zone Deployment Guide

This guide provides detailed deployment instructions for the Secure Regulated Cloud Landing Zone. For a quick start, see the [README](../README.md#quick-start).

## Prerequisites

- Azure Subscription with Owner rights
- Azure CLI 2.30.0 or later
- Terraform 1.0.0 or later
- OpenSSL 1.1.1 or later
- jq (JSON processor)

## Deployment Steps

### 1. Clone and Setup
```bash
git clone https://github.com/topazyo/secure-regulated-cloud-landing-zone.git
cd secure-regulated-cloud-landing-zone
```

### 2. Initialize Environment
```bash
# Login to Azure
az login

# Set subscription
az account set --subscription <your-subscription-id>
```

### 3. Generate HSM-Protected Keys
```bash
./src/scripts/generate-hsm-keys.sh --key-vault mykeyvault --resource-group myrg --location switzerlandnorth --subscription <sub-id> --admin-id <admin-object-id>
```

### 4. Configure Network Segmentation
```bash
./src/scripts/configure-network.sh --subscription <sub-id> --resource-group myrg --environment production
```

### 5. Deploy Infrastructure
```bash
cd examples/multi-tenant
terraform init
terraform apply
```

### 6. Validate Deployment and Compliance
```bash
./src/scripts/deployment/validate-deployment.sh
./src/scripts/verify-compliance.sh -s <sub-id> -g myrg
```

## Post-Deployment Validation

### Security Checklist
- [ ] Network segmentation verified
- [ ] HSM keys rotation configured
- [ ] Compliance policies applied
- [ ] Monitoring alerts active