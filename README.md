# Secure Regulated Cloud Landing Zone

Enterprise-grade landing zone implementation for regulated industries, focusing on financial services, healthcare, and government sectors with automated compliance and security controls.

## Features

- Zero Trust Architecture Implementation
- HSM-Backed Security Controls (RSA-4096 keys, FIPS 140-2 Level 3)
- Real-Time Compliance Monitoring (PCI-DSS, SWIFT-SCR, HIPAA, GDPR)
- Automated Policy Enforcement via Azure Policy
- Multi-Regulatory Framework Support with customizable controls
- Network Segmentation and Isolation Validation
- Automated Remediation Workflows
- Comprehensive Testing (Unit, Integration, Terraform)

## Prerequisites

- Azure Subscription with Owner rights
- Azure CLI (`az`) installed and authenticated — scripts call `az` directly. TODO: confirm minimum tested `az` version from CI.
- Node.js 16 — required for tests and some CI jobs (see `.github/workflows/infrastructure-validation.yml`).
- Terraform 1.x recommended — CI uses `hashicorp/setup-terraform@v1` which installs a v1.x Terraform runtime.
- OpenSSL 1.1.1 or later (used by key handling scripts/helpers).
- jq (JSON processor)

CI note: GitHub Actions workflows run on `ubuntu-latest` and use `actions/setup-node@v2` (Node.js 16) and `hashicorp/setup-terraform@v1` for Terraform. The repository also runs security scans with `aquasecurity/tfsec-action` and CodeQL in CI.

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/topazyo/secure-regulated-cloud-landing-zone.git
cd secure-regulated-cloud-landing-zone
```

2. Login to Azure and set subscription:
```bash
az login
az account set --subscription <your-subscription-id>
```

3. Generate HSM-protected keys:
```bash
./src/scripts/generate-hsm-keys.sh --key-vault mykeyvault --resource-group myrg --location switzerlandnorth --subscription <sub-id> --admin-id <admin-object-id>
```

4. Configure network segmentation:
```bash
./src/scripts/configure-network.sh --subscription <sub-id> --resource-group myrg --environment production
```

5. Deploy infrastructure:
```bash
cd examples/multi-tenant
terraform init
terraform apply
```

6. Validate deployment and compliance:
```bash
./src/scripts/deployment/validate-deployment.sh
./src/scripts/verify-compliance.sh -s <sub-id> -g myrg
```

## Install/Setup

After cloning, ensure prerequisites are installed. Run setup scripts in order:
- Key generation: `src/scripts/generate-hsm-keys.sh`
- Network config: `src/scripts/configure-network.sh`
- Deployment: Use Terraform in `examples/` or `src/terraform/`

## Configuration

| Name | Required | Default | Description | Where Used |
|------|----------|---------|-------------|------------|
| `SUBSCRIPTION_ID` | Yes | Current active | Azure subscription ID | All scripts (e.g., `verify-compliance.sh`, `configure-network.sh`) |
| `RESOURCE_GROUP` | Yes | None | Resource group name | Scripts like `validate-deployment.sh`, `configure-network.sh` |
| `LOG_ANALYTICS_WORKSPACE` | No | Auto-detected | Log Analytics workspace name | `verify-compliance.sh`, monitoring scripts |
| `KEY_VAULT_NAME` | No | Auto-detected | Key Vault name | `generate-hsm-keys.sh`, compliance checks |
| `AZURE_LOG_ANALYTICS_WORKSPACE` | No | None | Env var for Log Analytics | Scripts requiring workspace |
| `AZURE_KEY_VAULT_NAME` | No | None | Env var for Key Vault | Key-related scripts |
| `VERIFY_COMPLIANCE_DEBUG` | No | false | Enable debug logging | `verify-compliance.sh` |
| Config Files | Yes | `config/` | JSON configs for network/compliance | `compliance-check.sh`, `configure-network.sh` (e.g., `network_config.json`, `critical_controls.json`) |

## Usage

Common commands:

- Run compliance verification: `./src/scripts/verify-compliance.sh -s <sub-id> -g <rg>`
- Check specific frameworks: `./src/scripts/compliance/compliance-check.sh --framework pci-dss`
- Validate network isolation: `./src/scripts/validate-network-isolation.sh`
- Restore security baseline: `./src/scripts/restore-security-baseline.sh`
- Run unit tests: `cd tests/unit && bats test_*.sh` (requires Bats)
- Run integration tests: `./tests/integration/run_compliance_integration_tests.sh`

## Project Layout

- `src/`: Core implementation (scripts, TypeScript classes for validators/reporters)
- `config/`: Configuration files (network, compliance, schemas)
- `examples/`: Terraform examples (multi-tenant, pci-dss, swift-scr)
- `tests/`: Unit/integration tests (Bash, Go for Terraform)
- `docs/`: Documentation (architecture, compliance, deployment guides)
- `.github/workflows/`: CI/CD pipelines (infrastructure validation, security pipeline)

## CI/CD

Automated workflows in [.github/workflows/](.github/workflows/):
- Infrastructure validation on PRs
- Security pipeline scans

## License

MIT License - see [LICENSE](LICENSE).

## Contributing & Security

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and [SECURITY.md](SECURITY.md) for the vulnerability reporting policy. Follow the repository rules described there before opening PRs or reporting vulnerabilities.