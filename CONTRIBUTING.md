# Contributing

Thank you for contributing to Secure Regulated Cloud Landing Zone.

This file provides a minimal, repository-grounded contribution guide so contributors know the expectations for PRs, testing, and sensitive data handling.

Quick rules
- Open an issue before starting substantial work so maintainers can provide guidance.
- Keep pull requests focused and small. Target the `main` branch and reference the related issue.
- Include a short test plan in your PR description, and list any manual steps required to validate changes.
- Do not commit secrets, private keys, or credentials. Use Azure Key Vault and repository/CI secrets.

Developer workflow
1. Fork the repository and create a branch: `git checkout -b feat/your-feature`.
2. Implement your change and add tests where applicable.
3. Run relevant tests locally (see `tests/` and `src/`).
4. Push branch and open a PR describing the change, tests, and any infra/resources needed to verify.

Testing notes
- Unit tests: see `tests/unit` (Bats-based shell tests). Run with `bats`.
- Integration tests: see `tests/integration/run_compliance_integration_tests.sh`. Integration tests require real Azure resources and should be run in disposable subscriptions/resource groups.

Script and infra changes
- If a change modifies scripts that call the Azure CLI or change infrastructure behavior, include the exact `az`/Terraform commands and RBAC permissions required to run them in the PR.

Contact & support
- Open an issue for questions or to request maintainer review.
