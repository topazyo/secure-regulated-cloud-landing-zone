# Security Policy

This repository follows a minimal security disclosure and response process.

Reporting a vulnerability
- If you discover a security issue, open a private issue or contact the maintainers. If the repository's issue tracker does not support private reports, use the project's contact method or the maintainer's email listed in the repository metadata.

Disclosure timeline
- Maintainers will triage reported issues promptly. Provide reproducible steps and impact details.

Do not commit secrets
- Never commit private keys, credentials, or secrets to the repository. Use Azure Key Vault for secrets and the repository's CI secret storage for sensitive environment variables.

Dependencies
- Keep dependencies up to date and open PRs to update pinned versions when security fixes are released. CI contains workflows in `.github/workflows/` that may reference dependency checks.
