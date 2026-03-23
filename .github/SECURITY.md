# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### Preferred Method

Use [GitHub Security Advisories](https://github.com/192d-Wing/usg-est-client/security/advisories/new) to privately report the vulnerability. This allows us to assess and address it before public disclosure.

### Alternative Method

Email: **john.willman.1@us.af.mil**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact assessment
- Any suggested mitigations

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity
  - Critical: Patch within 7 days
  - High: Patch within 14 days
  - Medium: Patch within 30 days
  - Low: Next scheduled release

### Disclosure Policy

We follow coordinated disclosure. We ask reporters to:
1. Allow us reasonable time to address the issue before public disclosure
2. Make a good faith effort to avoid privacy violations, data destruction, or service disruption
3. Not access or modify data belonging to others

## Security Practices

This project enforces:
- TLS 1.3 minimum for all EST communications
- FIPS 140-2 compliant cryptography (optional feature)
- Automated dependency auditing via `cargo audit` and `cargo deny`
- Security-focused clippy lints in CI
- Credential sanitization in error messages
- No hardcoded secrets in production code

## Known Accepted Risks

### RSA Timing Side-Channel (RUSTSEC-2023-0071)

The `rsa` crate has a known timing side-channel vulnerability (Marvin Attack) in PKCS#1 v1.5 decryption. This project uses RSA only for **signature verification**, not decryption, which limits exposure. No upstream fix is available. We monitor for updates and document this as an accepted risk in [deny.toml](../deny.toml).
