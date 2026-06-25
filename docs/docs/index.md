# USG EST Client

A Rust implementation of an RFC 7030 compliant EST (Enrollment over Secure Transport) client for automated X.509 certificate enrollment and management.

## Quick links

- [Getting Started](getting-started.md)
- [Configuration](configuration.md)
- [Operations](operations.md)
- [Security](security.md)
- [API Reference](api-reference.md)
- [Examples](examples.md)
- [Troubleshooting](troubleshooting.md)

## Highlights

- Async-first Rust client covering all mandatory and optional EST operations
- Bootstrap/TOFU mode and multiple authentication paths (client certs, HTTP basic)
- Feature-gated helpers for CSR generation, metrics, and revocation handling
- Production-focused design: rigorous error handling, TLS hardening, and platform guides

## Project resources

- Crate: [usg-est-client on crates.io](https://crates.io/crates/usg-est-client)
- API docs: [docs.rs/usg-est-client](https://docs.rs/usg-est-client)
- Source: [GitHub repository](https://github.com/192d-Wing/usg-est-client)
