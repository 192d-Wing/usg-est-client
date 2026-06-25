# USG EST Client Documentation

This directory contains the documentation site for `usg-est-client`, an
RFC 7030 compliant EST (Enrollment over Secure Transport) client library.
The site is built with [Zensical](https://zensical.org).

## Documentation Structure

```
docs/
├── docs/                       # Documentation content (Markdown)
│   ├── index.md                # Overview
│   ├── getting-started.md      # Installation and first enrollment
│   ├── configuration.md        # Configuration guide
│   ├── config-reference.md     # Full configuration reference
│   ├── operations.md           # EST operations
│   ├── revocation-guide.md     # CRL/OCSP revocation guide
│   ├── revocation_status.md    # Revocation implementation status
│   ├── platform-tls.md         # TLS backend selection
│   ├── security.md             # Security guidance
│   ├── windows-enrollment.md   # Windows enrollment
│   ├── wasm-compatibility.md   # WebAssembly compatibility
│   ├── enterprise/             # Enterprise guides
│   │   └── group-policy.md     # Group Policy deployment
│   ├── examples.md             # Usage examples
│   ├── metrics.md              # Metrics and observability
│   ├── migration-from-adcs.md  # Migrating from ADCS
│   └── troubleshooting.md      # Troubleshooting
├── zensical.toml               # Site configuration
├── pyproject.toml              # Python project / Zensical dependency
└── README.md                   # This file
```

## Building the Documentation

This project pins Zensical via `pyproject.toml`/`uv.lock`, so the
recommended workflow uses [uv](https://docs.astral.sh/uv/):

```bash
cd docs
uv run zensical build -f zensical.toml
```

> **Note:** pass `-f zensical.toml` explicitly. The generated site is written
> to the `site/` directory.

### Serve Locally

```bash
cd docs
uv run zensical serve -f zensical.toml
```

Then visit <http://127.0.0.1:8000> in your browser.

## Diagrams (Mermaid)

Architecture and flow diagrams are authored as [Mermaid](https://mermaid.js.org)
code blocks (` ```mermaid `), enabled via the `pymdownx.superfences`
`custom_fences` setting in `zensical.toml`.

> **Air-gapped / ATO deployments:** Zensical's bundled theme loads the Mermaid
> runtime from a public CDN (`https://unpkg.com/mermaid@11/dist/mermaid.min.js`)
> at page-render time. In a disconnected or accreditation-controlled environment
> this request will fail and the diagrams will not render (the page otherwise
> works). To support offline/ATO hosting, vendor the Mermaid library locally —
> place `mermaid.min.js` under `docs/docs/javascripts/` and reference it via
> `extra_javascript` in `zensical.toml` (with a local `mermaid.initialize`
> call), or pre-render the diagrams to static SVG. Confirm the chosen approach
> against your environment's content-security and supply-chain requirements.

## Contributing to Documentation

1. Create or edit Markdown files in `docs/docs/`.
2. Preview locally with `uv run zensical serve -f zensical.toml`.
3. Keep fenced code blocks flush with the left margin (indenting a fence by
   4+ spaces makes Markdown render it as literal text).
4. Commit changes; the site is built and deployed via CI.

## Contact

- Open an issue on [GitHub](https://github.com/192d-Wing/usg-est-client).
- Contact: John Edward Willman V <john.willman.1@us.af.mil>
