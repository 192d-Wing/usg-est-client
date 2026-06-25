# Trust Anchor Management (TAMP, RFC 5934)

The `tamp` feature adds a **Trust Anchor Management Protocol** client for pulling
and applying trust anchor information from a Trust Anchor Manager (TAM). TAMP
([RFC 5934](https://www.rfc-editor.org/rfc/rfc5934)) is a CMS-based protocol for
managing the set of trust anchors a device or application trusts; trust anchors
themselves use the Trust Anchor Format
([RFC 5914](https://www.rfc-editor.org/rfc/rfc5914)).

This crate implements the **client (managed entity) role only**. It does not
implement the Trust Anchor Manager (server) side.

## Enabling

```toml
[dependencies]
usg-est-client = { version = "2", features = ["tamp"] }
```

The `tamp` feature is **enabled automatically by the `fips` feature** (and thus
by `dod`), because trust anchor management is how a FIPS deployment's roots of
trust are provisioned and rotated. Under `fips`, all TAMP signing, verification,
and hashing run inside the FIPS-validated aws-lc-rs module.

## What it does

| Capability | Detail |
|---|---|
| Pull status | Send `TAMPStatusQuery`, verify the signed `TAMPStatusResponse`, and read the current trust anchor list |
| Apply updates | Verify and apply Trust Anchor Update and Apex Update messages to a local store |
| Replay protection | Per-trust-anchor sequence numbers; a message is rejected unless its sequence number strictly exceeds the last accepted value (RFC 5934 §5) |
| Signed confirms | Emit signed `TAMPUpdateConfirm` / `TAMPError` messages using the client identity |
| Transport | HTTP(S) via the same reqwest/TLS stack as the EST client, using the RFC 5934 media types |

Trust anchor material is the RFC 5914 `TrustAnchorChoice` (a certificate, a bare
`TBSCertificate`, or a `TrustAnchorInfo`), reused from the `x509-cert` crate.

## Security model

A received management message is honored only if **both** hold:

1. its CMS `SignedData` signature verifies against a trust anchor already held in
   the local store (resolved by Subject Key Identifier or issuer/serial); and
2. its sequence number is fresh for the signing trust anchor (anti-replay).

A trust root (typically the **apex** trust anchor) must therefore be
provisioned out of band before any response can be trusted.

## Library usage

```rust,no_run
use usg_est_client::EstClientConfig;
use usg_est_client::tamp::{TampClient, TrustAnchorStore};
use usg_est_client::Certificate;
use x509_cert::anchor::TrustAnchorChoice;
use der::DecodePem;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
// Seed the store with the apex trust anchor (provisioned out of band).
let apex = Certificate::from_pem(std::fs::read("apex.pem")?)?;
let mut store = TrustAnchorStore::new();
store.upsert(TrustAnchorChoice::Certificate(apex), true)?;

let config = EstClientConfig::builder().server_url("https://ta.example.mil")?.build()?;
let mut client = TampClient::new(config, "https://ta.example.mil/tamp", store)?;

// Pull the current trust anchor information.
let response = client.status_query_all(false).await?;
println!("local store now holds {} anchors", client.store().len());
# let _ = response;
# Ok(()) }
```

The pulled store can be persisted as canonical DER with
`TrustAnchorStore::to_der` / `from_der` (no `serde` dependency), so anchors and
their replay counters survive restarts.

## CLI usage

With the `est-enroll` binary built with both `cli` and `tamp` features:

```text
# Pull trust anchor info, verifying against a provisioned apex anchor,
# and save the resulting store:
est-enroll tamp status \
    --tamp-url https://ta.example.mil/tamp \
    --trust-anchor apex.pem \
    --save-store store.der

# Print the anchors held in a saved store:
est-enroll tamp export --trust-store store.der --format text

# Verify and apply a TAMP update received out of band, emit the signed confirm:
est-enroll tamp process update.cms \
    --trust-store store.der \
    --output confirm.cms \
    --save-store store.der
```

## Scope and limitations

- Client role only; no Trust Anchor Manager (server) implementation.
- Signature algorithms: RSA (PKCS#1 v1.5) and ECDSA P-256 / P-384 with SHA-256 /
  SHA-384 / SHA-512.
- `TrustAnchorUpdate` `add` and `remove` operations are applied; `change`
  operations are reported (and surfaced in the confirm status) rather than
  silently applied.
- `CMSContentConstraints` (RFC 6010) authorization beyond "the signer is a
  trusted anchor" is not yet enforced.
