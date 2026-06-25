# WebAssembly (WASM) Compatibility Analysis

This document analyzes the compatibility of `usg-est-client` with WebAssembly targets, identifies blockers, and proposes potential solutions.

## Target Platforms

| Target | Description | Status |
|--------|-------------|--------|
| `wasm32-unknown-unknown` | Browser/generic WASM | ❌ Blocked |
| `wasm32-wasi` | WASI runtime (Wasmtime, WasmEdge) | ⚠️ Partial |
| `wasm32-wasip1` | WASI Preview 1 | ⚠️ Partial |
| `wasm32-wasip2` | WASI Preview 2 (Component Model) | 🔄 Future |

## Dependency Compatibility Matrix

### Core Dependencies

| Crate | Version | WASM Compatible | Blocker | Notes |
|-------|---------|-----------------|---------|-------|
| `tokio` | 1.47 | ⚠️ Limited | Multi-threading | Requires `tokio-with-wasm` or `tokio_wasi` fork |
| `reqwest` | 0.13 | ⚠️ Limited | TLS backend | Browser uses native fetch; WASI needs patches |
| `rustls` | 0.23 | ❌ No | `ring` dependency | `ring` has native assembly code |
| `webpki-roots` | 1.0 | ✅ Yes | None | Pure Rust |

### TLS Stack (Primary Blocker)

| Crate | WASM Compatible | Issue |
|-------|-----------------|-------|
| `rustls` | ❌ No | Depends on `ring` which has native assembly |
| `rustls-pemfile` | ✅ Yes | Pure Rust parsing |
| `rustls-pki-types` | ✅ Yes | Pure Rust types |
| `ring` | ❌ No | Contains platform-specific assembly |
| `aws-lc-rs` | ❌ No | Contains C/assembly code |

### Cryptography (RustCrypto)

| Crate | Version | WASM Compatible | Notes |
|-------|---------|-----------------|-------|
| `x509-cert` | 0.2 | ✅ Yes | Pure Rust, `no_std` compatible |
| `der` | 0.7.9 | ✅ Yes | Pure Rust, `no_std` compatible |
| `cms` | 0.2 | ✅ Yes | Pure Rust |
| `pkcs8` | 0.10.2 | ✅ Yes | Pure Rust |
| `spki` | 0.7.3 | ✅ Yes | Pure Rust |
| `const-oid` | 0.9.6 | ✅ Yes | Pure Rust, `no_std` |
| `sha2` | 0.10.8 | ✅ Yes | Pure Rust |
| `aes` | 0.8 | ✅ Yes | Pure Rust |
| `cbc` | 0.1 | ✅ Yes | Pure Rust |
| `des` | 0.8 | ✅ Yes | Pure Rust |

### CSR Generation

| Crate | Version | WASM Compatible | Issue |
|-------|---------|-----------------|-------|
| `rcgen` | 0.14 | ❌ No | Depends on `ring` by default |

**Note**: `rcgen` 0.14+ supports `aws-lc-rs` as an alternative backend via feature flag, but `aws-lc-rs` also doesn't compile to WASM.

### Utility Crates

| Crate | Version | WASM Compatible | Notes |
|-------|---------|-----------------|-------|
| `base64` | 0.22.1 | ✅ Yes | Pure Rust |
| `thiserror` | 2.0.17 | ✅ Yes | Pure Rust |
| `url` | 2.5.7 | ✅ Yes | Pure Rust |
| `tracing` | 0.1.44 | ✅ Yes | Pure Rust |
| `async-trait` | 0.1.89 | ✅ Yes | Pure Rust |

### Optional Feature Dependencies

| Feature | Crate | WASM Compatible | Notes |
|---------|-------|-----------------|-------|
| `renewal` | `time` | ✅ Yes | Pure Rust |
| `pkcs11` | `cryptoki` | ❌ No | Requires native PKCS#11 library |
| `metrics-prometheus` | `prometheus` | ⚠️ Partial | May have threading issues |
| `auto-enroll` | `dirs` | ❌ No | Filesystem access |
| `auto-enroll` | `hostname` | ❌ No | System calls |

## Primary Blockers

### 1. TLS Implementation (Critical)

**Problem**: `rustls` depends on `ring` for cryptographic operations. `ring` contains platform-specific assembly code that cannot compile to WASM.

**Impact**: Cannot establish TLS connections, which is fundamental to EST protocol (RFC 7030 requires TLS).

**Potential Solutions**:

| Solution | Feasibility | Effort | Notes |
|----------|-------------|--------|-------|
| Browser native fetch | High | Medium | For `wasm32-unknown-unknown` in browsers |
| `rustls` with `aws-lc-rs` | Low | N/A | `aws-lc-rs` also has native code |
| Pure Rust TLS | Low | Very High | No mature pure-Rust TLS exists |
| WASI-crypto | Medium | Medium | For WASI runtimes only |
| Host-provided TLS | Medium | Medium | WASI Preview 3 async support |

### 2. Async Runtime (Critical)

**Problem**: Standard `tokio` doesn't work in browser WASM due to:
- No native threading support in `wasm32-unknown-unknown`
- Blocking operations panic in browser main thread
- No direct socket access

**Potential Solutions**:

| Solution | Target | Effort | Notes |
|----------|--------|--------|-------|
| `tokio-with-wasm` | Browser | Medium | Drop-in replacement for browser |
| `tokio_wasi` | WASI | Medium | Fork with WASI support |
| `wasm-bindgen-futures` | Browser | Medium | Bridge to JS Promises |

### 3. CSR Generation (Medium)

**Problem**: `rcgen` depends on `ring` for key generation and signing.

**Potential Solutions**:

| Solution | Feasibility | Effort |
|----------|-------------|--------|
| Use `p256`/`p384` crates | High | Medium |
| Pure Rust key generation | High | Medium |
| Pre-generated keys | Medium | Low |

## WASM Support Strategies

### Strategy A: Browser-Only (wasm32-unknown-unknown)

For browser environments, rely on the browser's native capabilities:

```
┌─────────────────────────────────────────────┐
│                Browser                       │
├─────────────────────────────────────────────┤
│  JavaScript (glue code)                      │
│    ↓                                         │
│  WASM Module (usg-est-client-wasm)          │
│    - Certificate parsing (x509-cert, der)   │
│    - CSR building (pure Rust)               │
│    - Base64/encoding                         │
│    ↓                                         │
│  Browser Fetch API (via wasm-bindgen)       │
│    - TLS handled by browser                 │
│    - Cookies handled by browser             │
└─────────────────────────────────────────────┘
```

**Advantages**:
- TLS handled by browser (trusted, optimized)
- Cookie management by browser
- Works with existing browser security model

**Limitations**:
- No TLS client certificate authentication (browser limitation)
- Limited control over TLS settings
- CORS restrictions apply

**Required Changes**:
1. Create `wasm` feature flag
2. Use `reqwest` with default WASM backend (uses `fetch`)
3. Replace `tokio` with `wasm-bindgen-futures`
4. Replace `rcgen` with pure-Rust key generation
5. Disable features: `pkcs11`, `auto-enroll`

### Strategy B: WASI Runtime (wasm32-wasi)

For server-side WASM runtimes (Wasmtime, WasmEdge):

```
┌─────────────────────────────────────────────┐
│            WASI Runtime                      │
│         (Wasmtime, WasmEdge)                │
├─────────────────────────────────────────────┤
│  WASM Module (usg-est-client-wasi)          │
│    - Uses tokio_wasi                        │
│    - Uses patched reqwest                   │
│    ↓                                         │
│  WASI Sockets API                           │
│    - TCP/TLS via host                       │
│    - wasi-crypto (if available)             │
└─────────────────────────────────────────────┘
```

**Advantages**:
- Full networking capabilities (via host)
- TLS client certificates possible
- More control than browser

**Limitations**:
- Requires WASI-compatible runtime
- Socket creation limitations in current WASI
- WASI-crypto not universally supported

**Required Changes**:
1. Create `wasi` feature flag
2. Use `tokio_wasi` instead of `tokio`
3. Patch `reqwest` for WASI (see WasmEdge examples)
4. Conditional compilation for WASI-specific code

### Strategy C: Minimal WASM Library

Create a minimal WASM-compatible library for certificate/CSR operations only:

```rust
// New crate: usg-est-types (pure Rust, no I/O)
pub mod certificate;  // x509-cert wrappers
pub mod csr;          // CSR building (pure Rust)
pub mod pkcs7;        // PKCS#7 parsing
pub mod encoding;     // Base64, DER, PEM
```

**Advantages**:
- Guaranteed WASM compatibility
- Useful for parsing/building without network
- Can be used with any HTTP client

**Limitations**:
- Not a complete EST client
- User must handle HTTP/TLS

## Recommended Approach

### Phase 1: Compatibility Audit (Current)
- ✅ Document dependency compatibility
- ✅ Identify blockers
- ✅ Evaluate strategies

### Phase 2: Minimal WASM Types Library
1. Extract pure-Rust types into `usg-est-types` crate
2. Ensure `no_std` + `alloc` compatibility
3. Test compilation to `wasm32-unknown-unknown`

### Phase 3: Browser WASM Client
1. Create `usg-est-client-wasm` crate
2. Use browser fetch API via `reqwest` WASM backend
3. Implement async with `wasm-bindgen-futures`
4. Pure-Rust CSR generation with `p256`/`p384`

### Phase 4: WASI Client (Future)
1. Wait for WASI Preview 3 (async support)
2. Evaluate WASI-crypto adoption
3. Implement full client for WASI runtimes

## Code Changes Required

### New Feature Flags

```toml
[features]
# ... existing features ...
wasm = []  # Enable WASM-compatible code paths
wasi = ["wasm"]  # WASI-specific support
```

### Conditional Compilation

```rust
// In src/lib.rs
#[cfg(not(target_arch = "wasm32"))]
mod native_client;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod wasm_client;

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
mod wasi_client;
```

### Alternative HTTP Client

```rust
#[cfg(target_arch = "wasm32")]
use gloo_net::http::Request;  // or web-sys fetch

#[cfg(not(target_arch = "wasm32"))]
use reqwest::Client;
```

## Testing WASM Compilation

```bash
# Add WASM target
rustup target add wasm32-unknown-unknown

# Test compilation (will fail with current code)
cargo build --target wasm32-unknown-unknown --no-default-features

# Test with WASI target
rustup target add wasm32-wasi
cargo build --target wasm32-wasi --no-default-features
```

## References

- [Rust and WebAssembly](https://rustwasm.github.io/)
- [reqwest WASM documentation](https://docs.rs/reqwest/latest/wasm32-unknown-unknown/reqwest/)
- [tokio-with-wasm](https://github.com/cunarist/tokio-with-wasm)
- [WasmEdge reqwest demo](https://github.com/WasmEdge/wasmedge_reqwest_demo)
- [ring WASM issue #918](https://github.com/briansmith/ring/issues/918)
- [RustCrypto formats](https://github.com/RustCrypto/formats)

## Conclusion

Full WASM support for `usg-est-client` is **not currently feasible** due to the TLS stack dependency on `ring`. However, partial support is achievable:

1. **Browser WASM**: Possible with significant refactoring to use browser-native fetch/TLS
2. **WASI**: Partially possible with WasmEdge patches, full support awaiting WASI Preview 3
3. **Types-only library**: Achievable now for certificate/CSR parsing without networking

The recommended path is to first create a minimal pure-Rust types library, then incrementally add browser WASM support for the full client.
