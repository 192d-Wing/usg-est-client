// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! rustls integration for PKCS#11 token-held keys.
//!
//! Bridges a [`Pkcs11KeyProvider`] key into rustls so a TLS endpoint can
//! authenticate with a private key that never leaves the token:
//!
//! - [`Pkcs11SigningKey`] — a rustls [`SigningKey`] whose handshake signatures
//!   are produced inside the token (via [`Pkcs11KeyProvider::sign_blocking`]).
//! - [`Pkcs11ClientCertResolver`] — a [`ResolvesClientCert`] presenting one
//!   token-backed identity, for EST `simplereenroll` mutual-TLS where the node's
//!   key is in a TPM/HSM (the EST [`ClientIdentity`](crate::config::ClientIdentity)
//!   is PEM-only and cannot carry a non-extractable key).
//!
//! `Pkcs11SigningKey` is deliberately public and reusable: a TLS *server*
//! (e.g. a management API) can wrap it in a [`CertifiedKey`] and its own
//! `ResolvesServerCert` to serve with a token-held key.

use std::sync::Arc;

use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{Error as RustlsError, SignatureAlgorithm, SignatureScheme};

use super::pkcs11::Pkcs11KeyProvider;
use super::{KeyAlgorithm, KeyHandle};

/// Map a token key's algorithm to its TLS signature scheme + algorithm. The
/// schemes match the hash-and-sign mechanisms [`Pkcs11KeyProvider::sign_blocking`]
/// uses (SHA-256 for P-256/RSA, SHA-384 for P-384) and the DER signature
/// encoding the provider returns.
fn scheme_for(algorithm: KeyAlgorithm) -> (SignatureScheme, SignatureAlgorithm) {
    match algorithm {
        KeyAlgorithm::EcdsaP256 => (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureAlgorithm::ECDSA,
        ),
        KeyAlgorithm::EcdsaP384 => (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureAlgorithm::ECDSA,
        ),
        KeyAlgorithm::Rsa { .. } => (SignatureScheme::RSA_PKCS1_SHA256, SignatureAlgorithm::RSA),
    }
}

/// A rustls [`SigningKey`] backed by a PKCS#11 token key.
///
/// The private key never leaves the token: handshake signing is delegated to
/// [`Pkcs11KeyProvider::sign_blocking`], which returns a DER-encoded signature
/// in the form rustls expects.
#[derive(Clone)]
pub struct Pkcs11SigningKey {
    provider: Arc<Pkcs11KeyProvider>,
    handle: KeyHandle,
    scheme: SignatureScheme,
    algorithm: SignatureAlgorithm,
}

impl Pkcs11SigningKey {
    /// Wrap a token key (identified by `handle`) as a rustls signing key.
    pub fn new(provider: Arc<Pkcs11KeyProvider>, handle: KeyHandle) -> Self {
        let (scheme, algorithm) = scheme_for(handle.algorithm());
        Self {
            provider,
            handle,
            scheme,
            algorithm,
        }
    }
}

impl std::fmt::Debug for Pkcs11SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11SigningKey")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl SigningKey for Pkcs11SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&self.scheme).then(|| {
            Box::new(Pkcs11Signer {
                provider: self.provider.clone(),
                handle: self.handle.clone(),
                scheme: self.scheme,
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// The active signer for a single negotiated scheme (one per handshake).
struct Pkcs11Signer {
    provider: Arc<Pkcs11KeyProvider>,
    handle: KeyHandle,
    scheme: SignatureScheme,
}

impl std::fmt::Debug for Pkcs11Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl Signer for Pkcs11Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        self.provider
            .sign_blocking(&self.handle, message)
            .map_err(|e| RustlsError::General(format!("PKCS#11 TLS signing failed: {e}")))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// A [`ResolvesClientCert`] presenting one token-backed client identity.
///
/// Use as the client-auth resolver for EST `simplereenroll` when the node's key
/// lives in a TPM/HSM. The certificate chain is the node's current certificate
/// (leaf first); the matching private key stays in the token.
#[derive(Debug)]
pub struct Pkcs11ClientCertResolver {
    certified_key: Arc<CertifiedKey>,
    scheme: SignatureScheme,
}

impl Pkcs11ClientCertResolver {
    /// Build a resolver from a token key and the node's current certificate
    /// chain (DER, leaf first).
    pub fn new(
        provider: Arc<Pkcs11KeyProvider>,
        handle: KeyHandle,
        cert_chain: Vec<CertificateDer<'static>>,
    ) -> Self {
        let (scheme, _) = scheme_for(handle.algorithm());
        let signing_key = Arc::new(Pkcs11SigningKey::new(provider, handle)) as Arc<dyn SigningKey>;
        let certified_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));
        Self {
            certified_key,
            scheme,
        }
    }
}

impl ResolvesClientCert for Pkcs11ClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        // Only offer the identity if the server accepts our key's scheme.
        sigschemes
            .contains(&self.scheme)
            .then(|| self.certified_key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_mapping_matches_curves() {
        assert_eq!(
            scheme_for(KeyAlgorithm::EcdsaP256).0,
            SignatureScheme::ECDSA_NISTP256_SHA256
        );
        assert_eq!(
            scheme_for(KeyAlgorithm::EcdsaP384).0,
            SignatureScheme::ECDSA_NISTP384_SHA384
        );
        assert_eq!(
            scheme_for(KeyAlgorithm::EcdsaP256).1,
            SignatureAlgorithm::ECDSA
        );
    }
}
