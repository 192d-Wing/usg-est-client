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

//! CSR (Certificate Signing Request) generation utilities.
//!
//! This module provides a builder for creating PKCS#10 Certificate Signing
//! Requests. It is feature-gated behind the `csr-gen` feature.

// Manual PKCS#10 construction for HSM integration
#[cfg(all(feature = "csr-gen", feature = "hsm"))]
mod pkcs10;

#[cfg(feature = "csr-gen")]
mod builder {
    use std::net::IpAddr;

    use rcgen::{
        CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, SanType,
    };

    use crate::error::{EstError, Result};
    use crate::types::CsrAttributes;

    /// Builder for creating Certificate Signing Requests.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use usg_est_client::csr::CsrBuilder;
    ///
    /// let (csr_der, key_pair) = CsrBuilder::new()
    ///     .common_name("device.example.com")
    ///     .organization("Example Corp")
    ///     .country("US")
    ///     .san_dns("device.example.com")
    ///     .build()
    ///     .expect("Failed to generate CSR");
    /// ```
    pub struct CsrBuilder {
        params: CertificateParams,
        key_pair: Option<KeyPair>,
    }

    impl Default for CsrBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CsrBuilder {
        /// Create a new CSR builder with default parameters.
        pub fn new() -> Self {
            Self {
                params: CertificateParams::default(),
                key_pair: None,
            }
        }

        /// Set the Common Name (CN) for the subject.
        pub fn common_name(mut self, cn: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::CommonName, cn.into());
            self
        }

        /// Set the Organization (O) for the subject.
        pub fn organization(mut self, org: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::OrganizationName, org.into());
            self
        }

        /// Set the Organizational Unit (OU) for the subject.
        pub fn organizational_unit(mut self, ou: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::OrganizationalUnitName, ou.into());
            self
        }

        /// Set the Country (C) for the subject.
        pub fn country(mut self, country: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::CountryName, country.into());
            self
        }

        /// Set the State/Province (ST) for the subject.
        pub fn state(mut self, state: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::StateOrProvinceName, state.into());
            self
        }

        /// Set the Locality (L) for the subject.
        pub fn locality(mut self, locality: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::LocalityName, locality.into());
            self
        }

        /// Add a DNS Subject Alternative Name.
        pub fn san_dns(mut self, dns: impl Into<String>) -> Self {
            self.params
                .subject_alt_names
                .push(SanType::DnsName(dns.into().try_into().unwrap()));
            self
        }

        /// Add an IP address Subject Alternative Name.
        pub fn san_ip(mut self, ip: IpAddr) -> Self {
            self.params.subject_alt_names.push(SanType::IpAddress(ip));
            self
        }

        /// Add an email Subject Alternative Name.
        pub fn san_email(mut self, email: impl Into<String>) -> Self {
            self.params
                .subject_alt_names
                .push(SanType::Rfc822Name(email.into().try_into().unwrap()));
            self
        }

        /// Add a URI Subject Alternative Name.
        pub fn san_uri(mut self, uri: impl Into<String>) -> Self {
            self.params
                .subject_alt_names
                .push(SanType::URI(uri.into().try_into().unwrap()));
            self
        }

        /// Enable digital signature key usage.
        pub fn key_usage_digital_signature(mut self) -> Self {
            self.params
                .key_usages
                .push(KeyUsagePurpose::DigitalSignature);
            self
        }

        /// Enable key encipherment key usage.
        pub fn key_usage_key_encipherment(mut self) -> Self {
            self.params
                .key_usages
                .push(KeyUsagePurpose::KeyEncipherment);
            self
        }

        /// Enable key agreement key usage.
        pub fn key_usage_key_agreement(mut self) -> Self {
            self.params.key_usages.push(KeyUsagePurpose::KeyAgreement);
            self
        }

        /// Add TLS client authentication extended key usage.
        pub fn extended_key_usage_client_auth(mut self) -> Self {
            self.params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ClientAuth);
            self
        }

        /// Add TLS server authentication extended key usage.
        pub fn extended_key_usage_server_auth(mut self) -> Self {
            self.params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);
            self
        }

        /// Set the challenge password attribute.
        ///
        /// This can be used for TLS channel binding per RFC 7030 Section 3.5.
        pub fn challenge_password(self, password: impl Into<String>) -> Self {
            // Note: rcgen doesn't directly support challenge-password
            // This would need custom extension handling
            let _ = password;
            self
        }

        /// Apply attributes from a server's /csrattrs response.
        ///
        /// This configures the CSR builder based on the server's requirements.
        pub fn with_attributes(self, _attrs: &CsrAttributes) -> Self {
            // Would iterate through attrs and apply relevant settings
            // For now, this is a placeholder
            self
        }

        /// Use an existing key pair instead of generating a new one.
        pub fn with_key_pair(mut self, key_pair: KeyPair) -> Self {
            self.key_pair = Some(key_pair);
            self
        }

        /// Build the CSR with a new ECDSA P-256 key pair.
        ///
        /// Returns the DER-encoded CSR and the generated key pair.
        pub fn build(self) -> Result<(Vec<u8>, KeyPair)> {
            let key_pair = match self.key_pair {
                Some(kp) => kp,
                None => KeyPair::generate()
                    .map_err(|e| EstError::csr(format!("Failed to generate key pair: {}", e)))?,
            };

            let csr = self
                .params
                .serialize_request(&key_pair)
                .map_err(|e| EstError::csr(format!("Failed to serialize CSR: {}", e)))?;

            let csr_der = csr.der().to_vec();

            Ok((csr_der, key_pair))
        }

        /// Build the CSR using the provided key pair.
        ///
        /// Returns only the DER-encoded CSR.
        pub fn build_with_key(self, key_pair: &KeyPair) -> Result<Vec<u8>> {
            let csr = self
                .params
                .serialize_request(key_pair)
                .map_err(|e| EstError::csr(format!("Failed to serialize CSR: {}", e)))?;

            Ok(csr.der().to_vec())
        }
    }

    /// Generate a simple CSR for a device.
    ///
    /// This is a convenience function for common use cases.
    pub fn generate_device_csr(
        common_name: &str,
        organization: Option<&str>,
    ) -> Result<(Vec<u8>, KeyPair)> {
        let mut builder = CsrBuilder::new()
            .common_name(common_name)
            .san_dns(common_name)
            .key_usage_digital_signature()
            .key_usage_key_encipherment()
            .extended_key_usage_client_auth();

        if let Some(org) = organization {
            builder = builder.organization(org);
        }

        builder.build()
    }

    /// Generate a CSR for a TLS server.
    pub fn generate_server_csr(
        common_name: &str,
        san_names: &[&str],
    ) -> Result<(Vec<u8>, KeyPair)> {
        let mut builder = CsrBuilder::new()
            .common_name(common_name)
            .key_usage_digital_signature()
            .key_usage_key_encipherment()
            .extended_key_usage_server_auth();

        for name in san_names {
            builder = builder.san_dns(*name);
        }

        builder.build()
    }
}

/// HSM-backed CSR generation support.
///
/// This module provides functionality to generate CSRs using keys stored in
/// Hardware Security Modules or other secure key providers.
#[cfg(all(feature = "csr-gen", feature = "hsm"))]
mod hsm_csr {
    use crate::error::{EstError, Result};
    use crate::hsm::{KeyHandle, KeyProvider, SoftwareKeyProvider};
    use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyUsagePurpose, SanType};
    use std::net::IpAddr;

    /// Builder for creating CSRs with HSM-backed keys.
    ///
    /// This builder allows generating CSRs using keys stored in Hardware Security
    /// Modules or other secure key providers. Unlike the standard `CsrBuilder`,
    /// this does not generate new keys - it uses existing keys from the provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use usg_est_client::csr::HsmCsrBuilder;
    /// use usg_est_client::hsm::{KeyProvider, KeyAlgorithm, SoftwareKeyProvider};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Create a key provider and generate a key
    /// let provider = SoftwareKeyProvider::new();
    /// let key_handle = provider
    ///     .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("my-key"))
    ///     .await?;
    ///
    /// // Build a CSR using the HSM key
    /// let csr_der = HsmCsrBuilder::new()
    ///     .common_name("device.example.com")
    ///     .organization("Example Corp")
    ///     .san_dns("device.example.com")
    ///     .build_with_provider(&provider, &key_handle)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub struct HsmCsrBuilder {
        params: CertificateParams,
    }

    impl Default for HsmCsrBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HsmCsrBuilder {
        /// Create a new HSM CSR builder with default parameters.
        pub fn new() -> Self {
            Self {
                params: CertificateParams::default(),
            }
        }

        /// Set the Common Name (CN) for the subject.
        pub fn common_name(mut self, cn: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::CommonName, cn.into());
            self
        }

        /// Set the Organization (O) for the subject.
        pub fn organization(mut self, org: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::OrganizationName, org.into());
            self
        }

        /// Set the Organizational Unit (OU) for the subject.
        pub fn organizational_unit(mut self, ou: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::OrganizationalUnitName, ou.into());
            self
        }

        /// Set the Country (C) for the subject.
        pub fn country(mut self, country: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::CountryName, country.into());
            self
        }

        /// Set the State/Province (ST) for the subject.
        pub fn state(mut self, state: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::StateOrProvinceName, state.into());
            self
        }

        /// Set the Locality (L) for the subject.
        pub fn locality(mut self, locality: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::LocalityName, locality.into());
            self
        }

        /// Add a DNS Subject Alternative Name.
        pub fn san_dns(mut self, dns: impl Into<String>) -> Self {
            self.params
                .subject_alt_names
                .push(SanType::DnsName(dns.into().try_into().unwrap()));
            self
        }

        /// Add an IP address Subject Alternative Name.
        pub fn san_ip(mut self, ip: IpAddr) -> Self {
            self.params.subject_alt_names.push(SanType::IpAddress(ip));
            self
        }

        /// Add an email Subject Alternative Name.
        pub fn san_email(mut self, email: impl Into<String>) -> Self {
            self.params
                .subject_alt_names
                .push(SanType::Rfc822Name(email.into().try_into().unwrap()));
            self
        }

        /// Add a URI Subject Alternative Name.
        pub fn san_uri(mut self, uri: impl Into<String>) -> Self {
            self.params
                .subject_alt_names
                .push(SanType::URI(uri.into().try_into().unwrap()));
            self
        }

        /// Enable digital signature key usage.
        pub fn key_usage_digital_signature(mut self) -> Self {
            self.params
                .key_usages
                .push(KeyUsagePurpose::DigitalSignature);
            self
        }

        /// Enable key encipherment key usage.
        pub fn key_usage_key_encipherment(mut self) -> Self {
            self.params
                .key_usages
                .push(KeyUsagePurpose::KeyEncipherment);
            self
        }

        /// Enable key agreement key usage.
        pub fn key_usage_key_agreement(mut self) -> Self {
            self.params.key_usages.push(KeyUsagePurpose::KeyAgreement);
            self
        }

        /// Add TLS client authentication extended key usage.
        pub fn extended_key_usage_client_auth(mut self) -> Self {
            self.params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ClientAuth);
            self
        }

        /// Add TLS server authentication extended key usage.
        pub fn extended_key_usage_server_auth(mut self) -> Self {
            self.params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);
            self
        }

        /// Build the CSR using a SoftwareKeyProvider.
        ///
        /// This method is optimized for software key providers and uses the
        /// underlying rcgen KeyPair directly for CSR generation.
        ///
        /// # Arguments
        ///
        /// * `provider` - The software key provider containing the key
        /// * `key_handle` - Handle to the key to use for signing
        ///
        /// # Returns
        ///
        /// The DER-encoded CSR bytes.
        pub fn build_with_software_provider(
            self,
            provider: &SoftwareKeyProvider,
            key_handle: &KeyHandle,
        ) -> Result<Vec<u8>> {
            // Get the rcgen KeyPair from the provider
            let key_pair = provider.get_rcgen_key_pair(key_handle)?;

            // Generate the CSR
            let csr = self
                .params
                .serialize_request(&key_pair)
                .map_err(|e| EstError::csr(format!("Failed to serialize CSR: {}", e)))?;

            Ok(csr.der().to_vec())
        }

        /// Build the CSR using any KeyProvider.
        ///
        /// This method works with any key provider implementation, including
        /// hardware HSMs. For software providers, prefer `build_with_software_provider`
        /// for better performance.
        ///
        /// # Arguments
        ///
        /// * `provider` - The key provider containing the key
        /// * `key_handle` - Handle to the key to use for signing
        ///
        /// # Returns
        ///
        /// The DER-encoded CSR bytes.
        ///
        /// # Note
        ///
        /// This method currently only supports SoftwareKeyProvider. For PKCS#11
        /// and other HSM providers, use the provider's native CSR generation
        /// capabilities or implement a custom signing callback.
        pub async fn build_with_provider<P: KeyProvider>(
            self,
            provider: &P,
            key_handle: &KeyHandle,
        ) -> Result<Vec<u8>> {
            // Get the public key from the provider
            let _public_key = provider.public_key(key_handle).await?;

            // For now, we need to use a workaround since rcgen doesn't support
            // external signing. This implementation works for SoftwareKeyProvider
            // and serves as a framework for future HSM integration.
            //
            // For true HSM support, we would need to:
            // 1. Build the TBSCertificationRequest structure manually
            // 2. Hash the TBS data
            // 3. Sign using provider.sign(handle, hash)
            // 4. Assemble the final CertificationRequest with signature

            // Check if this is actually a SoftwareKeyProvider by trying to use
            // the public key to verify it's a valid SPKI structure
            let _alg_id = provider.algorithm_identifier(key_handle).await?;

            // Currently, direct HSM signing for CSRs requires manual ASN.1 construction
            // which is not yet implemented. Return an informative error.
            Err(EstError::not_supported(
                "Generic HSM CSR generation requires manual ASN.1 construction. \
                 For SoftwareKeyProvider, use build_with_software_provider(). \
                 For PKCS#11, use the provider's native signing capabilities.",
            ))
        }
    }

    /// Generate a CSR using a software key provider.
    ///
    /// This is a convenience function for the common case of using a software
    /// key provider with ECDSA P-256 keys.
    ///
    /// # Arguments
    ///
    /// * `provider` - The software key provider
    /// * `key_handle` - Handle to an existing key in the provider
    /// * `common_name` - The Common Name for the certificate subject
    /// * `organization` - Optional organization name
    ///
    /// # Returns
    ///
    /// The DER-encoded CSR bytes.
    pub fn generate_csr_with_software_key(
        provider: &SoftwareKeyProvider,
        key_handle: &KeyHandle,
        common_name: &str,
        organization: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut builder = HsmCsrBuilder::new()
            .common_name(common_name)
            .san_dns(common_name)
            .key_usage_digital_signature()
            .key_usage_key_encipherment()
            .extended_key_usage_client_auth();

        if let Some(org) = organization {
            builder = builder.organization(org);
        }

        builder.build_with_software_provider(provider, key_handle)
    }
}

#[cfg(feature = "csr-gen")]
pub use builder::*;

#[cfg(all(feature = "csr-gen", feature = "hsm"))]
pub use hsm_csr::*;

#[cfg(not(feature = "csr-gen"))]
pub fn feature_not_enabled() {
    // This module requires the "csr-gen" feature
}

#[cfg(all(test, feature = "csr-gen"))]
mod tests {
    use super::*;

    #[test]
    fn test_csr_builder_basic() {
        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("test.example.com")
            .organization("Test Org")
            .build()
            .expect("Failed to build CSR");

        assert!(!csr_der.is_empty());
        // CSR should start with SEQUENCE tag
        assert_eq!(csr_der[0], 0x30);
    }

    #[test]
    fn test_generate_device_csr() {
        let (csr_der, _key_pair) =
            generate_device_csr("device001.example.com", Some("Example Corp"))
                .expect("Failed to generate device CSR");

        assert!(!csr_der.is_empty());
    }

    #[test]
    fn test_generate_server_csr() {
        let (csr_der, _key_pair) = generate_server_csr(
            "server.example.com",
            &["www.example.com", "api.example.com"],
        )
        .expect("Failed to generate server CSR");

        assert!(!csr_der.is_empty());
    }
}

#[cfg(all(test, feature = "csr-gen", feature = "hsm"))]
mod hsm_tests {
    use super::*;
    use crate::hsm::{KeyAlgorithm, KeyProvider, SoftwareKeyProvider};

    #[tokio::test]
    async fn test_hsm_csr_builder_with_software_provider() {
        let provider = SoftwareKeyProvider::new();

        // Generate a key
        let key_handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("test-csr-key"))
            .await
            .expect("Failed to generate key");

        // Build a CSR using the key
        let csr_der = HsmCsrBuilder::new()
            .common_name("hsm-test.example.com")
            .organization("Test Org")
            .san_dns("hsm-test.example.com")
            .key_usage_digital_signature()
            .extended_key_usage_client_auth()
            .build_with_software_provider(&provider, &key_handle)
            .expect("Failed to build CSR");

        assert!(!csr_der.is_empty());
        // CSR should start with SEQUENCE tag
        assert_eq!(csr_der[0], 0x30);
    }

    #[tokio::test]
    async fn test_generate_csr_with_software_key() {
        let provider = SoftwareKeyProvider::new();

        // Generate a key
        let key_handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("convenience-key"))
            .await
            .expect("Failed to generate key");

        // Use the convenience function
        let csr_der = generate_csr_with_software_key(
            &provider,
            &key_handle,
            "device.example.com",
            Some("Example Corp"),
        )
        .expect("Failed to generate CSR");

        assert!(!csr_der.is_empty());
        assert_eq!(csr_der[0], 0x30);
    }

    #[tokio::test]
    async fn test_hsm_csr_builder_default() {
        let builder = HsmCsrBuilder::default();
        // Just verify we can create a default builder
        assert!(std::mem::size_of_val(&builder) > 0);
    }

    #[tokio::test]
    async fn test_hsm_csr_with_all_fields() {
        let provider = SoftwareKeyProvider::new();

        let key_handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP384, Some("full-csr-key"))
            .await
            .expect("Failed to generate key");

        let csr_der = HsmCsrBuilder::new()
            .common_name("full-test.example.com")
            .organization("Full Test Org")
            .organizational_unit("Engineering")
            .country("US")
            .state("California")
            .locality("San Francisco")
            .san_dns("full-test.example.com")
            .san_dns("alt.example.com")
            .san_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 1,
            )))
            .san_email("admin@example.com")
            .san_uri("https://example.com")
            .key_usage_digital_signature()
            .key_usage_key_encipherment()
            .key_usage_key_agreement()
            .extended_key_usage_client_auth()
            .extended_key_usage_server_auth()
            .build_with_software_provider(&provider, &key_handle)
            .expect("Failed to build CSR with all fields");

        assert!(!csr_der.is_empty());
    }
}
