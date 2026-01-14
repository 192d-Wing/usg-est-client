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
        ///
        /// # Panics
        ///
        /// Panics if the DNS name is invalid (e.g., contains invalid characters).
        /// Ensure DNS names conform to RFC 1035 before calling this method.
        pub fn san_dns(mut self, dns: impl Into<String>) -> Self {
            let dns_str = dns.into();
            let dns_name = dns_str.as_str().try_into().unwrap_or_else(|_| {
                panic!(
                    "Invalid DNS name for SAN: '{}'. DNS names must conform to RFC 1035. \
                     Check for invalid characters or excessive length.",
                    dns_str
                )
            });
            self.params
                .subject_alt_names
                .push(SanType::DnsName(dns_name));
            self
        }

        /// Add an IP address Subject Alternative Name.
        pub fn san_ip(mut self, ip: IpAddr) -> Self {
            self.params.subject_alt_names.push(SanType::IpAddress(ip));
            self
        }

        /// Add an email Subject Alternative Name.
        ///
        /// # Panics
        ///
        /// Panics if the email address is invalid according to RFC 822.
        /// Ensure email addresses are properly formatted before calling this method.
        pub fn san_email(mut self, email: impl Into<String>) -> Self {
            let email_str = email.into();
            let email_addr = email_str.as_str().try_into().unwrap_or_else(|_| {
                panic!(
                    "Invalid email address for SAN: '{}'. Email must conform to RFC 822. \
                     Check for proper format (user@domain.com).",
                    email_str
                )
            });
            self.params
                .subject_alt_names
                .push(SanType::Rfc822Name(email_addr));
            self
        }

        /// Add a URI Subject Alternative Name.
        ///
        /// # Panics
        ///
        /// Panics if the URI is invalid according to RFC 3986.
        /// Ensure URIs are properly formatted before calling this method.
        pub fn san_uri(mut self, uri: impl Into<String>) -> Self {
            let uri_str = uri.into();
            let uri_value = uri_str.as_str().try_into().unwrap_or_else(|_| {
                panic!(
                    "Invalid URI for SAN: '{}'. URI must conform to RFC 3986. \
                     Check for proper scheme and format (e.g., https://example.com).",
                    uri_str
                )
            });
            self.params.subject_alt_names.push(SanType::URI(uri_value));
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
    use rcgen::{
        CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose, KeyUsagePurpose, SanType,
    };
    use std::net::IpAddr;
    use std::str::FromStr;
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;

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
        ///
        /// # Panics
        ///
        /// Panics if the DNS name is invalid (e.g., contains invalid characters).
        /// Ensure DNS names conform to RFC 1035 before calling this method.
        pub fn san_dns(mut self, dns: impl Into<String>) -> Self {
            let dns_str = dns.into();
            let dns_name = dns_str.as_str().try_into().unwrap_or_else(|_| {
                panic!(
                    "Invalid DNS name for SAN: '{}'. DNS names must conform to RFC 1035. \
                     Check for invalid characters or excessive length.",
                    dns_str
                )
            });
            self.params
                .subject_alt_names
                .push(SanType::DnsName(dns_name));
            self
        }

        /// Add an IP address Subject Alternative Name.
        pub fn san_ip(mut self, ip: IpAddr) -> Self {
            self.params.subject_alt_names.push(SanType::IpAddress(ip));
            self
        }

        /// Add an email Subject Alternative Name.
        ///
        /// # Panics
        ///
        /// Panics if the email address is invalid according to RFC 822.
        /// Ensure email addresses are properly formatted before calling this method.
        pub fn san_email(mut self, email: impl Into<String>) -> Self {
            let email_str = email.into();
            let email_addr = email_str.as_str().try_into().unwrap_or_else(|_| {
                panic!(
                    "Invalid email address for SAN: '{}'. Email must conform to RFC 822. \
                     Check for proper format (user@domain.com).",
                    email_str
                )
            });
            self.params
                .subject_alt_names
                .push(SanType::Rfc822Name(email_addr));
            self
        }

        /// Add a URI Subject Alternative Name.
        ///
        /// # Panics
        ///
        /// Panics if the URI is invalid according to RFC 3986.
        /// Ensure URIs are properly formatted before calling this method.
        pub fn san_uri(mut self, uri: impl Into<String>) -> Self {
            let uri_str = uri.into();
            let uri_value = uri_str.as_str().try_into().unwrap_or_else(|_| {
                panic!(
                    "Invalid URI for SAN: '{}'. URI must conform to RFC 3986. \
                     Check for proper scheme and format (e.g., https://example.com).",
                    uri_str
                )
            });
            self.params.subject_alt_names.push(SanType::URI(uri_value));
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
        /// hardware HSMs. It uses manual PKCS#10 construction to generate CSRs
        /// without requiring direct access to private key material.
        ///
        /// # Arguments
        ///
        /// * `provider` - The key provider containing the key
        /// * `key_handle` - Handle to the key to use for signing
        ///
        /// # Returns
        ///
        /// The DER-encoded CSR bytes.
        pub async fn build_with_provider<P: KeyProvider>(
            self,
            provider: &P,
            key_handle: &KeyHandle,
        ) -> Result<Vec<u8>> {
            use der::Encode;

            // Get the public key from the provider
            let public_key = provider.public_key(key_handle).await?;

            // Get the key algorithm for hash selection
            let key_algorithm = key_handle.algorithm();

            // Convert rcgen DistinguishedName to x509_cert Name
            let subject = self.build_subject_name()?;

            // Build extensions and attributes
            let mut extensions = Vec::new();

            // Add Subject Alternative Names if present
            if !self.params.subject_alt_names.is_empty() {
                let san_ext = self.build_san_extension()?;
                extensions.push(san_ext);
            }

            // Add KeyUsage extension if present
            if !self.params.key_usages.is_empty() {
                let key_usage_ext = self.build_key_usage_extension()?;
                extensions.push(key_usage_ext);
            }

            // Create attributes list
            let mut attributes = Vec::new();
            if !extensions.is_empty() {
                let ext_req_attr = super::pkcs10::create_extension_request_attribute(extensions)?;
                attributes.push(ext_req_attr);
            }

            // Build CertReqInfo
            let info = super::pkcs10::build_cert_req_info(subject, public_key, attributes)?;

            // Encode and hash
            let (_tbs_der, digest) = super::pkcs10::encode_and_hash(&info, key_algorithm)?;

            // Sign the digest using the provider
            let signature_bytes = provider.sign(key_handle, &digest).await?;

            // Get algorithm identifier
            let algorithm = provider.algorithm_identifier(key_handle).await?;

            // Assemble final CSR
            let cert_req = super::pkcs10::assemble_cert_req(info, algorithm, signature_bytes)?;

            // Encode to DER
            let csr_der = cert_req
                .to_der()
                .map_err(|e| EstError::csr(format!("Failed to encode CSR: {}", e)))?;

            Ok(csr_der)
        }

        /// Convert rcgen DistinguishedName to x509_cert Name.
        fn build_subject_name(&self) -> Result<Name> {
            let dn_str = self.build_dn_string();

            // Parse the DN string into a Name
            Name::from_str(&dn_str)
                .map_err(|e| EstError::operational(format!("Failed to parse DN: {}", e)))
        }

        /// Build a DN string from rcgen DistinguishedName.
        fn build_dn_string(&self) -> String {
            let mut parts = Vec::new();

            for (dn_type, value) in self.params.distinguished_name.iter() {
                let attr_name = match dn_type {
                    DnType::CommonName => "CN",
                    DnType::OrganizationName => "O",
                    DnType::OrganizationalUnitName => "OU",
                    DnType::CountryName => "C",
                    DnType::StateOrProvinceName => "ST",
                    DnType::LocalityName => "L",
                    _ => continue, // Skip unsupported DN types
                };

                // Extract string value from DnValue enum
                // For most use cases, we only expect Utf8String and PrintableString
                let value_str = match value {
                    DnValue::Utf8String(s) => s.as_str(),
                    DnValue::PrintableString(s) => s.as_ref(),
                    DnValue::Ia5String(s) => s.as_ref(),
                    DnValue::TeletexString(s) => s.as_ref(),
                    // BmpString and UniversalString are rare, just skip them for now
                    _ => continue,
                };

                parts.push(format!("{}={}", attr_name, value_str));
            }

            parts.join(",")
        }

        /// Build Subject Alternative Name extension.
        fn build_san_extension(&self) -> Result<Extension> {
            use der::Encode;
            use der::asn1::OctetString;
            use x509_cert::ext::pkix::SubjectAltName;
            use x509_cert::ext::pkix::name::GeneralName;

            let mut general_names = Vec::new();

            for san in &self.params.subject_alt_names {
                let general_name = match san {
                    SanType::DnsName(name) => {
                        let ia5_str = der::asn1::Ia5String::new(name.as_ref()).map_err(|e| {
                            EstError::operational(format!("Invalid DNS name: {}", e))
                        })?;
                        GeneralName::DnsName(ia5_str)
                    }
                    SanType::IpAddress(ip) => {
                        let octets = match ip {
                            IpAddr::V4(v4) => v4.octets().to_vec(),
                            IpAddr::V6(v6) => v6.octets().to_vec(),
                        };
                        GeneralName::IpAddress(OctetString::new(octets).map_err(|e| {
                            EstError::operational(format!("Invalid IP address: {}", e))
                        })?)
                    }
                    SanType::URI(uri) => {
                        let ia5_str = der::asn1::Ia5String::new(uri.as_ref())
                            .map_err(|e| EstError::operational(format!("Invalid URI: {}", e)))?;
                        GeneralName::UniformResourceIdentifier(ia5_str)
                    }
                    _ => {
                        return Err(EstError::operational("Unsupported SAN type"));
                    }
                };
                general_names.push(general_name);
            }

            // Create SubjectAltName
            let san = SubjectAltName(general_names);

            // Encode to DER
            let san_der = san
                .to_der()
                .map_err(|e| EstError::operational(format!("Failed to encode SAN: {}", e)))?;

            // Create Extension
            Ok(Extension {
                extn_id: const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME,
                critical: false,
                extn_value: OctetString::new(san_der).map_err(|e| {
                    EstError::operational(format!("Failed to create OctetString: {}", e))
                })?,
            })
        }

        /// Build KeyUsage extension.
        fn build_key_usage_extension(&self) -> Result<Extension> {
            let mut digital_signature = false;
            let mut key_encipherment = false;
            let mut key_agreement = false;

            for usage in &self.params.key_usages {
                match usage {
                    KeyUsagePurpose::DigitalSignature => digital_signature = true,
                    KeyUsagePurpose::KeyEncipherment => key_encipherment = true,
                    KeyUsagePurpose::KeyAgreement => key_agreement = true,
                    _ => {} // Ignore other key usages for now
                }
            }

            super::pkcs10::create_key_usage_extension(
                digital_signature,
                key_encipherment,
                key_agreement,
            )
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

    #[tokio::test]
    async fn test_build_with_provider_p256() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let provider = SoftwareKeyProvider::new();

        // Generate P-256 key
        let key_handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("provider-p256-key"))
            .await
            .expect("Failed to generate key");

        // Build CSR using build_with_provider (generic method)
        let csr_der = HsmCsrBuilder::new()
            .common_name("provider-test.example.com")
            .organization("Provider Test Org")
            .san_dns("provider-test.example.com")
            .key_usage_digital_signature()
            .key_usage_key_agreement()
            .extended_key_usage_client_auth()
            .build_with_provider(&provider, &key_handle)
            .await
            .expect("Failed to build CSR with provider");

        // Verify CSR is not empty
        assert!(!csr_der.is_empty());

        // Verify CSR can be parsed
        let cert_req = CertReq::from_der(&csr_der).expect("Failed to parse CSR");

        // Verify subject
        assert!(
            cert_req
                .info
                .subject
                .to_string()
                .contains("provider-test.example.com")
        );

        // Verify signature is present
        assert!(!cert_req.signature.as_bytes().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_build_with_provider_p384() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let provider = SoftwareKeyProvider::new();

        // Generate P-384 key
        let key_handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP384, Some("provider-p384-key"))
            .await
            .expect("Failed to generate key");

        // Build CSR using build_with_provider
        let csr_der = HsmCsrBuilder::new()
            .common_name("p384-test.example.com")
            .organization("P384 Test Org")
            .san_dns("p384-test.example.com")
            .san_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)))
            .key_usage_digital_signature()
            .extended_key_usage_server_auth()
            .build_with_provider(&provider, &key_handle)
            .await
            .expect("Failed to build CSR with P-384 key");

        // Verify CSR is valid
        assert!(!csr_der.is_empty());

        // Parse and verify
        let cert_req = CertReq::from_der(&csr_der).expect("Failed to parse P-384 CSR");

        assert!(
            cert_req
                .info
                .subject
                .to_string()
                .contains("p384-test.example.com")
        );
    }

    #[tokio::test]
    async fn test_build_with_provider_multiple_sans() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let provider = SoftwareKeyProvider::new();

        let key_handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("multi-san-key"))
            .await
            .expect("Failed to generate key");

        // Build CSR with multiple SANs of different types
        let csr_der = HsmCsrBuilder::new()
            .common_name("multi-san.example.com")
            .san_dns("multi-san.example.com")
            .san_dns("alt1.example.com")
            .san_dns("alt2.example.com")
            .san_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 100,
            )))
            .san_uri("https://api.example.com")
            .key_usage_digital_signature()
            .build_with_provider(&provider, &key_handle)
            .await
            .expect("Failed to build CSR with multiple SANs");

        assert!(!csr_der.is_empty());

        // Verify it parses correctly
        let cert_req = CertReq::from_der(&csr_der).expect("Failed to parse multi-SAN CSR");

        // Verify attributes are present (SANs are in extension request attribute)
        assert!(!cert_req.info.attributes.is_empty());
    }
}
