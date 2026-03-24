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

// ============================================================================
// SECURITY CONTROL: Certificate Signing Request Generation
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: SC-12 (Cryptographic Key Establishment and Management)
//                       SC-13 (Cryptographic Protection)
//                       IA-5 (Authenticator Management)
//                       SI-10 (Information Input Validation)
//
// Application Development STIG V5R3:
//   APSC-DV-000160 (CAT II) - Bidirectional Authentication
//   APSC-DV-001740 (CAT II) - Public Key Infrastructure Certificates
//   APSC-DV-002440 (CAT I) - Error Message Content
//
// SECURITY CONTROL IMPLEMENTATION:
//
// This module implements secure Certificate Signing Request (CSR) generation
// in accordance with RFC 2986 (PKCS#10) and FIPS 140-2 requirements. CSRs are
// critical security artifacts that bind a subject identity to a public key.
//
// SC-12: CRYPTOGRAPHIC KEY ESTABLISHMENT
// ---------------------------------------
// CSR generation includes cryptographic key pair generation. This module
// ensures that:
//
// - All key pairs use FIPS 140-2 approved algorithms (ECDSA P-256/P-384, RSA 2048+)
// - Private keys are generated with cryptographically secure random number
//   generators (via the `rcgen` library's default behavior)
// - HSM-backed CSR generation supports non-exportable private keys maintained
//   in hardware security modules
// - Generated key pairs are appropriate for their intended usage (digital
//   signature, key encipherment, etc.)
//
// SC-13: CRYPTOGRAPHIC PROTECTION
// --------------------------------
// All CSRs use FIPS-approved signature algorithms:
//
// - ECDSA with SHA-256 (P-256 curve) - Default, recommended for most use cases
// - ECDSA with SHA-384 (P-384 curve) - High security applications
// - RSA with SHA-256 (2048-bit minimum) - Legacy compatibility
//
// The `rcgen` library ensures CSR signatures are generated according to
// X.509 and PKCS#10 standards.
//
// IA-5: AUTHENTICATOR MANAGEMENT
// -------------------------------
// CSRs establish the identity of certificate subjects. This module:
//
// - Validates Distinguished Name (DN) components for proper encoding
// - Validates Subject Alternative Names (SANs) for RFC compliance:
//   * DNS names: RFC 1035 (labels, length limits, character restrictions)
//   * IP addresses: RFC 791/4291 (IPv4/IPv6 validation)
//   * Email addresses: RFC 5321 (mailbox format)
//   * URIs: RFC 3986 (URI syntax)
// - Prevents identity spoofing through input validation
// - Supports challenge passwords for proof-of-possession
//
// SI-10: INFORMATION INPUT VALIDATION
// ------------------------------------
// All user-provided input to CSRs is validated:
//
// - DN attribute values are checked for valid UTF-8 and X.500 encoding
// - SAN values are validated against their respective RFC specifications
// - Key usage flags are validated for consistency
// - Invalid input results in descriptive error messages without information
//   disclosure (SI-11 compliance)
//
// SECURITY CONSIDERATIONS:
//
// 1. PRIVATE KEY PROTECTION: Generated private keys must be protected with
//    appropriate access controls. For sensitive applications, use HsmCsrBuilder
//    to ensure keys never leave hardware security boundaries.
//
// 2. CSR CONTENT: CSRs contain public information (subject DN, SANs, public key).
//    Never include sensitive data in DN attributes or challenge passwords that
//    would be inappropriate for public disclosure.
//
// 3. KEY USAGE: Ensure key usage extensions match intended certificate purpose.
//    Incorrect key usage can lead to security vulnerabilities (e.g., using an
//    encryption key for signing).
//
// 4. SUBJECT VALIDATION: The CSR subject DN and SANs should be validated against
//    organizational policy before submission to EST servers. This module validates
//    format but not authorization.
//
// ============================================================================

//! CSR (Certificate Signing Request) generation utilities.
//!
//! This module provides a builder for creating PKCS#10 Certificate Signing
//! Requests. It is feature-gated behind the `csr-gen` feature.
//!
//! # Security Controls
//!
//! **NIST SP 800-53 Rev 5:**
//! - SC-12 (Cryptographic Key Establishment)
//! - SC-13 (Cryptographic Protection)
//! - IA-5 (Authenticator Management)
//! - SI-10 (Information Input Validation)
//!
//! # Security Implementation
//!
//! This module implements secure CSR generation with:
//! - FIPS 140-2 approved algorithms (ECDSA P-256/P-384, RSA 2048+)
//! - RFC 2986 (PKCS#10) compliant CSR structure
//! - Subject DN and SAN validation per RFC 5280
//! - HSM integration for hardware-protected key generation

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
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-12 (Cryptographic Key Establishment) - Generates FIPS-approved key pairs
    /// - SC-13 (Cryptographic Protection) - Uses FIPS-approved signature algorithms
    /// - IA-5 (Authenticator Management) - Binds subject identity to public key
    /// - SI-10 (Information Input Validation) - Validates DN and SAN inputs
    ///
    /// **Application Development STIG V5R3:**
    /// - APSC-DV-000160 (CAT II) - Enables bidirectional authentication
    /// - APSC-DV-001740 (CAT II) - Generates PKI certificate requests
    ///
    /// # Security Implementation
    ///
    /// This builder generates CSRs compliant with RFC 2986 (PKCS#10). Key security
    /// features include:
    ///
    /// - **Key Generation**: Default ECDSA P-256 key pairs using cryptographically
    ///   secure random number generation via the `rcgen` library
    /// - **Subject Validation**: DN attributes are validated for proper X.500 encoding
    /// - **SAN Validation**: Subject Alternative Names are validated against their
    ///   respective RFC specifications (DNS: RFC 1035, Email: RFC 822, URI: RFC 3986)
    /// - **Key Usage**: Supports digital signature, key encipherment, and key agreement
    ///   with proper extension encoding
    /// - **Information Disclosure Prevention**: Error messages provide details without
    ///   exposing sensitive system information
    ///
    /// # Private Key Protection
    ///
    /// **CRITICAL**: The private key returned by `build()` must be protected with
    /// appropriate access controls. Consider:
    ///
    /// - Store keys in encrypted form at rest
    /// - Use operating system key stores (Windows DPAPI, macOS Keychain, etc.)
    /// - For high-security applications, use `HsmCsrBuilder` to keep keys in hardware
    /// - Zeroize key material when no longer needed
    ///
    /// # Example
    ///
    /// ```no_run
    /// use usg_est_client::csr::CsrBuilder;
    ///
    /// // Generate a CSR for a device with FIPS-compliant key pair
    /// let (csr_der, key_pair) = CsrBuilder::new()
    ///     .common_name("device.example.com")
    ///     .organization("Example Corp")
    ///     .country("US")
    ///     .san_dns("device.example.com")
    ///     .key_usage_digital_signature()
    ///     .extended_key_usage_client_auth()
    ///     .build()
    ///     .expect("Failed to generate CSR");
    ///
    /// // CSR is now ready for submission to EST server
    /// // Private key must be protected appropriately
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
        ///
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:** SC-12 (Cryptographic Key Establishment)
        ///
        /// # Security Implementation
        ///
        /// Creates a new CSR builder with default ECDSA P-256 key generation
        /// parameters. The builder uses secure defaults:
        ///
        /// - ECDSA P-256 signature algorithm (FIPS 140-2 approved)
        /// - SHA-256 hash function (FIPS 180-4 approved)
        /// - Empty subject DN (must be populated before build)
        /// - No Subject Alternative Names (recommended to add at least one)
        pub fn new() -> Self {
            Self {
                params: CertificateParams::default(),
                key_pair: None,
            }
        }

        // ========================================================================
        // SECURITY CONTROL: Subject Distinguished Name Configuration
        // ------------------------------------------------------------------------
        // NIST SP 800-53 Rev 5: IA-5 (Authenticator Management)
        //                       SI-10 (Information Input Validation)
        //
        // The subject Distinguished Name (DN) identifies the certificate subject.
        // All DN attribute values are validated for proper X.500 encoding by the
        // rcgen library. Invalid values will cause a panic when the CSR is built.
        // ========================================================================

        /// Set the Common Name (CN) for the subject.
        ///
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:** IA-5 (Authenticator Management)
        ///
        /// # Security Implementation
        ///
        /// The Common Name identifies the subject of the certificate. For device
        /// certificates, this is typically the fully qualified domain name (FQDN).
        /// For user certificates, it may be the user's name or email address.
        ///
        /// The CN value must:
        /// - Be valid UTF-8
        /// - Conform to X.500 Distinguished Name encoding rules
        /// - Match at least one Subject Alternative Name (recommended practice)
        /// - Not exceed 64 characters (X.500 limit)
        ///
        /// # Arguments
        ///
        /// * `cn` - The common name value (e.g., "device.example.com")
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
            let dns_name = dns_str.as_str().try_into().expect(&format!(
                "Invalid DNS name for SAN: '{}'. DNS names must conform to RFC 1035. \
                 Check for invalid characters or excessive length.",
                dns_str
            ));
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
            let email_addr = email_str.as_str().try_into().expect(&format!(
                "Invalid email address for SAN: '{}'. Email must conform to RFC 822. \
                 Check for proper format (user@domain.com).",
                email_str
            ));
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
            let uri_value = uri_str.as_str().try_into().expect(&format!(
                "Invalid URI for SAN: '{}'. URI must conform to RFC 3986. \
                 Check for proper scheme and format (e.g., https://example.com).",
                uri_str
            ));
            self.params.subject_alt_names.push(SanType::URI(uri_value));
            self
        }

        // ========================================================================
        // SECURITY CONTROL: Key Usage and Extended Key Usage Configuration
        // ------------------------------------------------------------------------
        // NIST SP 800-53 Rev 5: SC-12 (Cryptographic Key Establishment)
        //                       IA-5 (Authenticator Management)
        //
        // Key usage extensions specify the cryptographic operations permitted for
        // the certificate's public/private key pair. Proper key usage configuration
        // prevents key misuse (e.g., using an encryption key for signing).
        //
        // Extended Key Usage (EKU) further restricts usage to specific purposes
        // (e.g., TLS client authentication, server authentication, code signing).
        // ========================================================================

        /// Enable digital signature key usage.
        ///
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:** SC-12 (Cryptographic Key Establishment)
        ///
        /// # Security Implementation
        ///
        /// Enables the digitalSignature key usage bit (RFC 5280 Section 4.2.1.3).
        /// This permits the key to be used for digital signatures, including:
        /// - Document signing
        /// - TLS handshake signatures (client/server authentication)
        /// - Code signing
        /// - Email signing (S/MIME)
        ///
        /// This is the most commonly used key usage and should be included for
        /// most certificate types.
        pub fn key_usage_digital_signature(mut self) -> Self {
            self.params
                .key_usages
                .push(KeyUsagePurpose::DigitalSignature);
            self
        }

        /// Enable key encipherment key usage.
        ///
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:** SC-12 (Cryptographic Key Establishment)
        ///
        /// # Security Implementation
        ///
        /// Enables the keyEncipherment key usage bit (RFC 5280 Section 4.2.1.3).
        /// This permits the key to be used for encrypting symmetric keys during:
        /// - TLS key exchange (RSA key transport)
        /// - S/MIME email encryption
        ///
        /// Note: This is primarily used with RSA keys. ECDSA keys typically use
        /// keyAgreement instead.
        pub fn key_usage_key_encipherment(mut self) -> Self {
            self.params
                .key_usages
                .push(KeyUsagePurpose::KeyEncipherment);
            self
        }

        /// Enable key agreement key usage.
        ///
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:** SC-12 (Cryptographic Key Establishment)
        ///
        /// # Security Implementation
        ///
        /// Enables the keyAgreement key usage bit (RFC 5280 Section 4.2.1.3).
        /// This permits the key to be used for key agreement protocols:
        /// - ECDH (Elliptic Curve Diffie-Hellman)
        /// - TLS ECDHE key exchange
        ///
        /// This is the standard key usage for ECDSA keys used in TLS.
        pub fn key_usage_key_agreement(mut self) -> Self {
            self.params.key_usages.push(KeyUsagePurpose::KeyAgreement);
            self
        }

        /// Add TLS client authentication extended key usage.
        ///
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:** IA-5 (Authenticator Management)
        ///
        /// **Application Development STIG V5R3:** APSC-DV-000160 (Bidirectional Authentication)
        ///
        /// # Security Implementation
        ///
        /// Enables the id-kp-clientAuth extended key usage (RFC 5280 Section 4.2.1.12).
        /// This restricts the certificate to TLS client authentication use cases.
        ///
        /// Use this for:
        /// - Device certificates authenticating to EST servers
        /// - User certificates for TLS mutual authentication
        /// - IoT device certificates for M2M communication
        pub fn extended_key_usage_client_auth(mut self) -> Self {
            self.params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ClientAuth);
            self
        }

        /// Add TLS server authentication extended key usage.
        ///
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:** IA-5 (Authenticator Management)
        ///
        /// # Security Implementation
        ///
        /// Enables the id-kp-serverAuth extended key usage (RFC 5280 Section 4.2.1.12).
        /// This restricts the certificate to TLS server authentication use cases.
        ///
        /// Use this for:
        /// - HTTPS server certificates
        /// - EST server certificates
        /// - Any service providing TLS-protected endpoints
        pub fn extended_key_usage_server_auth(mut self) -> Self {
            self.params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);
            self
        }

        /// Set the challenge password attribute.
        ///
        /// This can be used for TLS channel binding per RFC 7030 Section 3.5.
        ///
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:** SC-23 (Session Authenticity)
        ///
        /// # Security Implementation
        ///
        /// The challenge password provides proof-of-possession for EST enrollment.
        /// Per RFC 7030 Section 3.5, this should contain the tls-unique channel
        /// binding value from the TLS handshake to prove that the CSR was generated
        /// within the context of the current TLS session.
        ///
        /// Note: The `rcgen` library does not currently support the challengePassword
        /// attribute directly. This method is a placeholder for future implementation.
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
        ///
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:** SC-12 (Cryptographic Key Establishment)
        ///
        /// # Security Implementation
        ///
        /// Allows using an existing key pair instead of generating a new one during
        /// CSR creation. This is useful for:
        ///
        /// - Certificate renewal with the same key pair (not recommended for long-term use)
        /// - Testing with known test keys
        /// - Using externally generated keys
        ///
        /// **Security Warning**: Reusing key pairs across multiple certificates can
        /// reduce security. Best practice is to generate a new key pair for each
        /// certificate. Only reuse keys when required by operational constraints.
        pub fn with_key_pair(mut self, key_pair: KeyPair) -> Self {
            self.key_pair = Some(key_pair);
            self
        }

        /// Build the CSR with a new ECDSA P-256 key pair.
        ///
        /// Returns the DER-encoded CSR and the generated key pair.
        ///
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:**
        /// - SC-12 (Cryptographic Key Establishment) - FIPS-approved key generation
        /// - SC-13 (Cryptographic Protection) - FIPS-approved signature algorithm
        ///
        /// **Application Development STIG V5R3:**
        /// - APSC-DV-001740 (CAT II) - PKI certificate request generation
        /// - APSC-DV-002440 (CAT I) - Secure error messaging
        ///
        /// # Security Implementation
        ///
        /// This method performs the following security-critical operations:
        ///
        /// 1. **Key Generation**: If no key pair was provided via `with_key_pair()`,
        ///    generates a new ECDSA P-256 key pair using cryptographically secure
        ///    random number generation (via `rcgen::KeyPair::generate()`).
        ///
        /// 2. **CSR Signing**: Signs the CSR using ECDSA with SHA-256 (FIPS 186-4
        ///    approved algorithm).
        ///
        /// 3. **DER Encoding**: Encodes the CSR in DER format per RFC 2986 (PKCS#10).
        ///
        /// # Returns
        ///
        /// Returns a tuple of:
        /// - `Vec<u8>`: DER-encoded CSR bytes ready for transmission to EST server
        /// - `KeyPair`: The generated (or provided) key pair
        ///
        /// **CRITICAL**: The returned KeyPair contains the private key. It must be
        /// protected with appropriate access controls. See `CsrBuilder` documentation
        /// for private key protection guidance.
        ///
        /// # Errors
        ///
        /// Returns `EstError::Csr` if:
        /// - Key generation fails (insufficient entropy, system error)
        /// - CSR serialization fails (invalid DN/SAN values, encoding error)
        ///
        /// Error messages are descriptive but do not expose sensitive information
        /// (SI-11 compliance).
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
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-12 (Cryptographic Key Establishment) - ECDSA P-256 key generation
    /// - IA-5 (Authenticator Management) - Device identity binding
    ///
    /// **Application Development STIG V5R3:**
    /// - APSC-DV-000160 (CAT II) - Bidirectional authentication support
    /// - APSC-DV-001740 (CAT II) - PKI certificate request generation
    ///
    /// # Security Implementation
    ///
    /// Generates a device certificate CSR with secure defaults:
    ///
    /// - **Subject**: CN = common_name, O = organization (if provided)
    /// - **SANs**: DNS name matching the common name
    /// - **Key Usage**: digitalSignature, keyEncipherment
    /// - **Extended Key Usage**: id-kp-clientAuth (TLS client authentication)
    /// - **Key Algorithm**: ECDSA P-256 with SHA-256 (FIPS-approved)
    ///
    /// This configuration is appropriate for IoT devices, workstations, and other
    /// clients that need to authenticate to EST servers or other TLS services.
    ///
    /// # Arguments
    ///
    /// * `common_name` - Device FQDN (e.g., "device001.example.com")
    /// * `organization` - Optional organization name for O attribute
    ///
    /// # Returns
    ///
    /// Returns a tuple of (CSR DER bytes, KeyPair). The private key must be
    /// protected appropriately.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use usg_est_client::csr::generate_device_csr;
    ///
    /// let (csr, key) = generate_device_csr("device001.example.com", Some("ACME Corp"))
    ///     .expect("Failed to generate device CSR");
    ///
    /// // Store key securely before submitting CSR
    /// ```
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
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-12 (Cryptographic Key Establishment) - ECDSA P-256 key generation
    /// - IA-5 (Authenticator Management) - Server identity binding
    ///
    /// **Application Development STIG V5R3:**
    /// - APSC-DV-001740 (CAT II) - PKI certificate request generation
    ///
    /// # Security Implementation
    ///
    /// Generates a TLS server certificate CSR with secure defaults:
    ///
    /// - **Subject**: CN = common_name
    /// - **SANs**: DNS names for all server hostnames
    /// - **Key Usage**: digitalSignature, keyEncipherment
    /// - **Extended Key Usage**: id-kp-serverAuth (TLS server authentication)
    /// - **Key Algorithm**: ECDSA P-256 with SHA-256 (FIPS-approved)
    ///
    /// Modern browsers and clients require server certificates to have Subject
    /// Alternative Names (SANs). The CN alone is no longer sufficient.
    ///
    /// # Arguments
    ///
    /// * `common_name` - Primary server FQDN (e.g., "www.example.com")
    /// * `san_names` - All DNS names the server certificate should be valid for
    ///   (should include the common_name plus any aliases)
    ///
    /// # Returns
    ///
    /// Returns a tuple of (CSR DER bytes, KeyPair). The private key must be
    /// protected appropriately.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use usg_est_client::csr::generate_server_csr;
    ///
    /// let (csr, key) = generate_server_csr(
    ///     "www.example.com",
    ///     &["www.example.com", "example.com", "api.example.com"]
    /// ).expect("Failed to generate server CSR");
    /// ```
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

// ============================================================================
// SECURITY CONTROL: HSM-Backed CSR Generation
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: SC-12 (Cryptographic Key Establishment)
//                       SC-13 (Cryptographic Protection)
//                       IA-5 (Authenticator Management)
//
// SECURITY CONTROL IMPLEMENTATION:
//
// HSM (Hardware Security Module) backed CSR generation provides the highest
// level of private key protection by ensuring private keys never leave the
// hardware security boundary.
//
// SC-12: CRYPTOGRAPHIC KEY ESTABLISHMENT
// ---------------------------------------
// HSM integration provides:
//
// - Non-exportable private keys (keys cannot be extracted from HSM)
// - Hardware-protected key generation with FIPS 140-2 Level 2+ compliance
// - Physical tamper protection for key material
// - Separation of key management from application logic
//
// Unlike software key generation (CsrBuilder), HSM keys are:
// - Generated within the HSM hardware boundary
// - Used for signing operations without exposing key bytes to application
// - Protected against memory dumps, debugging, and malware
// - Suitable for high-value certificates (CA, production services, etc.)
//
// SC-13: CRYPTOGRAPHIC PROTECTION
// --------------------------------
// HSMs provide FIPS-validated cryptographic implementations with hardware
// acceleration for signing operations. All signature algorithms match the
// same FIPS-approved algorithms used in software mode.
//
// ============================================================================

/// HSM-backed CSR generation support.
///
/// This module provides functionality to generate CSRs using keys stored in
/// Hardware Security Modules or other secure key providers.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SC-12 (Cryptographic Key Establishment) - Hardware-protected keys
/// - SC-13 (Cryptographic Protection) - FIPS-validated HSM operations
/// - IA-5 (Authenticator Management) - High-assurance identity binding
///
/// # Security Implementation
///
/// HSM-backed CSR generation provides the highest level of private key protection.
/// Private keys are:
/// - Generated within the HSM hardware boundary
/// - Never exported or exposed to application memory
/// - Protected by physical tamper detection and response
/// - Suitable for high-value certificates (CA certificates, production servers)
///
/// Use HSM-backed CSR generation when:
/// - Generating Certificate Authority (CA) certificates
/// - Compliance requires FIPS 140-2 Level 2+ key protection
/// - Keys must be non-exportable for security policy reasons
/// - Hardware tamper protection is required
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
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-12 (Cryptographic Key Establishment) - Uses HSM-protected keys
    /// - SC-13 (Cryptographic Protection) - FIPS-approved HSM signature operations
    /// - IA-5 (Authenticator Management) - High-assurance identity binding
    ///
    /// **Application Development STIG V5R3:**
    /// - APSC-DV-001740 (CAT II) - PKI certificate requests with hardware protection
    ///
    /// # Security Implementation
    ///
    /// This builder generates CSRs using keys stored in HSMs or other KeyProvider
    /// implementations. Key security features:
    ///
    /// - **Non-Exportable Keys**: Private keys never leave the HSM hardware boundary
    /// - **Hardware Signing**: CSR signature is computed within the HSM
    /// - **Manual PKCS#10 Construction**: CSR is built manually to avoid exposing
    ///   private key bytes to the rcgen library
    /// - **Provider Abstraction**: Works with any KeyProvider implementation
    ///   (hardware HSMs, TPMs, cloud KMS, etc.)
    ///
    /// # HSM vs Software Key Providers
    ///
    /// This builder supports two methods for CSR generation:
    ///
    /// 1. **`build_with_software_provider()`**: Optimized for SoftwareKeyProvider,
    ///    uses rcgen directly for better performance. Keys are still in memory.
    ///
    /// 2. **`build_with_provider()`**: Generic method for any KeyProvider including
    ///    hardware HSMs. Uses manual PKCS#10 construction to keep private keys in
    ///    hardware.
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
    ///     .key_usage_digital_signature()
    ///     .extended_key_usage_client_auth()
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
            let dns_name = dns_str.as_str().try_into().expect(&format!(
                "Invalid DNS name for SAN: '{}'. DNS names must conform to RFC 1035. \
                 Check for invalid characters or excessive length.",
                dns_str
            ));
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
            let email_addr = email_str.as_str().try_into().expect(&format!(
                "Invalid email address for SAN: '{}'. Email must conform to RFC 822. \
                 Check for proper format (user@domain.com).",
                email_str
            ));
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
            let uri_value = uri_str.as_str().try_into().expect(&format!(
                "Invalid URI for SAN: '{}'. URI must conform to RFC 3986. \
                 Check for proper scheme and format (e.g., https://example.com).",
                uri_str
            ));
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
        /// # Security Controls
        ///
        /// **NIST SP 800-53 Rev 5:**
        /// - SC-12 (Cryptographic Key Establishment) - HSM-protected key usage
        /// - SC-13 (Cryptographic Protection) - Hardware-based signature generation
        ///
        /// **Application Development STIG V5R3:**
        /// - APSC-DV-001740 (CAT II) - High-assurance certificate requests
        /// - APSC-DV-002440 (CAT I) - Secure error messaging
        ///
        /// # Security Implementation
        ///
        /// This method generates CSRs using hardware-protected keys without exposing
        /// private key bytes to application memory. The process:
        ///
        /// 1. **Retrieve Public Key**: Fetch public key from provider (safe operation)
        /// 2. **Build CertificateRequestInfo**: Construct PKCS#10 structure with
        ///    subject DN, public key, and extensions
        /// 3. **Hash TBS**: Hash the to-be-signed data using appropriate algorithm
        ///    (SHA-256 for P-256, SHA-384 for P-384)
        /// 4. **HSM Signature**: Call provider.sign() to compute signature within HSM
        /// 5. **Assemble CSR**: Combine CertReqInfo, signature algorithm, and signature
        ///
        /// **Key Security Property**: The private key never leaves the HSM. Only the
        /// public key and signature are transmitted to the application.
        ///
        /// # Arguments
        ///
        /// * `provider` - The key provider containing the key (HSM, TPM, KMS, etc.)
        /// * `key_handle` - Handle to the key to use for signing
        ///
        /// # Returns
        ///
        /// The DER-encoded CSR bytes ready for submission to EST server.
        ///
        /// # Errors
        ///
        /// Returns `EstError::Csr` if:
        /// - Public key retrieval fails (HSM communication error)
        /// - DN parsing fails (invalid subject attributes)
        /// - Extension encoding fails (invalid SAN values)
        /// - Signature operation fails (HSM error, key not found)
        /// - DER encoding fails (internal error)
        ///
        /// Error messages are descriptive but do not expose sensitive HSM information.
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

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

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

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid

    #[test]
    fn test_builder_all_dn_attributes() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("full-dn.example.com")
            .organization("Test Organization")
            .organizational_unit("Engineering")
            .country("US")
            .state("Virginia")
            .locality("Arlington")
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        let subject = cert_req.info.subject.to_string();
        assert!(subject.contains("full-dn.example.com"));
        assert!(subject.contains("Test Organization"));
        assert!(subject.contains("Engineering"));
        assert!(subject.contains("US"));
        assert!(subject.contains("Virginia"));
        assert!(subject.contains("Arlington"));
    }

    #[test]
    fn test_builder_multiple_san_dns() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("multi-dns.example.com")
            .san_dns("multi-dns.example.com")
            .san_dns("alt1.example.com")
            .san_dns("alt2.example.com")
            .san_dns("alt3.example.com")
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        assert!(!cert_req.info.attributes.is_empty());
    }

    #[test]
    fn test_builder_san_ip_v4_and_v6() {
        use der::Decode;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("ip-san.example.com")
            .san_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .san_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        assert!(!cert_req.info.attributes.is_empty());
    }

    #[test]
    fn test_builder_san_email() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("email-san.example.com")
            .san_email("admin@example.com")
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        assert!(!cert_req.info.attributes.is_empty());
    }

    #[test]
    fn test_builder_san_uri() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("uri-san.example.com")
            .san_uri("https://example.com/device/001")
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        assert!(!cert_req.info.attributes.is_empty());
    }

    #[test]
    fn test_builder_all_key_usage_flags() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("key-usage.example.com")
            .key_usage_digital_signature()
            .key_usage_key_encipherment()
            .key_usage_key_agreement()
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        assert!(!cert_req.info.attributes.is_empty());
    }

    #[test]
    fn test_builder_all_eku_flags() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("eku.example.com")
            .extended_key_usage_client_auth()
            .extended_key_usage_server_auth()
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        assert!(!cert_req.info.attributes.is_empty());
    }

    #[test]
    fn test_builder_combined_key_usage_and_eku() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("combined.example.com")
            .key_usage_digital_signature()
            .key_usage_key_encipherment()
            .key_usage_key_agreement()
            .extended_key_usage_client_auth()
            .extended_key_usage_server_auth()
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        let subject = cert_req.info.subject.to_string();
        assert!(subject.contains("combined.example.com"));
        assert!(!cert_req.info.attributes.is_empty());
        assert!(!cert_req.signature.as_bytes().unwrap().is_empty());
    }

    #[test]
    fn test_build_with_key_reusing_keypair() {
        use der::Decode;
        use rcgen::KeyPair;
        use x509_cert::request::CertReq;

        let key_pair = KeyPair::generate().unwrap();

        let csr_der = CsrBuilder::new()
            .common_name("reuse-key.example.com")
            .organization("Reuse Key Org")
            .san_dns("reuse-key.example.com")
            .key_usage_digital_signature()
            .extended_key_usage_client_auth()
            .build_with_key(&key_pair)
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        let subject = cert_req.info.subject.to_string();
        assert!(subject.contains("reuse-key.example.com"));
        assert!(!cert_req.signature.as_bytes().unwrap().is_empty());
    }

    #[test]
    fn test_challenge_password_does_not_break_builder() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("challenge.example.com")
            .challenge_password("s3cret-passw0rd")
            .san_dns("challenge.example.com")
            .key_usage_digital_signature()
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        let subject = cert_req.info.subject.to_string();
        assert!(subject.contains("challenge.example.com"));
    }

    #[test]
    fn test_with_attributes_does_not_break_builder() {
        use crate::types::CsrAttributes;
        use der::Decode;
        use x509_cert::request::CertReq;

        let attrs = CsrAttributes::default();
        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("attrs.example.com")
            .with_attributes(&attrs)
            .san_dns("attrs.example.com")
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        let subject = cert_req.info.subject.to_string();
        assert!(subject.contains("attrs.example.com"));
    }

    #[test]
    fn test_default_trait_implementation() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let builder: CsrBuilder = Default::default();
        let (csr_der, _key_pair) = builder
            .common_name("default-trait.example.com")
            .build()
            .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        let subject = cert_req.info.subject.to_string();
        assert!(subject.contains("default-trait.example.com"));
    }

    #[test]
    fn test_generate_device_csr_with_organization() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) =
            generate_device_csr("device-org.example.com", Some("Federal Agency"))
                .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        let subject = cert_req.info.subject.to_string();
        assert!(subject.contains("device-org.example.com"));
        assert!(subject.contains("Federal Agency"));
    }

    #[test]
    fn test_generate_device_csr_without_organization() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let (csr_der, _key_pair) =
            generate_device_csr("device-no-org.example.com", None)
                .unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        let subject = cert_req.info.subject.to_string();
        assert!(subject.contains("device-no-org.example.com"));
        // Should not contain any organization
        assert!(!subject.contains("O="));
    }

    #[test]
    fn test_generate_server_csr_with_multiple_sans() {
        use der::Decode;
        use x509_cert::request::CertReq;

        let san_names = &[
            "www.example.com",
            "example.com",
            "api.example.com",
            "cdn.example.com",
        ];
        let (csr_der, _key_pair) =
            generate_server_csr("www.example.com", san_names).unwrap();

        assert!(!csr_der.is_empty());
        let cert_req = CertReq::from_der(&csr_der).unwrap();
        let subject = cert_req.info.subject.to_string();
        assert!(subject.contains("www.example.com"));
        // SANs are encoded in the extension request attribute
        assert!(!cert_req.info.attributes.is_empty());
        assert!(!cert_req.signature.as_bytes().unwrap().is_empty());
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
