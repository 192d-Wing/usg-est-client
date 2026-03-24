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

//! EST message types and parsing utilities.
//!
//! This module provides types for EST request and response messages,
//! including PKCS#7/CMS structures, CSR attributes, and CMC messages.

mod cmc;
pub mod cmc_full;
pub mod csr_attrs;
mod pkcs7;

pub use cmc::{CmcRequest, CmcResponse, CmcStatus};
pub use cmc_full::{
    BatchRequest, BatchResponse, BodyPartId, CmcFailInfo, CmcStatusInfo, CmcStatusValue,
    PendingInfo, PkiData, PkiDataBuilder, PkiResponse, TaggedAttribute, TaggedCertificationRequest,
    TaggedRequest,
};
pub use csr_attrs::CsrAttributes;
pub use pkcs7::{CaCertificates, parse_certs_only};

use x509_cert::Certificate;

/// Response from a simple enrollment or re-enrollment request.
#[derive(Debug, Clone)]
pub enum EnrollmentResponse {
    /// Certificate was issued immediately.
    Issued {
        /// The issued certificate.
        certificate: Box<Certificate>,
    },

    /// Enrollment is pending manual approval.
    ///
    /// The client should wait and retry after the specified duration.
    Pending {
        /// Number of seconds to wait before retrying.
        retry_after: u64,
    },
}

impl EnrollmentResponse {
    /// Create a new issued response.
    pub fn issued(certificate: Certificate) -> Self {
        Self::Issued {
            certificate: Box::new(certificate),
        }
    }

    /// Create a new pending response.
    pub fn pending(retry_after: u64) -> Self {
        Self::Pending { retry_after }
    }

    /// Returns the certificate if the enrollment was successful.
    pub fn certificate(&self) -> Option<&Certificate> {
        match self {
            Self::Issued { certificate } => Some(certificate),
            Self::Pending { .. } => None,
        }
    }

    /// Returns true if the enrollment is pending.
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    /// Returns the retry-after value if pending.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Pending { retry_after } => Some(*retry_after),
            Self::Issued { .. } => None,
        }
    }
}

/// Response from a server key generation request.
#[derive(Debug, Clone)]
pub struct ServerKeygenResponse {
    /// The issued certificate.
    pub certificate: Certificate,

    /// The server-generated private key (DER-encoded PKCS#8).
    ///
    /// This may be encrypted if the server chose to encrypt it.
    pub private_key: Vec<u8>,

    /// Whether the private key is encrypted.
    pub key_encrypted: bool,
}

impl ServerKeygenResponse {
    /// Create a new server keygen response.
    pub fn new(certificate: Certificate, private_key: Vec<u8>, key_encrypted: bool) -> Self {
        Self {
            certificate,
            private_key,
            key_encrypted,
        }
    }
}

/// Content types used in EST protocol.
pub mod content_types {
    /// PKCS#10 CSR content type.
    pub const PKCS10: &str = "application/pkcs10";

    /// PKCS#7/CMS content type.
    pub const PKCS7_MIME: &str = "application/pkcs7-mime";

    /// PKCS#7 certs-only content type with smime-type parameter.
    pub const PKCS7_CERTS_ONLY: &str = "application/pkcs7-mime; smime-type=certs-only";

    /// PKCS#8 private key content type.
    pub const PKCS8: &str = "application/pkcs8";

    /// CSR attributes content type.
    pub const CSR_ATTRS: &str = "application/csrattrs";

    /// CMC request content type.
    pub const CMC_REQUEST: &str = "application/pkcs7-mime; smime-type=CMC-request";

    /// CMC response content type.
    pub const CMC_RESPONSE: &str = "application/pkcs7-mime; smime-type=CMC-response";

    /// Multipart mixed content type (for server keygen).
    pub const MULTIPART_MIXED: &str = "multipart/mixed";
}

/// EST operation paths.
pub mod operations {
    /// CA certificates endpoint.
    pub const CACERTS: &str = "cacerts";

    /// Simple enrollment endpoint.
    pub const SIMPLE_ENROLL: &str = "simpleenroll";

    /// Simple re-enrollment endpoint.
    pub const SIMPLE_REENROLL: &str = "simplereenroll";

    /// CSR attributes endpoint.
    pub const CSR_ATTRS: &str = "csrattrs";

    /// Server-side key generation endpoint.
    pub const SERVER_KEYGEN: &str = "serverkeygen";

    /// Full CMC endpoint.
    pub const FULL_CMC: &str = "fullcmc";
}

#[cfg(test)]
mod tests {
    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    use super::*;
    use der::Decode;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateDer;

    /// Load the test CA certificate from the fixtures directory.
    fn test_certificate() -> x509_cert::Certificate {
        let pem = include_bytes!("../../tests/fixtures/certs/ca.pem");
        let cert_der = CertificateDer::pem_slice_iter(pem).next().unwrap().unwrap();
        x509_cert::Certificate::from_der(cert_der.as_ref()).unwrap()
    }

    // ---- EnrollmentResponse tests ----

    #[test]
    fn enrollment_response_issued_creates_issued_variant() {
        let cert = test_certificate();
        let resp = EnrollmentResponse::issued(cert);
        assert!(matches!(resp, EnrollmentResponse::Issued { .. }));
    }

    #[test]
    fn enrollment_response_pending_creates_pending_variant() {
        let resp = EnrollmentResponse::pending(60);
        assert!(matches!(resp, EnrollmentResponse::Pending { retry_after: 60 }));
    }

    #[test]
    fn certificate_returns_some_for_issued() {
        let cert = test_certificate();
        let resp = EnrollmentResponse::issued(cert);
        assert!(resp.certificate().is_some());
    }

    #[test]
    fn certificate_returns_none_for_pending() {
        let resp = EnrollmentResponse::pending(30);
        assert!(resp.certificate().is_none());
    }

    #[test]
    fn is_pending_returns_true_for_pending() {
        let resp = EnrollmentResponse::pending(120);
        assert!(resp.is_pending());
    }

    #[test]
    fn is_pending_returns_false_for_issued() {
        let cert = test_certificate();
        let resp = EnrollmentResponse::issued(cert);
        assert!(!resp.is_pending());
    }

    #[test]
    fn retry_after_returns_some_for_pending() {
        let resp = EnrollmentResponse::pending(45);
        assert_eq!(resp.retry_after(), Some(45));
    }

    #[test]
    fn retry_after_returns_none_for_issued() {
        let cert = test_certificate();
        let resp = EnrollmentResponse::issued(cert);
        assert_eq!(resp.retry_after(), None);
    }

    // ---- ServerKeygenResponse tests ----

    #[test]
    fn server_keygen_response_new_populates_all_fields() {
        let cert = test_certificate();
        let key_data = vec![1, 2, 3, 4];
        let resp = ServerKeygenResponse::new(cert.clone(), key_data.clone(), false);

        assert_eq!(resp.private_key, key_data);
        assert!(!resp.key_encrypted);
        // Verify the certificate was stored by checking it round-trips
        assert_eq!(
            resp.certificate.tbs_certificate.serial_number,
            cert.tbs_certificate.serial_number
        );
    }

    #[test]
    fn server_keygen_response_with_encrypted_key() {
        let cert = test_certificate();
        let encrypted_key = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let resp = ServerKeygenResponse::new(cert, encrypted_key.clone(), true);

        assert!(resp.key_encrypted);
        assert_eq!(resp.private_key, encrypted_key);
    }

    #[test]
    fn server_keygen_response_with_unencrypted_key() {
        let cert = test_certificate();
        let raw_key = vec![0x30, 0x82, 0x01, 0x22];
        let resp = ServerKeygenResponse::new(cert, raw_key.clone(), false);

        assert!(!resp.key_encrypted);
        assert_eq!(resp.private_key, raw_key);
    }

    // ---- content_types constants tests ----

    #[test]
    fn content_type_pkcs10_is_correct() {
        assert_eq!(content_types::PKCS10, "application/pkcs10");
        assert!(!content_types::PKCS10.is_empty());
    }

    #[test]
    fn content_type_pkcs7_mime_is_correct() {
        assert_eq!(content_types::PKCS7_MIME, "application/pkcs7-mime");
    }

    #[test]
    fn content_type_pkcs7_certs_only_is_correct() {
        assert_eq!(
            content_types::PKCS7_CERTS_ONLY,
            "application/pkcs7-mime; smime-type=certs-only"
        );
    }

    #[test]
    fn content_type_pkcs8_is_correct() {
        assert_eq!(content_types::PKCS8, "application/pkcs8");
    }

    #[test]
    fn content_type_csr_attrs_is_correct() {
        assert_eq!(content_types::CSR_ATTRS, "application/csrattrs");
    }

    #[test]
    fn content_type_cmc_request_is_correct() {
        assert_eq!(
            content_types::CMC_REQUEST,
            "application/pkcs7-mime; smime-type=CMC-request"
        );
    }

    #[test]
    fn content_type_cmc_response_is_correct() {
        assert_eq!(
            content_types::CMC_RESPONSE,
            "application/pkcs7-mime; smime-type=CMC-response"
        );
    }

    #[test]
    fn content_type_multipart_mixed_is_correct() {
        assert_eq!(content_types::MULTIPART_MIXED, "multipart/mixed");
    }

    #[test]
    fn all_content_types_are_non_empty() {
        assert!(!content_types::PKCS10.is_empty());
        assert!(!content_types::PKCS7_MIME.is_empty());
        assert!(!content_types::PKCS7_CERTS_ONLY.is_empty());
        assert!(!content_types::PKCS8.is_empty());
        assert!(!content_types::CSR_ATTRS.is_empty());
        assert!(!content_types::CMC_REQUEST.is_empty());
        assert!(!content_types::CMC_RESPONSE.is_empty());
        assert!(!content_types::MULTIPART_MIXED.is_empty());
    }

    // ---- operations constants tests ----

    #[test]
    fn operation_cacerts_is_correct() {
        assert_eq!(operations::CACERTS, "cacerts");
    }

    #[test]
    fn operation_simple_enroll_is_correct() {
        assert_eq!(operations::SIMPLE_ENROLL, "simpleenroll");
    }

    #[test]
    fn operation_simple_reenroll_is_correct() {
        assert_eq!(operations::SIMPLE_REENROLL, "simplereenroll");
    }

    #[test]
    fn operation_csr_attrs_is_correct() {
        assert_eq!(operations::CSR_ATTRS, "csrattrs");
    }

    #[test]
    fn operation_server_keygen_is_correct() {
        assert_eq!(operations::SERVER_KEYGEN, "serverkeygen");
    }

    #[test]
    fn operation_full_cmc_is_correct() {
        assert_eq!(operations::FULL_CMC, "fullcmc");
    }

    #[test]
    fn all_operations_are_non_empty() {
        assert!(!operations::CACERTS.is_empty());
        assert!(!operations::SIMPLE_ENROLL.is_empty());
        assert!(!operations::SIMPLE_REENROLL.is_empty());
        assert!(!operations::CSR_ATTRS.is_empty());
        assert!(!operations::SERVER_KEYGEN.is_empty());
        assert!(!operations::FULL_CMC.is_empty());
    }
}
