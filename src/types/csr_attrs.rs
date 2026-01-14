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

//! CSR Attributes parsing.
//!
//! This module handles parsing of the CSR Attributes response from the
//! /csrattrs endpoint as defined in RFC 7030 Section 4.5.

use base64::prelude::*;
use const_oid::ObjectIdentifier;
use der::Decode;

use crate::error::{EstError, Result};

/// CSR Attributes returned from the /csrattrs endpoint.
///
/// These attributes indicate what the EST server expects to see in
/// Certificate Signing Requests.
#[derive(Debug, Clone, Default)]
pub struct CsrAttributes {
    /// List of attribute type OIDs.
    pub attributes: Vec<CsrAttribute>,
}

/// A single CSR attribute from the /csrattrs response.
#[derive(Debug, Clone)]
pub struct CsrAttribute {
    /// The attribute OID.
    pub oid: ObjectIdentifier,

    /// Optional attribute values (DER-encoded).
    pub values: Vec<Vec<u8>>,
}

impl CsrAttributes {
    /// Create a new empty CSR attributes collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse CSR attributes from a base64-encoded response body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        // Handle empty response
        if body.is_empty() || body.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(Self::new());
        }

        // Decode base64
        let cleaned: Vec<u8> = body
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();

        let der_bytes = BASE64_STANDARD.decode(&cleaned).map_err(EstError::Base64)?;

        // Parse ASN.1 SEQUENCE OF AttrOrOID
        Self::parse_der(&der_bytes)
    }

    /// Parse CSR attributes from DER-encoded data.
    fn parse_der(data: &[u8]) -> Result<Self> {
        // CSR Attributes is a SEQUENCE OF AttrOrOID
        // AttrOrOID ::= CHOICE { oid OBJECT IDENTIFIER, attribute Attribute }
        // Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF ANY }

        // Simple parsing: just extract OIDs from the sequence
        // Full parsing would require handling nested structures

        let mut attributes = Vec::new();

        // Check for SEQUENCE tag
        if data.is_empty() || data[0] != 0x30 {
            return Err(EstError::cms_parsing(
                "Invalid CSR attributes: expected SEQUENCE",
            ));
        }

        // Parse the outer sequence length
        let (content, _) = parse_der_length(&data[1..])?;

        // Parse each element
        let mut offset = 0;
        while offset < content.len() {
            let tag = content[offset];
            let (element_content, element_len) = parse_der_length(&content[offset + 1..])?;

            if tag == 0x06 {
                // OID
                if let Ok(oid) = ObjectIdentifier::from_der(
                    &content[offset..offset + 1 + element_len + element_content.len()],
                ) {
                    attributes.push(CsrAttribute::new(oid));
                }
            } else if tag == 0x30 {
                // SEQUENCE (Attribute)
                let attr_data = &content[offset..offset + 1 + element_len + element_content.len()];
                if let Ok(attr) = Self::parse_attribute(attr_data) {
                    attributes.push(attr);
                }
            }

            offset += 1 + element_len + element_content.len();
        }

        Ok(Self { attributes })
    }

    /// Parse a single Attribute from DER data.
    fn parse_attribute(data: &[u8]) -> Result<CsrAttribute> {
        // Attribute ::= SEQUENCE { type OID, values SET OF ANY }
        if data.is_empty() || data[0] != 0x30 {
            return Err(EstError::cms_parsing(
                "Invalid attribute: expected SEQUENCE",
            ));
        }

        let (content, _) = parse_der_length(&data[1..])?;

        // First element should be the OID
        if content.is_empty() || content[0] != 0x06 {
            return Err(EstError::cms_parsing("Invalid attribute: expected OID"));
        }

        let (oid_content, oid_len) = parse_der_length(&content[1..])?;
        let oid_data = &content[0..1 + oid_len + oid_content.len()];

        let oid = ObjectIdentifier::from_der(oid_data)
            .map_err(|e| EstError::cms_parsing(format!("Failed to parse OID: {}", e)))?;

        Ok(CsrAttribute::new(oid))
    }

    /// Returns true if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// Returns the number of attributes.
    pub fn len(&self) -> usize {
        self.attributes.len()
    }

    /// Check if a specific OID is requested.
    pub fn contains_oid(&self, oid: &ObjectIdentifier) -> bool {
        self.attributes.iter().any(|attr| &attr.oid == oid)
    }

    /// Get all attribute OIDs.
    pub fn oids(&self) -> Vec<ObjectIdentifier> {
        self.attributes.iter().map(|a| a.oid).collect()
    }
}

/// Parse DER length encoding and return (content_slice, length_of_length).
fn parse_der_length(data: &[u8]) -> Result<(&[u8], usize)> {
    if data.is_empty() {
        return Err(EstError::cms_parsing("Unexpected end of DER data"));
    }

    let first = data[0];
    if first < 0x80 {
        // Short form
        let len = first as usize;
        if data.len() < 1 + len {
            return Err(EstError::cms_parsing("DER data too short"));
        }
        Ok((&data[1..1 + len], 1))
    } else if first == 0x80 {
        // Indefinite length (not supported)
        Err(EstError::cms_parsing("Indefinite length not supported"))
    } else {
        // Long form
        let num_bytes = (first & 0x7f) as usize;
        if data.len() < 1 + num_bytes {
            return Err(EstError::cms_parsing("DER data too short for long length"));
        }

        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }

        let start = 1 + num_bytes;
        if data.len() < start + len {
            return Err(EstError::cms_parsing("DER data too short for content"));
        }

        Ok((&data[start..start + len], 1 + num_bytes))
    }
}

impl CsrAttribute {
    /// Create a new CSR attribute with just an OID.
    pub fn new(oid: ObjectIdentifier) -> Self {
        Self {
            oid,
            values: Vec::new(),
        }
    }

    /// Create a new CSR attribute with OID and values.
    pub fn with_values(oid: ObjectIdentifier, values: Vec<Vec<u8>>) -> Self {
        Self { oid, values }
    }

    /// Check if this attribute has any values.
    pub fn has_values(&self) -> bool {
        !self.values.is_empty()
    }
}

/// Well-known OIDs used in CSR attributes.
pub mod oids {
    use const_oid::ObjectIdentifier;

    /// Challenge Password OID (1.2.840.113549.1.9.7)
    pub const CHALLENGE_PASSWORD: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.7");

    /// Extension Request OID (1.2.840.113549.1.9.14)
    pub const EXTENSION_REQUEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");

    /// Subject Alternative Name OID (2.5.29.17)
    pub const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

    /// Key Usage OID (2.5.29.15)
    pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

    /// Extended Key Usage OID (2.5.29.37)
    pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

    /// Basic Constraints OID (2.5.29.19)
    pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_empty_response() {
        let attrs = CsrAttributes::parse(b"").unwrap();
        assert!(attrs.is_empty());

        let attrs = CsrAttributes::parse(b"   \n  ").unwrap();
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_csr_attribute_creation() {
        let attr = CsrAttribute::new(oids::CHALLENGE_PASSWORD);
        assert!(!attr.has_values());
        assert_eq!(attr.oid, oids::CHALLENGE_PASSWORD);
    }
}
