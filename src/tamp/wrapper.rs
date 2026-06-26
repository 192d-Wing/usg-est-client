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

//! CMS `SignedData` wrapping/unwrapping for TAMP messages (RFC 5934 §3).
//!
//! Every TAMP message travels as a CMS `SignedData` whose `eContentType` is the
//! TAMP message OID and whose `eContent` is the DER of the message. This module
//! parses an inbound CMS blob into a [`TampMessage`] (content type + the raw
//! encapsulated message bytes + the `SignedData` needed for signature
//! verification) and assembles an outbound `SignedData` from parts.
//!
//! Signature *verification* lives in [`super::verify`]; signature *creation*
//! lives in [`super::response`]. This module is purely structural CMS handling.

use base64::prelude::*;
use cms::content_info::ContentInfo;
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfo};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString, SetOfVec};
use der::{Decode, Encode, Tag, Tagged};

use crate::error::{EstError, Result};

use super::oid::TampContentType;

/// CMS `id-signedData` content type (RFC 5652): `1.2.840.113549.1.7.2`.
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// CMS `id-data` content type (RFC 5652): `1.2.840.113549.1.7.1`.
///
/// Used as the `content-type` signed attribute value is the TAMP eContentType,
/// not id-data; this constant is retained only for completeness.
#[allow(dead_code)]
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// A parsed TAMP CMS message.
///
/// Holds everything later stages need: the recognized message kind, the raw
/// `eContentType` OID, the inner message DER (`eContent`), and the full
/// `SignedData` (for signature verification against the trust anchor store).
#[derive(Clone, Debug)]
pub struct TampMessage {
    /// The recognized TAMP message kind, or `None` if the OID is not a TAMP type.
    pub content_type: Option<TampContentType>,
    /// The raw `eContentType` OID as it appeared on the wire.
    pub econtent_type: ObjectIdentifier,
    /// The DER encoding of the inner TAMP message (the `eContent` octets).
    pub econtent: Vec<u8>,
    /// The CMS `SignedData`, retained for signature verification.
    pub signed_data: SignedData,
}

impl TampMessage {
    /// Parse a CMS `SignedData` carrying a TAMP message.
    ///
    /// Accepts either raw DER or base64-encoded DER (some transports/servers
    /// base64 the body), mirroring [`crate::types::parse_certs_only`].
    pub fn parse(body: &[u8]) -> Result<Self> {
        let der_bytes = normalize_to_der(body)?;

        let content_info = ContentInfo::from_der(&der_bytes)
            .map_err(|e| EstError::tamp(format!("parse CMS ContentInfo: {e}")))?;

        if content_info.content_type != ID_SIGNED_DATA {
            return Err(EstError::tamp(format!(
                "expected CMS SignedData ({ID_SIGNED_DATA}), got {}",
                content_info.content_type
            )));
        }

        let signed_data = content_info
            .content
            .to_der()
            .map_err(|e| EstError::tamp(format!("re-encode CMS content: {e}")))
            .and_then(|der| {
                SignedData::from_der(&der)
                    .map_err(|e| EstError::tamp(format!("parse CMS SignedData: {e}")))
            })?;

        let eci = &signed_data.encap_content_info;
        let econtent_type = eci.econtent_type;

        // eContent is `[0] EXPLICIT OCTET STRING`; its octets are the TAMP
        // message DER. A TAMP message must carry inline content.
        let econtent = extract_econtent(eci)?;

        Ok(Self {
            content_type: TampContentType::from_oid(&econtent_type),
            econtent_type,
            econtent,
            signed_data,
        })
    }

    /// The recognized content type, or an error naming the unknown OID.
    pub fn require_known_type(&self) -> Result<TampContentType> {
        self.content_type.ok_or_else(|| {
            EstError::tamp(format!(
                "unrecognized TAMP eContentType: {}",
                self.econtent_type
            ))
        })
    }
}

/// Pull the inner message DER out of an `EncapsulatedContentInfo`.
fn extract_econtent(eci: &EncapsulatedContentInfo) -> Result<Vec<u8>> {
    let any = eci.econtent.as_ref().ok_or_else(|| {
        EstError::tamp("CMS eContent is absent (detached TAMP messages are not allowed)")
    })?;

    // eContent is an OCTET STRING; its value octets are the encapsulated DER.
    if any.tag() != Tag::OctetString {
        return Err(EstError::tamp(format!(
            "CMS eContent has unexpected tag {:?}, expected OCTET STRING",
            any.tag()
        )));
    }
    let octets: OctetString = any
        .decode_as()
        .map_err(|e| EstError::tamp(format!("decode eContent OCTET STRING: {e}")))?;
    Ok(octets.as_bytes().to_vec())
}

/// Assemble a CMS `SignedData` `ContentInfo` from already-built parts.
///
/// `certificates` and `signer_infos` are produced by [`super::response`]; this
/// function is the structural glue that wraps a TAMP message body. Returns the
/// DER of the outer `ContentInfo`.
pub fn assemble_signed_data(
    econtent_type: ObjectIdentifier,
    econtent_der: &[u8],
    digest_algorithms: SetOfVec<spki::AlgorithmIdentifierOwned>,
    certificates: Option<cms::signed_data::CertificateSet>,
    signer_infos: Vec<SignerInfo>,
) -> Result<Vec<u8>> {
    let econtent = Any::new(Tag::OctetString, econtent_der)
        .map_err(|e| EstError::tamp(format!("wrap eContent: {e}")))?;

    let signer_infos = SetOfVec::try_from(signer_infos)
        .map_err(|e| EstError::tamp(format!("build signerInfos set: {e}")))?;

    let signed_data = SignedData {
        version: cms::content_info::CmsVersion::V3,
        digest_algorithms,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type,
            econtent: Some(econtent),
        },
        certificates,
        crls: None,
        signer_infos: cms::signed_data::SignerInfos(signer_infos),
    };

    let signed_data_der = signed_data
        .to_der()
        .map_err(|e| EstError::tamp(format!("encode SignedData: {e}")))?;

    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::from_der(&signed_data_der)
            .map_err(|e| EstError::tamp(format!("wrap SignedData in ContentInfo: {e}")))?,
    };

    content_info
        .to_der()
        .map_err(|e| EstError::tamp(format!("encode ContentInfo: {e}")))
}

/// Wrap a TAMP message body as `[0] EXPLICIT OCTET STRING` eContent `Any`.
///
/// Exposed for callers that build their own `SignedData`.
pub fn econtent_any(econtent_der: &[u8]) -> Result<Any> {
    Any::new(Tag::OctetString, econtent_der)
        .map_err(|e| EstError::tamp(format!("wrap eContent: {e}")))
}

/// Decode a body that is either raw DER (leading SEQUENCE tag `0x30`) or
/// base64-encoded DER. Mirrors the heuristic in `types::pkcs7`.
fn normalize_to_der(body: &[u8]) -> Result<Vec<u8>> {
    let first = body.iter().position(|b| !b.is_ascii_whitespace());
    match first {
        Some(i) if body[i] == 0x30 => Ok(body[i..].to_vec()),
        _ => {
            let cleaned: Vec<u8> = body
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            BASE64_STANDARD
                .decode(&cleaned)
                .map_err(|e| EstError::tamp(format!("base64-decode TAMP body: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tamp::asn1::{
        TampMsgRef, TampStatusQuery, TampVersion, TargetIdentifier, TerseOrVerbose,
    };

    // Build a self-signed-free SignedData purely to exercise the structural
    // wrap → parse round trip (no real signer; signer_infos empty).
    fn sample_status_query_der() -> Vec<u8> {
        let q = TampStatusQuery {
            version: TampVersion::V2,
            terse: TerseOrVerbose::Verbose,
            query: TampMsgRef {
                target: TargetIdentifier::AllModules(der::asn1::Null),
                seq_num: 1,
            },
        };
        q.to_der().unwrap()
    }

    #[test]
    fn assemble_then_parse_round_trips_content() {
        let msg_der = sample_status_query_der();
        let digest_algs = SetOfVec::new();
        let cms_der = assemble_signed_data(
            crate::tamp::oid::ID_CT_TAMP_STATUS_QUERY,
            &msg_der,
            digest_algs,
            None,
            vec![],
        )
        .unwrap();

        let parsed = TampMessage::parse(&cms_der).unwrap();
        assert_eq!(parsed.content_type, Some(TampContentType::StatusQuery));
        assert_eq!(
            parsed.econtent_type,
            crate::tamp::oid::ID_CT_TAMP_STATUS_QUERY
        );
        assert_eq!(parsed.econtent, msg_der);
        // And the inner bytes decode back to the original message.
        let back = TampStatusQuery::from_der(&parsed.econtent).unwrap();
        assert_eq!(back.query.seq_num, 1);
    }

    #[test]
    fn parse_accepts_base64_bodies() {
        let msg_der = sample_status_query_der();
        let cms_der = assemble_signed_data(
            crate::tamp::oid::ID_CT_TAMP_STATUS_QUERY,
            &msg_der,
            SetOfVec::new(),
            None,
            vec![],
        )
        .unwrap();
        let b64 = BASE64_STANDARD.encode(&cms_der);
        let parsed = TampMessage::parse(b64.as_bytes()).unwrap();
        assert_eq!(parsed.content_type, Some(TampContentType::StatusQuery));
    }

    #[test]
    fn rejects_non_signed_data() {
        // A bare TAMP message (not CMS-wrapped) must be rejected.
        let msg_der = sample_status_query_der();
        let err = TampMessage::parse(&msg_der).unwrap_err();
        assert!(matches!(err, EstError::Tamp(_)));
    }
}
