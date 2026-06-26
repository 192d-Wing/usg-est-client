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

//! Object identifiers for TAMP (RFC 5934) and the Trust Anchor Format (RFC 5914).
//!
//! # Provenance
//!
//! All OID values in this module are transcribed verbatim from the authoritative
//! ASN.1 modules in the RFCs (RFC 5934 Appendix A and RFC 5914 Appendix A) — NOT
//! from secondary summaries. The base arc for TAMP message content types is, per
//! RFC 5934 Appendix A:
//!
//! ```text
//! id-tamp OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) country(16) us(840)
//!     organization(1) gov(101) dod(2) infosec(1) formats(2) 77 }
//! ```
//!
//! i.e. `2.16.840.1.101.2.1.2.77` — the DoD infosec "formats" arc, **not** the
//! `id-smime` arc. Every TAMP content type hangs directly off `id-tamp`.
//!
//! The Trust Anchor List content type (RFC 5914) lives under the S/MIME `id-ct`
//! arc instead: `id-ct-trustAnchorList = 1.2.840.113549.1.9.16.1.34`.

use const_oid::ObjectIdentifier;

/// Base arc for TAMP message content types (RFC 5934 Appendix A): `id-tamp`.
///
/// `2.16.840.1.101.2.1.2.77`
pub const ID_TAMP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77");

/// `id-ct-TAMP-statusQuery ::= { id-tamp 1 }` — `TAMPStatusQuery` content type.
pub const ID_CT_TAMP_STATUS_QUERY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.1");

/// `id-ct-TAMP-statusResponse ::= { id-tamp 2 }` — `TAMPStatusResponse` content type.
pub const ID_CT_TAMP_STATUS_RESPONSE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.2");

/// `id-ct-TAMP-update ::= { id-tamp 3 }` — `TAMPUpdate` content type.
pub const ID_CT_TAMP_UPDATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.3");

/// `id-ct-TAMP-updateConfirm ::= { id-tamp 4 }` — `TAMPUpdateConfirm` content type.
pub const ID_CT_TAMP_UPDATE_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.4");

/// `id-ct-TAMP-apexUpdate ::= { id-tamp 5 }` — `TAMPApexUpdate` content type.
pub const ID_CT_TAMP_APEX_UPDATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.5");

/// `id-ct-TAMP-apexUpdateConfirm ::= { id-tamp 6 }` — `TAMPApexUpdateConfirm` content type.
pub const ID_CT_TAMP_APEX_UPDATE_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.6");

/// `id-ct-TAMP-communityUpdate ::= { id-tamp 7 }` — `TAMPCommunityUpdate` content type.
pub const ID_CT_TAMP_COMMUNITY_UPDATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.7");

/// `id-ct-TAMP-communityUpdateConfirm ::= { id-tamp 8 }` — `TAMPCommunityUpdateConfirm` content type.
pub const ID_CT_TAMP_COMMUNITY_UPDATE_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.8");

/// `id-ct-TAMP-error ::= { id-tamp 9 }` — `TAMPError` content type.
///
/// Note the out-of-order assignment in RFC 5934: error is `{ id-tamp 9 }` while
/// the sequence-number-adjust pair are `{ id-tamp 10 }` / `{ id-tamp 11 }`.
pub const ID_CT_TAMP_ERROR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.9");

/// `id-ct-TAMP-seqNumAdjust ::= { id-tamp 10 }` — `SequenceNumberAdjust` content type.
pub const ID_CT_TAMP_SEQ_NUM_ADJUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.10");

/// `id-ct-TAMP-seqNumAdjustConfirm ::= { id-tamp 11 }` — `SequenceNumberAdjustConfirm` content type.
pub const ID_CT_TAMP_SEQ_NUM_ADJUST_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.11");

/// `id-ct-trustAnchorList` (RFC 5914) — CMS content type wrapping a `TrustAnchorList`.
///
/// `{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
///    id-smime(16) id-ct(1) 34 }` = `1.2.840.113549.1.9.16.1.34`.
pub const ID_CT_TRUST_ANCHOR_LIST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.34");

/// `id-aa-TAMP-contingencyPublicKeyDecryptKey ::= { id-attributes 63 }` (RFC 5934).
///
/// Unsigned CMS attribute carrying the contingency symmetric key. `id-attributes`
/// is `{ ... dod(2) infosec(1) 5 }` = `2.16.840.1.101.2.1.5`.
pub const ID_AA_TAMP_CONTINGENCY_PUBLIC_KEY_DECRYPT_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.5.63");

/// The kind of TAMP message identified by a CMS `eContentType`.
///
/// Used to dispatch a verified CMS payload to the correct ASN.1 decoder. Only the
/// variants a TAMP *client* receives are acted upon; the client-originated types
/// are still recognized here for completeness and logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TampContentType {
    /// `TAMPStatusQuery` (client → server).
    StatusQuery,
    /// `TAMPStatusResponse` (server → client) — carries the trust anchor list.
    StatusResponse,
    /// `TAMPUpdate` (server → client).
    Update,
    /// `TAMPUpdateConfirm` (client → server).
    UpdateConfirm,
    /// `TAMPApexUpdate` (server → client).
    ApexUpdate,
    /// `TAMPApexUpdateConfirm` (client → server).
    ApexUpdateConfirm,
    /// `TAMPCommunityUpdate` (server → client).
    CommunityUpdate,
    /// `TAMPCommunityUpdateConfirm` (client → server).
    CommunityUpdateConfirm,
    /// `SequenceNumberAdjust` (server → client).
    SeqNumAdjust,
    /// `SequenceNumberAdjustConfirm` (client → server).
    SeqNumAdjustConfirm,
    /// `TAMPError` (either direction).
    Error,
}

impl TampContentType {
    /// Resolve a CMS `eContentType` OID to its TAMP message kind, if recognized.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        Some(match *oid {
            ID_CT_TAMP_STATUS_QUERY => Self::StatusQuery,
            ID_CT_TAMP_STATUS_RESPONSE => Self::StatusResponse,
            ID_CT_TAMP_UPDATE => Self::Update,
            ID_CT_TAMP_UPDATE_CONFIRM => Self::UpdateConfirm,
            ID_CT_TAMP_APEX_UPDATE => Self::ApexUpdate,
            ID_CT_TAMP_APEX_UPDATE_CONFIRM => Self::ApexUpdateConfirm,
            ID_CT_TAMP_COMMUNITY_UPDATE => Self::CommunityUpdate,
            ID_CT_TAMP_COMMUNITY_UPDATE_CONFIRM => Self::CommunityUpdateConfirm,
            ID_CT_TAMP_SEQ_NUM_ADJUST => Self::SeqNumAdjust,
            ID_CT_TAMP_SEQ_NUM_ADJUST_CONFIRM => Self::SeqNumAdjustConfirm,
            ID_CT_TAMP_ERROR => Self::Error,
            _ => return None,
        })
    }

    /// The CMS `eContentType` OID for this message kind.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            Self::StatusQuery => ID_CT_TAMP_STATUS_QUERY,
            Self::StatusResponse => ID_CT_TAMP_STATUS_RESPONSE,
            Self::Update => ID_CT_TAMP_UPDATE,
            Self::UpdateConfirm => ID_CT_TAMP_UPDATE_CONFIRM,
            Self::ApexUpdate => ID_CT_TAMP_APEX_UPDATE,
            Self::ApexUpdateConfirm => ID_CT_TAMP_APEX_UPDATE_CONFIRM,
            Self::CommunityUpdate => ID_CT_TAMP_COMMUNITY_UPDATE,
            Self::CommunityUpdateConfirm => ID_CT_TAMP_COMMUNITY_UPDATE_CONFIRM,
            Self::SeqNumAdjust => ID_CT_TAMP_SEQ_NUM_ADJUST,
            Self::SeqNumAdjustConfirm => ID_CT_TAMP_SEQ_NUM_ADJUST_CONFIRM,
            Self::Error => ID_CT_TAMP_ERROR,
        }
    }

    /// The IANA media type registered for this message (RFC 5934 §6 / Appendix B).
    ///
    /// Used as the HTTP `Content-Type` when sending and `Accept` when expecting a
    /// particular response.
    pub fn media_type(self) -> &'static str {
        match self {
            Self::StatusQuery => "application/tamp-status-query",
            Self::StatusResponse => "application/tamp-status-response",
            Self::Update => "application/tamp-update",
            Self::UpdateConfirm => "application/tamp-update-confirm",
            Self::ApexUpdate => "application/tamp-apex-update",
            Self::ApexUpdateConfirm => "application/tamp-apex-update-confirm",
            Self::CommunityUpdate => "application/tamp-community-update",
            Self::CommunityUpdateConfirm => "application/tamp-community-update-confirm",
            Self::SeqNumAdjust => "application/tamp-sequence-adjust",
            Self::SeqNumAdjustConfirm => "application/tamp-sequence-adjust-confirm",
            Self::Error => "application/tamp-error",
        }
    }

    /// True if this message kind is one a managed client *receives* (server → client).
    ///
    /// `TAMPError` is excluded here because it may travel in either direction.
    pub fn is_client_inbound(self) -> bool {
        matches!(
            self,
            Self::StatusResponse | Self::Update | Self::ApexUpdate | Self::CommunityUpdate
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact dotted strings so any accidental edit (or a future "correction"
    // back to the wrong id-smime arc that the secondary sources suggested) fails CI.
    #[test]
    fn tamp_content_type_oids_are_exact() {
        assert_eq!(ID_TAMP.to_string(), "2.16.840.1.101.2.1.2.77");
        assert_eq!(
            ID_CT_TAMP_STATUS_QUERY.to_string(),
            "2.16.840.1.101.2.1.2.77.1"
        );
        assert_eq!(
            ID_CT_TAMP_STATUS_RESPONSE.to_string(),
            "2.16.840.1.101.2.1.2.77.2"
        );
        assert_eq!(ID_CT_TAMP_UPDATE.to_string(), "2.16.840.1.101.2.1.2.77.3");
        assert_eq!(ID_CT_TAMP_ERROR.to_string(), "2.16.840.1.101.2.1.2.77.9");
        assert_eq!(
            ID_CT_TAMP_SEQ_NUM_ADJUST.to_string(),
            "2.16.840.1.101.2.1.2.77.10"
        );
        assert_eq!(
            ID_CT_TAMP_SEQ_NUM_ADJUST_CONFIRM.to_string(),
            "2.16.840.1.101.2.1.2.77.11"
        );
    }

    #[test]
    fn trust_anchor_list_oid_is_under_id_ct() {
        assert_eq!(
            ID_CT_TRUST_ANCHOR_LIST.to_string(),
            "1.2.840.113549.1.9.16.1.34"
        );
    }

    #[test]
    fn content_types_all_under_id_tamp_arc() {
        // Every TAMP message OID must be a child of id-tamp.
        let prefix = format!("{}.", ID_TAMP);
        for ct in [
            TampContentType::StatusQuery,
            TampContentType::StatusResponse,
            TampContentType::Update,
            TampContentType::UpdateConfirm,
            TampContentType::ApexUpdate,
            TampContentType::ApexUpdateConfirm,
            TampContentType::CommunityUpdate,
            TampContentType::CommunityUpdateConfirm,
            TampContentType::SeqNumAdjust,
            TampContentType::SeqNumAdjustConfirm,
            TampContentType::Error,
        ] {
            assert!(
                ct.oid().to_string().starts_with(&prefix),
                "{ct:?} OID {} not under id-tamp",
                ct.oid()
            );
        }
    }

    #[test]
    fn oid_round_trips_through_dispatch() {
        for ct in [
            TampContentType::StatusQuery,
            TampContentType::StatusResponse,
            TampContentType::Update,
            TampContentType::UpdateConfirm,
            TampContentType::ApexUpdate,
            TampContentType::ApexUpdateConfirm,
            TampContentType::CommunityUpdate,
            TampContentType::CommunityUpdateConfirm,
            TampContentType::SeqNumAdjust,
            TampContentType::SeqNumAdjustConfirm,
            TampContentType::Error,
        ] {
            assert_eq!(TampContentType::from_oid(&ct.oid()), Some(ct));
        }
    }

    #[test]
    fn unknown_oid_is_not_a_tamp_type() {
        // id-ct-trustAnchorList is a TAF type, not a TAMP message type.
        assert_eq!(TampContentType::from_oid(&ID_CT_TRUST_ANCHOR_LIST), None);
    }

    #[test]
    fn client_inbound_classification() {
        assert!(TampContentType::StatusResponse.is_client_inbound());
        assert!(TampContentType::Update.is_client_inbound());
        assert!(!TampContentType::StatusQuery.is_client_inbound());
        assert!(!TampContentType::UpdateConfirm.is_client_inbound());
        // Error is bidirectional, so not classified as strictly inbound.
        assert!(!TampContentType::Error.is_client_inbound());
    }
}
