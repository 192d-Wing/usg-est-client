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

//! TAMP message ASN.1 types (RFC 5934 Appendix A).
//!
//! These are hand-rolled `der`-derived types transcribed verbatim from the
//! authoritative ASN.1 module in RFC 5934 Appendix A.2 (1988 syntax), which is
//! `DEFINITIONS IMPLICIT TAGS`. Consequently every context-specific tag below is
//! `IMPLICIT` **unless** the RFC explicitly marks it `EXPLICIT` (the two such
//! sites — `TrustAnchorUpdate.change [3]` and `TBSCertificateChangeInfo.exts [5]`
//! — are tagged `tag_mode = "EXPLICIT"`).
//!
//! The trust anchor payload type `TrustAnchorChoice` (and `TrustAnchorInfo`,
//! `CertPathControls`) come from RFC 5914 and are reused from
//! [`x509_cert::anchor`] rather than re-derived here.
//!
//! Each ASN.1 definition is reproduced in a doc comment above its Rust type for
//! auditing against the RFC.

use der::asn1::{Ia5String, ObjectIdentifier, OctetString};
use der::{Any, Choice, Enumerated, Sequence};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::anchor::TrustAnchorChoice;
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

// ===========================================================================
// Primitive / shared types
// ===========================================================================

/// `KeyIdentifier` — an octet string public key identifier (RFC 5280 §4.2.1.2).
pub type KeyIdentifier = OctetString;

/// `Community ::= OBJECT IDENTIFIER`
pub type Community = ObjectIdentifier;

/// `SeqNumber ::= INTEGER (0..9223372036854775807)`
///
/// The upper bound is `i64::MAX`; we hold it in a `u64` (always in range).
pub type SeqNumber = u64;

/// `TAMPVersion ::= INTEGER { v1(1), v2(2) }`, `DEFAULT v2`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum TampVersion {
    /// Version 1.
    V1 = 1,
    /// Version 2 (default).
    #[default]
    V2 = 2,
}

/// `TerseOrVerbose ::= ENUMERATED { terse(1), verbose(2) }`, `DEFAULT verbose`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Enumerated)]
#[repr(u8)]
pub enum TerseOrVerbose {
    /// Terse form requested/used.
    Terse = 1,
    /// Verbose form requested/used (default).
    #[default]
    Verbose = 2,
}

/// DEFAULT helper: `usesApex BOOLEAN DEFAULT TRUE`.
fn default_true() -> bool {
    true
}

/// ```text
/// HardwareSerialEntry ::= CHOICE {
///   all     NULL,
///   single  OCTET STRING,
///   block   SEQUENCE { low OCTET STRING, high OCTET STRING } }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum HardwareSerialEntry {
    All(der::asn1::Null),
    Single(OctetString),
    Block(HardwareSerialBlock),
}

/// The `block` arm of [`HardwareSerialEntry`].
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct HardwareSerialBlock {
    pub low: OctetString,
    pub high: OctetString,
}

/// ```text
/// HardwareModules ::= SEQUENCE {
///   hwType          OBJECT IDENTIFIER,
///   hwSerialEntries SEQUENCE SIZE (1..MAX) OF HardwareSerialEntry }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct HardwareModules {
    pub hw_type: ObjectIdentifier,
    pub hw_serial_entries: Vec<HardwareSerialEntry>,
}

/// ```text
/// AnotherName ::= SEQUENCE {  -- INSTANCE OF OTHER-NAME
///   type-id  OBJECT IDENTIFIER,
///   value    [0] EXPLICIT ANY DEFINED BY type-id }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct AnotherName {
    pub type_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub value: Any,
}

/// ```text
/// TargetIdentifier ::= CHOICE {
///   hwModules    [1] HardwareModuleIdentifierList,
///   communities  [2] CommunityIdentifierList,
///   allModules   [3] NULL,
///   uri          [4] IA5String,
///   otherName    [5] INSTANCE OF OTHER-NAME }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum TargetIdentifier {
    /// `hwModules [1] HardwareModuleIdentifierList` (SEQUENCE OF HardwareModules).
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    HwModules(Vec<HardwareModules>),

    /// `communities [2] CommunityIdentifierList`.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", constructed = "true")]
    Communities(Vec<Community>),

    /// `allModules [3] NULL` — addresses every module.
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT")]
    AllModules(der::asn1::Null),

    /// `uri [4] IA5String`.
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT")]
    Uri(Ia5String),

    /// `otherName [5] INSTANCE OF OTHER-NAME`.
    #[asn1(context_specific = "5", tag_mode = "IMPLICIT", constructed = "true")]
    OtherName(AnotherName),
}

/// ```text
/// TAMPMsgRef ::= SEQUENCE {
///   target  TargetIdentifier,
///   seqNum  SeqNumber }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampMsgRef {
    pub target: TargetIdentifier,
    pub seq_num: SeqNumber,
}

/// ```text
/// TAMPSequenceNumber ::= SEQUENCE {
///   keyId      KeyIdentifier,
///   seqNumber  SeqNumber }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampSequenceNumber {
    pub key_id: KeyIdentifier,
    pub seq_number: SeqNumber,
}

// ===========================================================================
// Status Query / Status Response (RFC 5934 §4.1–4.2)
// ===========================================================================

/// ```text
/// TAMPStatusQuery ::= SEQUENCE {
///   version  [0] TAMPVersion DEFAULT v2,
///   terse    [1] TerseOrVerbose DEFAULT verbose,
///   query        TAMPMsgRef }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampStatusQuery {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", default = "Default::default")]
    pub terse: TerseOrVerbose,

    pub query: TampMsgRef,
}

/// ```text
/// TerseStatusResponse ::= SEQUENCE {
///   taKeyIds     KeyIdentifiers,
///   communities  CommunityIdentifierList OPTIONAL }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TerseStatusResponse {
    /// `KeyIdentifiers ::= SEQUENCE SIZE (1..MAX) OF KeyIdentifier`
    pub ta_key_ids: Vec<KeyIdentifier>,

    #[asn1(optional = "true")]
    pub communities: Option<Vec<Community>>,
}

/// ```text
/// VerboseStatusResponse ::= SEQUENCE {
///   taInfo                  TrustAnchorChoiceList,
///   continPubKeyDecryptAlg  [0] AlgorithmIdentifier OPTIONAL,
///   communities             [1] CommunityIdentifierList OPTIONAL,
///   tampSeqNumbers          [2] TAMPSequenceNumbers OPTIONAL }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct VerboseStatusResponse {
    /// `TrustAnchorChoiceList ::= SEQUENCE SIZE (1..MAX) OF TrustAnchorChoice`.
    pub ta_info: Vec<TrustAnchorChoice>,

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub contin_pub_key_decrypt_alg: Option<AlgorithmIdentifierOwned>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub communities: Option<Vec<Community>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub tamp_seq_numbers: Option<Vec<TampSequenceNumber>>,
}

/// ```text
/// StatusResponse ::= CHOICE {
///   terseResponse    [0] TerseStatusResponse,
///   verboseResponse  [1] VerboseStatusResponse }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum StatusResponse {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    Terse(TerseStatusResponse),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Verbose(VerboseStatusResponse),
}

/// ```text
/// TAMPStatusResponse ::= SEQUENCE {
///   version   [0] TAMPVersion DEFAULT v2,
///   query         TAMPMsgRef,
///   response      StatusResponse,
///   usesApex      BOOLEAN DEFAULT TRUE }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampStatusResponse {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    pub query: TampMsgRef,

    pub response: StatusResponse,

    #[asn1(default = "default_true")]
    pub uses_apex: bool,
}

// ===========================================================================
// Trust Anchor Update / Update Confirm (RFC 5934 §4.3–4.4)
// ===========================================================================

/// ```text
/// TBSCertificateChangeInfo ::= SEQUENCE {
///   serialNumber          CertificateSerialNumber OPTIONAL,
///   signature             [0] AlgorithmIdentifier OPTIONAL,
///   issuer                [1] Name OPTIONAL,
///   validity              [2] Validity OPTIONAL,
///   subject               [3] Name OPTIONAL,
///   subjectPublicKeyInfo  [4] SubjectPublicKeyInfo,
///   exts                  [5] EXPLICIT Extensions OPTIONAL }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TbsCertificateChangeInfo {
    #[asn1(optional = "true")]
    pub serial_number: Option<SerialNumber>,

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub signature: Option<AlgorithmIdentifierOwned>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer: Option<Name>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub validity: Option<Validity>,

    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    pub subject: Option<Name>,

    #[asn1(context_specific = "4", tag_mode = "IMPLICIT")]
    pub subject_public_key_info: SubjectPublicKeyInfoOwned,

    #[asn1(context_specific = "5", tag_mode = "EXPLICIT", optional = "true")]
    pub exts: Option<Extensions>,
}

/// ```text
/// TrustAnchorChangeInfo ::= SEQUENCE {
///   pubKey    SubjectPublicKeyInfo,
///   keyId     KeyIdentifier OPTIONAL,
///   taTitle   TrustAnchorTitle OPTIONAL,
///   certPath  CertPathControls OPTIONAL,
///   exts      [1] Extensions OPTIONAL }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TrustAnchorChangeInfo {
    pub pub_key: SubjectPublicKeyInfoOwned,

    #[asn1(optional = "true")]
    pub key_id: Option<KeyIdentifier>,

    /// `TrustAnchorTitle ::= UTF8String (SIZE (1..64))`
    #[asn1(optional = "true")]
    pub ta_title: Option<String>,

    #[asn1(optional = "true")]
    pub cert_path: Option<x509_cert::anchor::CertPathControls>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub exts: Option<Extensions>,
}

/// ```text
/// TrustAnchorChangeInfoChoice ::= CHOICE {
///   tbsCertChange  [0] TBSCertificateChangeInfo,
///   taChange       [1] TrustAnchorChangeInfo }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum TrustAnchorChangeInfoChoice {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    TbsCertChange(TbsCertificateChangeInfo),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    TaChange(TrustAnchorChangeInfo),
}

/// ```text
/// TrustAnchorUpdate ::= CHOICE {
///   add     [1] TrustAnchorChoice,
///   remove  [2] SubjectPublicKeyInfo,
///   change  [3] EXPLICIT TrustAnchorChangeInfoChoice }
/// ```
///
/// `add` wraps a CHOICE (`TrustAnchorChoice`), and `change` wraps a CHOICE
/// (`TrustAnchorChangeInfoChoice`); both therefore require EXPLICIT tagging.
/// (`add [1]` is written IMPLICIT in the module, but because its content is a
/// CHOICE, X.690 forces the tag to be constructed and the inner tag preserved —
/// `der` models this as EXPLICIT.)
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(clippy::large_enum_variant)]
#[allow(missing_docs)]
pub enum TrustAnchorUpdate {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    Add(TrustAnchorChoice),

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", constructed = "true")]
    Remove(SubjectPublicKeyInfoOwned),

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
    Change(TrustAnchorChangeInfoChoice),
}

/// ```text
/// TAMPUpdate ::= SEQUENCE {
///   version        [0] TAMPVersion DEFAULT v2,
///   terse          [1] TerseOrVerbose DEFAULT verbose,
///   msgRef             TAMPMsgRef,
///   updates            SEQUENCE SIZE (1..MAX) OF TrustAnchorUpdate,
///   tampSeqNumbers [2] TAMPSequenceNumbers OPTIONAL }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampUpdate {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", default = "Default::default")]
    pub terse: TerseOrVerbose,

    pub msg_ref: TampMsgRef,

    pub updates: Vec<TrustAnchorUpdate>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub tamp_seq_numbers: Option<Vec<TampSequenceNumber>>,
}

/// `StatusCodeList ::= SEQUENCE SIZE (1..MAX) OF StatusCode`
pub type StatusCodeList = Vec<StatusCode>;

/// ```text
/// VerboseUpdateConfirm ::= SEQUENCE {
///   status          StatusCodeList,
///   taInfo          TrustAnchorChoiceList,
///   tampSeqNumbers  TAMPSequenceNumbers OPTIONAL,
///   usesApex        BOOLEAN DEFAULT TRUE }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct VerboseUpdateConfirm {
    pub status: StatusCodeList,
    pub ta_info: Vec<TrustAnchorChoice>,

    #[asn1(optional = "true")]
    pub tamp_seq_numbers: Option<Vec<TampSequenceNumber>>,

    #[asn1(default = "default_true")]
    pub uses_apex: bool,
}

/// ```text
/// UpdateConfirm ::= CHOICE {
///   terseConfirm    [0] TerseUpdateConfirm,    -- StatusCodeList
///   verboseConfirm  [1] VerboseUpdateConfirm }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum UpdateConfirm {
    /// `TerseUpdateConfirm ::= StatusCodeList`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    Terse(StatusCodeList),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Verbose(VerboseUpdateConfirm),
}

/// ```text
/// TAMPUpdateConfirm ::= SEQUENCE {
///   version  [0] TAMPVersion DEFAULT v2,
///   update       TAMPMsgRef,
///   confirm      UpdateConfirm }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampUpdateConfirm {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    pub update: TampMsgRef,

    pub confirm: UpdateConfirm,
}

// ===========================================================================
// Apex Trust Anchor Update / Confirm (RFC 5934 §4.5–4.6)
// ===========================================================================

/// ```text
/// TAMPApexUpdate ::= SEQUENCE {
///   version            [0] TAMPVersion DEFAULT v2,
///   terse              [1] TerseOrVerbose DEFAULT verbose,
///   msgRef                 TAMPMsgRef,
///   clearTrustAnchors      BOOLEAN,
///   clearCommunities       BOOLEAN,
///   seqNumber              SeqNumber OPTIONAL,
///   apexTA                 TrustAnchorChoice }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampApexUpdate {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", default = "Default::default")]
    pub terse: TerseOrVerbose,

    pub msg_ref: TampMsgRef,

    pub clear_trust_anchors: bool,

    pub clear_communities: bool,

    #[asn1(optional = "true")]
    pub seq_number: Option<SeqNumber>,

    pub apex_ta: TrustAnchorChoice,
}

/// ```text
/// VerboseApexUpdateConfirm ::= SEQUENCE {
///   status          StatusCode,
///   taInfo          TrustAnchorChoiceList,
///   communities     [0] CommunityIdentifierList OPTIONAL,
///   tampSeqNumbers  [1] TAMPSequenceNumbers OPTIONAL }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct VerboseApexUpdateConfirm {
    pub status: StatusCode,
    pub ta_info: Vec<TrustAnchorChoice>,

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub communities: Option<Vec<Community>>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub tamp_seq_numbers: Option<Vec<TampSequenceNumber>>,
}

/// ```text
/// ApexUpdateConfirm ::= CHOICE {
///   terseApexConfirm    [0] TerseApexUpdateConfirm,   -- StatusCode
///   verboseApexConfirm  [1] VerboseApexUpdateConfirm }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum ApexUpdateConfirm {
    /// `TerseApexUpdateConfirm ::= StatusCode`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Terse(StatusCode),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Verbose(VerboseApexUpdateConfirm),
}

/// ```text
/// TAMPApexUpdateConfirm ::= SEQUENCE {
///   version      [0] TAMPVersion DEFAULT v2,
///   apexReplace      TAMPMsgRef,
///   apexConfirm      ApexUpdateConfirm }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampApexUpdateConfirm {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    pub apex_replace: TampMsgRef,

    pub apex_confirm: ApexUpdateConfirm,
}

// ===========================================================================
// Community Update / Confirm (RFC 5934 §4.7–4.8)
// ===========================================================================

/// ```text
/// CommunityUpdates ::= SEQUENCE {
///   remove  [1] CommunityIdentifierList OPTIONAL,
///   add     [2] CommunityIdentifierList OPTIONAL }
///   -- At least one must be present
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct CommunityUpdates {
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub remove: Option<Vec<Community>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub add: Option<Vec<Community>>,
}

/// ```text
/// TAMPCommunityUpdate ::= SEQUENCE {
///   version  [0] TAMPVersion DEFAULT v2,
///   terse    [1] TerseOrVerbose DEFAULT verbose,
///   msgRef       TAMPMsgRef,
///   updates      CommunityUpdates }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampCommunityUpdate {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", default = "Default::default")]
    pub terse: TerseOrVerbose,

    pub msg_ref: TampMsgRef,

    pub updates: CommunityUpdates,
}

/// ```text
/// VerboseCommunityConfirm ::= SEQUENCE {
///   status       StatusCode,
///   communities  CommunityIdentifierList OPTIONAL }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct VerboseCommunityConfirm {
    pub status: StatusCode,

    #[asn1(optional = "true")]
    pub communities: Option<Vec<Community>>,
}

/// ```text
/// CommunityConfirm ::= CHOICE {
///   terseCommConfirm    [0] TerseCommunityConfirm,   -- StatusCode
///   verboseCommConfirm  [1] VerboseCommunityConfirm }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum CommunityConfirm {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Terse(StatusCode),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Verbose(VerboseCommunityConfirm),
}

/// ```text
/// TAMPCommunityUpdateConfirm ::= SEQUENCE {
///   version      [0] TAMPVersion DEFAULT v2,
///   update           TAMPMsgRef,
///   commConfirm      CommunityConfirm }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampCommunityUpdateConfirm {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    pub update: TampMsgRef,

    pub comm_confirm: CommunityConfirm,
}

// ===========================================================================
// Sequence Number Adjust / Confirm (RFC 5934 §4.9–4.10)
// ===========================================================================

/// ```text
/// SequenceNumberAdjust ::= SEQUENCE {
///   version  [0] TAMPVersion DEFAULT v2,
///   msgRef       TAMPMsgRef }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct SequenceNumberAdjust {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    pub msg_ref: TampMsgRef,
}

/// ```text
/// SequenceNumberAdjustConfirm ::= SEQUENCE {
///   version  [0] TAMPVersion DEFAULT v2,
///   adjust       TAMPMsgRef,
///   status       StatusCode }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct SequenceNumberAdjustConfirm {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    pub adjust: TampMsgRef,

    pub status: StatusCode,
}

// ===========================================================================
// TAMP Error (RFC 5934 §4.11) + StatusCode
// ===========================================================================

/// ```text
/// TAMPError ::= SEQUENCE {
///   version  [0] TAMPVersion DEFAULT v2,
///   msgType      OBJECT IDENTIFIER,
///   status       StatusCode,
///   msgRef       TAMPMsgRef OPTIONAL }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TampError {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "Default::default")]
    pub version: TampVersion,

    pub msg_type: ObjectIdentifier,

    pub status: StatusCode,

    #[asn1(optional = "true")]
    pub msg_ref: Option<TampMsgRef>,
}

/// ```text
/// StatusCode ::= ENUMERATED { success(0), ... other(127) }
/// ```
///
/// Full enumeration from RFC 5934 Appendix A.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumerated)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum StatusCode {
    Success = 0,
    DecodeFailure = 1,
    BadContentInfo = 2,
    BadSignedData = 3,
    BadEncapContent = 4,
    BadCertificate = 5,
    BadSignerInfo = 6,
    BadSignedAttrs = 7,
    BadUnsignedAttrs = 8,
    MissingContent = 9,
    NoTrustAnchor = 10,
    NotAuthorized = 11,
    BadDigestAlgorithm = 12,
    BadSignatureAlgorithm = 13,
    UnsupportedKeySize = 14,
    UnsupportedParameters = 15,
    SignatureFailure = 16,
    InsufficientMemory = 17,
    UnsupportedTampMsgType = 18,
    ApexTampAnchor = 19,
    ImproperTaAddition = 20,
    SeqNumFailure = 21,
    ContingencyPublicKeyDecrypt = 22,
    IncorrectTarget = 23,
    CommunityUpdateFailed = 24,
    TrustAnchorNotFound = 25,
    UnsupportedTaAlgorithm = 26,
    UnsupportedTaKeySize = 27,
    UnsupportedContinPubKeyDecryptAlg = 28,
    MissingSignature = 29,
    ResourcesBusy = 30,
    VersionNumberMismatch = 31,
    MissingPolicySet = 32,
    RevokedCertificate = 33,
    UnsupportedTrustAnchorFormat = 34,
    ImproperTaChange = 35,
    Malformed = 36,
    CmsError = 37,
    UnsupportedTargetIdentifier = 38,
    Other = 127,
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};

    fn allmodules_msgref(seq: u64) -> TampMsgRef {
        TampMsgRef {
            target: TargetIdentifier::AllModules(der::asn1::Null),
            seq_num: seq,
        }
    }

    #[test]
    fn status_query_round_trips() {
        let q = TampStatusQuery {
            version: TampVersion::V2,
            terse: TerseOrVerbose::Verbose,
            query: allmodules_msgref(1),
        };
        let der = q.to_der().unwrap();
        let back = TampStatusQuery::from_der(&der).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn status_query_defaults_are_omitted_on_the_wire() {
        // version=v2 and terse=verbose are the DEFAULTs, so DER must omit both;
        // the encoding should be just SEQUENCE { query }.
        let q = TampStatusQuery {
            version: TampVersion::V2,
            terse: TerseOrVerbose::Verbose,
            query: allmodules_msgref(7),
        };
        let der = q.to_der().unwrap();
        let back = TampStatusQuery::from_der(&der).unwrap();
        assert_eq!(back.version, TampVersion::V2);
        assert_eq!(back.terse, TerseOrVerbose::Verbose);

        // A non-default value must round-trip distinctly.
        let q2 = TampStatusQuery {
            version: TampVersion::V1,
            terse: TerseOrVerbose::Terse,
            query: allmodules_msgref(7),
        };
        let der2 = q2.to_der().unwrap();
        assert!(der2.len() > der.len(), "non-default fields must be encoded");
        assert_eq!(TampStatusQuery::from_der(&der2).unwrap(), q2);
    }

    #[test]
    fn terse_status_response_round_trips() {
        let resp = TampStatusResponse {
            version: TampVersion::V2,
            query: allmodules_msgref(3),
            response: StatusResponse::Terse(TerseStatusResponse {
                ta_key_ids: vec![OctetString::new(vec![1, 2, 3, 4]).unwrap()],
                communities: None,
            }),
            uses_apex: true,
        };
        let der = resp.to_der().unwrap();
        let back = TampStatusResponse::from_der(&der).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn uri_target_round_trips() {
        let r = TampMsgRef {
            target: TargetIdentifier::Uri(Ia5String::new("https://tamp.example.mil").unwrap()),
            seq_num: 42,
        };
        let der = r.to_der().unwrap();
        assert_eq!(TampMsgRef::from_der(&der).unwrap(), r);
    }

    #[test]
    fn tamp_error_round_trips() {
        let e = TampError {
            version: TampVersion::V2,
            msg_type: crate::tamp::oid::ID_CT_TAMP_UPDATE,
            status: StatusCode::SeqNumFailure,
            msg_ref: Some(allmodules_msgref(9)),
        };
        let der = e.to_der().unwrap();
        assert_eq!(TampError::from_der(&der).unwrap(), e);
    }

    #[test]
    fn status_code_encodes_as_enumerated() {
        let der = StatusCode::Other.to_der().unwrap();
        // ENUMERATED tag 0x0A, length 1, value 127 (0x7F).
        assert_eq!(der, vec![0x0A, 0x01, 0x7F]);
    }
}
