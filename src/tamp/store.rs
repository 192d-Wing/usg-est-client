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

//! Local trust anchor store with sequence-number replay protection.
//!
//! The store holds the set of trust anchors a client currently trusts — as
//! pulled from a [`TAMPStatusResponse`](super::asn1::TampStatusResponse) and
//! mutated by verified update messages — together with, per trust anchor, the
//! highest TAMP sequence number accepted so far. The sequence numbers are the
//! anti-replay state required by RFC 5934 §5: a management message is rejected
//! unless its sequence number strictly exceeds the stored value for the signing
//! trust anchor.
//!
//! # Persistence
//!
//! [`TrustAnchorStore::to_der`] / [`TrustAnchorStore::from_der`] serialize the
//! whole store (anchors + key ids + sequence numbers + apex flag) as canonical
//! DER, so pulled trust anchors and their replay counters survive restarts
//! without pulling in `serde`. This keeps the FIPS build's dependency surface
//! minimal.

use der::asn1::OctetString;
use der::{Decode, Encode, Sequence};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::anchor::TrustAnchorChoice;

use crate::error::{EstError, Result};
use crate::fips_crypto;

/// Subject Key Identifier extension OID (RFC 5280 §4.2.1.2): `2.5.29.14`.
const OID_SUBJECT_KEY_IDENTIFIER: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.5.29.14");

/// One trust anchor plus its management metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchorStoreEntry {
    /// The trust anchor itself (RFC 5914 `TrustAnchorChoice`).
    pub anchor: TrustAnchorChoice,
    /// The trust anchor's key identifier, used to match TAMP sequence numbers
    /// and update/remove operations. See [`derive_key_id`].
    pub key_id: Vec<u8>,
    /// Highest TAMP sequence number accepted from this trust anchor, if any.
    pub last_seq_num: Option<u64>,
    /// Whether this is the apex trust anchor (the root of the management trust).
    pub is_apex: bool,
}

impl TrustAnchorStoreEntry {
    /// Build an entry for `anchor`, deriving its key identifier.
    pub fn new(anchor: TrustAnchorChoice, is_apex: bool) -> Result<Self> {
        let key_id = derive_key_id(&anchor)?;
        Ok(Self {
            anchor,
            key_id,
            last_seq_num: None,
            is_apex,
        })
    }

    /// The trust anchor's `SubjectPublicKeyInfo`, used to verify signatures.
    pub fn public_key(&self) -> Result<SubjectPublicKeyInfoOwned> {
        spki_of(&self.anchor)
    }

    /// A human-readable title, if the anchor carries one (`taTitle`).
    pub fn title(&self) -> Option<String> {
        match &self.anchor {
            TrustAnchorChoice::TaInfo(info) => info.ta_title.clone(),
            _ => None,
        }
    }
}

/// An in-memory trust anchor store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustAnchorStore {
    entries: Vec<TrustAnchorStoreEntry>,
}

impl TrustAnchorStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of trust anchors held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over the store entries.
    pub fn iter(&self) -> impl Iterator<Item = &TrustAnchorStoreEntry> {
        self.entries.iter()
    }

    /// The apex trust anchor entry, if one is designated.
    pub fn apex(&self) -> Option<&TrustAnchorStoreEntry> {
        self.entries.iter().find(|e| e.is_apex)
    }

    /// Find a trust anchor by its key identifier.
    pub fn find_by_key_id(&self, key_id: &[u8]) -> Option<&TrustAnchorStoreEntry> {
        self.entries.iter().find(|e| e.key_id == key_id)
    }

    /// Find a trust anchor by its `SubjectPublicKeyInfo` (DER-equality).
    ///
    /// Used to resolve `TrustAnchorUpdate::remove`, which identifies the target
    /// trust anchor by its public key rather than its key id.
    pub fn find_by_spki(&self, spki: &SubjectPublicKeyInfoOwned) -> Result<Option<usize>> {
        let needle = spki
            .to_der()
            .map_err(|e| EstError::tamp(format!("encode SPKI: {e}")))?;
        for (i, e) in self.entries.iter().enumerate() {
            if e.public_key()?.to_der().ok().as_deref() == Some(needle.as_slice()) {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    /// Insert or replace a trust anchor.
    ///
    /// If an anchor with the same key identifier already exists, its anchor
    /// material is replaced but its `last_seq_num` replay counter is preserved
    /// (so a re-add cannot reset anti-replay state).
    pub fn upsert(&mut self, anchor: TrustAnchorChoice, is_apex: bool) -> Result<()> {
        let entry = TrustAnchorStoreEntry::new(anchor, is_apex)?;
        if let Some(existing) = self.entries.iter_mut().find(|e| e.key_id == entry.key_id) {
            existing.anchor = entry.anchor;
            existing.is_apex = is_apex;
        } else {
            self.entries.push(entry);
        }
        Ok(())
    }

    /// Remove a trust anchor identified by its public key. Returns whether one
    /// was removed.
    pub fn remove_by_spki(&mut self, spki: &SubjectPublicKeyInfoOwned) -> Result<bool> {
        match self.find_by_spki(spki)? {
            Some(i) => {
                self.entries.remove(i);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Remove every non-apex trust anchor (used by an apex update that sets
    /// `clearTrustAnchors`).
    pub fn clear_non_apex(&mut self) {
        self.entries.retain(|e| e.is_apex);
    }

    /// Check a TAMP sequence number against the replay counter for `key_id`,
    /// **without** committing it.
    ///
    /// Returns `Ok(())` if `candidate` is acceptable (strictly greater than the
    /// stored value, or no value stored yet). Returns an error on replay. Per
    /// RFC 5934 §5, equal sequence numbers are rejected — only a strictly higher
    /// number is fresh.
    pub fn check_seq_num(&self, key_id: &[u8], candidate: u64) -> Result<()> {
        if let Some(entry) = self.find_by_key_id(key_id)
            && let Some(prev) = entry.last_seq_num
            && candidate <= prev
        {
            return Err(EstError::tamp(format!(
                "TAMP sequence number replay: received {candidate} <= last accepted {prev}"
            )));
        }
        Ok(())
    }

    /// Commit a TAMP sequence number for `key_id` after the message has been
    /// accepted. Checks for replay first; on success, advances the counter.
    pub fn accept_seq_num(&mut self, key_id: &[u8], candidate: u64) -> Result<()> {
        self.check_seq_num(key_id, candidate)?;
        if let Some(entry) = self.entries.iter_mut().find(|e| e.key_id == key_id) {
            entry.last_seq_num = Some(candidate);
        }
        Ok(())
    }

    // ----- Persistence -------------------------------------------------------

    /// Serialize the entire store to canonical DER.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let entries = self
            .entries
            .iter()
            .map(|e| {
                Ok(PersistedEntry {
                    anchor: e.anchor.clone(),
                    key_id: OctetString::new(e.key_id.clone())
                        .map_err(|e| EstError::tamp(format!("encode key id: {e}")))?,
                    last_seq_num: e.last_seq_num,
                    is_apex: e.is_apex,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        PersistedStore { entries }
            .to_der()
            .map_err(|e| EstError::tamp(format!("encode store: {e}")))
    }

    /// Reconstruct a store from DER produced by [`to_der`](Self::to_der).
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let persisted = PersistedStore::from_der(der)
            .map_err(|e| EstError::tamp(format!("decode store: {e}")))?;
        let entries = persisted
            .entries
            .into_iter()
            .map(|p| TrustAnchorStoreEntry {
                anchor: p.anchor,
                key_id: p.key_id.as_bytes().to_vec(),
                last_seq_num: p.last_seq_num,
                is_apex: p.is_apex,
            })
            .collect();
        Ok(Self { entries })
    }
}

/// On-disk representation of [`TrustAnchorStore`] (one entry per trust anchor).
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct PersistedStore {
    entries: Vec<PersistedEntry>,
}

/// On-disk representation of [`TrustAnchorStoreEntry`].
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct PersistedEntry {
    anchor: TrustAnchorChoice,
    key_id: OctetString,
    #[asn1(optional = "true")]
    last_seq_num: Option<u64>,
    #[asn1(default = "default_false")]
    is_apex: bool,
}

fn default_false() -> bool {
    false
}

/// Extract the `SubjectPublicKeyInfo` from any `TrustAnchorChoice` variant.
pub fn spki_of(anchor: &TrustAnchorChoice) -> Result<SubjectPublicKeyInfoOwned> {
    Ok(match anchor {
        TrustAnchorChoice::Certificate(cert) => cert.tbs_certificate().subject_public_key_info().clone(),
        TrustAnchorChoice::TbsCertificate(tbs) => tbs.subject_public_key_info().clone(),
        TrustAnchorChoice::TaInfo(info) => info.pub_key.clone(),
    })
}

/// Derive the key identifier used to track and match a trust anchor.
///
/// Resolution order:
/// 1. For a `taInfo` anchor, its explicit `keyId` field.
/// 2. For a certificate / TBS certificate, the Subject Key Identifier extension
///    value, if present (RFC 5280 §4.2.1.2).
/// 3. Otherwise, the SHA-256 digest of the public key BIT STRING contents
///    (FIPS-routed via [`crate::fips_crypto`]). This is a deterministic fallback
///    so every anchor has a stable identifier even without an SKI extension;
///    a Trust Anchor Manager that references anchors by this id must use the
///    same construction.
pub fn derive_key_id(anchor: &TrustAnchorChoice) -> Result<Vec<u8>> {
    match anchor {
        TrustAnchorChoice::TaInfo(info) => Ok(info.key_id.as_bytes().to_vec()),
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(ski) = subject_key_identifier(cert.tbs_certificate().extensions()) {
                return Ok(ski);
            }
            spki_digest(&spki_of(anchor)?)
        }
        TrustAnchorChoice::TbsCertificate(tbs) => {
            if let Some(ski) = subject_key_identifier(tbs.extensions()) {
                return Ok(ski);
            }
            spki_digest(&spki_of(anchor)?)
        }
    }
}

/// Pull the raw Subject Key Identifier octets from an extension set, if present.
fn subject_key_identifier(exts: Option<&x509_cert::ext::Extensions>) -> Option<Vec<u8>> {
    let exts = exts?;
    let ext = exts.iter().find(|e| e.extn_id == OID_SUBJECT_KEY_IDENTIFIER)?;
    // The extension value is a DER OCTET STRING wrapping the key id octets.
    OctetString::from_der(ext.extn_value.as_bytes())
        .ok()
        .map(|os| os.as_bytes().to_vec())
}

/// SHA-256 of the public key BIT STRING contents (fallback key id).
fn spki_digest(spki: &SubjectPublicKeyInfoOwned) -> Result<Vec<u8>> {
    let key_bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| EstError::tamp("public key BIT STRING is not byte-aligned"))?;
    Ok(fips_crypto::sha256(key_bits).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::BitString;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::anchor::{TrustAnchorInfo, Version};

    fn make_ta_info(key_id: &[u8], title: &str) -> TrustAnchorChoice {
        // A minimal, self-consistent taInfo trust anchor. The public key value is
        // arbitrary test bytes; we only exercise store mechanics, not crypto.
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&[0x04, 0x01, 0x02, 0x03]).unwrap(),
        };
        TrustAnchorChoice::TaInfo(TrustAnchorInfo {
            version: Version::V1,
            pub_key: spki,
            key_id: OctetString::new(key_id.to_vec()).unwrap(),
            ta_title: Some(title.to_string()),
            cert_path: None,
            extensions: None,
            ta_title_lang_tag: None,
        })
    }

    #[test]
    fn upsert_and_lookup() {
        let mut store = TrustAnchorStore::new();
        store
            .upsert(make_ta_info(b"key-1", "Root A"), true)
            .unwrap();
        store
            .upsert(make_ta_info(b"key-2", "Root B"), false)
            .unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.find_by_key_id(b"key-1").unwrap().title().as_deref(), Some("Root A"));
        assert!(store.apex().is_some());
        assert_eq!(store.apex().unwrap().key_id, b"key-1");
    }

    #[test]
    fn upsert_preserves_replay_counter() {
        let mut store = TrustAnchorStore::new();
        store.upsert(make_ta_info(b"k", "A"), false).unwrap();
        store.accept_seq_num(b"k", 5).unwrap();
        // Re-adding the same key id must not reset the counter.
        store.upsert(make_ta_info(b"k", "A-updated"), false).unwrap();
        assert_eq!(store.find_by_key_id(b"k").unwrap().last_seq_num, Some(5));
        assert!(store.check_seq_num(b"k", 5).is_err());
    }

    #[test]
    fn sequence_number_replay_is_rejected() {
        let mut store = TrustAnchorStore::new();
        store.upsert(make_ta_info(b"k", "A"), false).unwrap();
        store.accept_seq_num(b"k", 10).unwrap();
        assert!(store.check_seq_num(b"k", 10).is_err(), "equal seq must be replay");
        assert!(store.check_seq_num(b"k", 9).is_err(), "lower seq must be replay");
        assert!(store.check_seq_num(b"k", 11).is_ok(), "higher seq is fresh");
        store.accept_seq_num(b"k", 11).unwrap();
        assert_eq!(store.find_by_key_id(b"k").unwrap().last_seq_num, Some(11));
    }

    #[test]
    fn clear_non_apex_keeps_apex() {
        let mut store = TrustAnchorStore::new();
        store.upsert(make_ta_info(b"apex", "Apex"), true).unwrap();
        store.upsert(make_ta_info(b"leaf", "Leaf"), false).unwrap();
        store.clear_non_apex();
        assert_eq!(store.len(), 1);
        assert!(store.apex().is_some());
    }

    #[test]
    fn der_round_trip_preserves_everything() {
        let mut store = TrustAnchorStore::new();
        store.upsert(make_ta_info(b"key-1", "Root A"), true).unwrap();
        store.upsert(make_ta_info(b"key-2", "Root B"), false).unwrap();
        store.accept_seq_num(b"key-1", 42).unwrap();

        let der = store.to_der().unwrap();
        let restored = TrustAnchorStore::from_der(&der).unwrap();
        assert_eq!(store, restored);
        assert_eq!(restored.find_by_key_id(b"key-1").unwrap().last_seq_num, Some(42));
        assert!(restored.apex().is_some());
    }

    #[test]
    fn key_id_for_ta_info_uses_explicit_field() {
        let anchor = make_ta_info(b"explicit-id", "X");
        assert_eq!(derive_key_id(&anchor).unwrap(), b"explicit-id");
    }
}
