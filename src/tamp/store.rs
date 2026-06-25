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
            // Same key id must mean the same public key. Refuse to swap an
            // anchor's key out from under its key id — otherwise a crafted keyId
            // (taInfo) or an SKI collision could silently replace a trusted
            // anchor's key while inheriting its replay counter.
            if spki_of(&existing.anchor)?.to_der().map_err(spki_err)?
                != spki_of(&entry.anchor)?.to_der().map_err(spki_err)?
            {
                return Err(EstError::tamp(
                    "trust anchor key-id collision: an existing anchor shares this key \
                     identifier but has a different public key; refusing to replace it",
                ));
            }
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

    /// Demote any current apex anchor to a regular (non-apex) anchor, keeping its
    /// entry and replay counter. Used when an apex update installs a new apex: the
    /// old apex retains its committed sequence number (so its messages can't be
    /// replayed) but no longer holds apex authority.
    pub fn demote_apex(&mut self) {
        for e in self.entries.iter_mut().filter(|e| e.is_apex) {
            e.is_apex = false;
        }
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
    ///
    /// The persisted `key_id` is **not** trusted: it is re-derived from each
    /// anchor and the stored value must match. This prevents a tampered store
    /// file from binding an attacker-chosen key id (e.g. the apex's, or one with
    /// a low replay counter) to a public key it does not belong to. Duplicate key
    /// ids are also rejected so lookups are unambiguous.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let persisted = PersistedStore::from_der(der)
            .map_err(|e| EstError::tamp(format!("decode store: {e}")))?;
        let mut entries: Vec<TrustAnchorStoreEntry> = Vec::with_capacity(persisted.entries.len());
        for p in persisted.entries {
            let stored_key_id = p.key_id.as_bytes().to_vec();
            let derived = derive_key_id(&p.anchor)?;
            if derived != stored_key_id {
                return Err(EstError::tamp(
                    "persisted trust anchor key id does not match the anchor; \
                     store file is corrupt or tampered",
                ));
            }
            if entries.iter().any(|e| e.key_id == stored_key_id) {
                return Err(EstError::tamp(
                    "persisted trust anchor store contains a duplicate key id",
                ));
            }
            entries.push(TrustAnchorStoreEntry {
                anchor: p.anchor,
                key_id: stored_key_id,
                last_seq_num: p.last_seq_num,
                is_apex: p.is_apex,
            });
        }
        Ok(Self { entries })
    }
}

/// Error mapper for SPKI DER-encoding failures.
fn spki_err(e: der::Error) -> EstError {
    EstError::tamp(format!("encode SPKI: {e}"))
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

/// Minimum acceptable key-identifier length. An identifier shorter than this is
/// treated as absent and replaced by the SHA-256 SPKI-digest fallback, so an
/// empty or trivially short `keyId`/SKI cannot collapse distinct anchors onto a
/// colliding identifier.
const MIN_KEY_ID_LEN: usize = 8;

/// Derive the key identifier used to track and match a trust anchor.
///
/// Resolution order:
/// 1. For a `taInfo` anchor, its explicit `keyId` field (if at least
///    [`MIN_KEY_ID_LEN`] bytes).
/// 2. For a certificate / TBS certificate, the Subject Key Identifier extension
///    value, if present and long enough (RFC 5280 §4.2.1.2).
/// 3. Otherwise, the SHA-256 digest of the public key BIT STRING contents
///    (FIPS-routed via [`crate::fips_crypto`]). This is a deterministic fallback
///    so every anchor has a stable, collision-resistant identifier even without
///    a usable SKI; a Trust Anchor Manager that references anchors by this id
///    must use the same construction.
pub fn derive_key_id(anchor: &TrustAnchorChoice) -> Result<Vec<u8>> {
    match anchor {
        TrustAnchorChoice::TaInfo(info) => {
            let explicit = info.key_id.as_bytes();
            if explicit.len() >= MIN_KEY_ID_LEN {
                Ok(explicit.to_vec())
            } else {
                spki_digest(&spki_of(anchor)?)
            }
        }
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(ski) = subject_key_identifier(cert.tbs_certificate().extensions())
                && ski.len() >= MIN_KEY_ID_LEN
            {
                return Ok(ski);
            }
            spki_digest(&spki_of(anchor)?)
        }
        TrustAnchorChoice::TbsCertificate(tbs) => {
            if let Some(ski) = subject_key_identifier(tbs.extensions())
                && ski.len() >= MIN_KEY_ID_LEN
            {
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
        // A minimal, self-consistent taInfo trust anchor. The public key is
        // derived from the key_id so distinct anchors have distinct SPKIs (the
        // store now rejects same-key-id/different-key collisions); the bytes are
        // arbitrary — we exercise store mechanics, not crypto.
        let mut key_bytes = vec![0x04];
        key_bytes.extend_from_slice(key_id);
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&key_bytes).unwrap(),
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
            .upsert(make_ta_info(b"key-1aaa", "Root A"), true)
            .unwrap();
        store
            .upsert(make_ta_info(b"key-2bbb", "Root B"), false)
            .unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.find_by_key_id(b"key-1aaa").unwrap().title().as_deref(), Some("Root A"));
        assert!(store.apex().is_some());
        assert_eq!(store.apex().unwrap().key_id, b"key-1aaa");
    }

    #[test]
    fn upsert_preserves_replay_counter() {
        let mut store = TrustAnchorStore::new();
        store.upsert(make_ta_info(b"key-aaaa", "A"), false).unwrap();
        store.accept_seq_num(b"key-aaaa", 5).unwrap();
        // Re-adding the same key id (same key) must not reset the counter.
        store.upsert(make_ta_info(b"key-aaaa", "A-updated"), false).unwrap();
        assert_eq!(store.find_by_key_id(b"key-aaaa").unwrap().last_seq_num, Some(5));
        assert!(store.check_seq_num(b"key-aaaa", 5).is_err());
    }

    #[test]
    fn upsert_rejects_key_id_collision_with_different_key() {
        // Two distinct taInfo anchors that share an (explicit) key id but carry
        // different public keys must not silently overwrite each other.
        let mut store = TrustAnchorStore::new();
        store.upsert(make_ta_info(b"shared-id-1", "A"), false).unwrap();
        let colliding = match make_ta_info(b"shared-id-1", "B") {
            TrustAnchorChoice::TaInfo(mut info) => {
                // Force a different public key under the same key id.
                info.pub_key.subject_public_key =
                    BitString::from_bytes(&[0x04, 0xff, 0xfe, 0xfd]).unwrap();
                TrustAnchorChoice::TaInfo(info)
            }
            other => other,
        };
        assert!(store.upsert(colliding, false).is_err());
    }

    #[test]
    fn sequence_number_replay_is_rejected() {
        let mut store = TrustAnchorStore::new();
        store.upsert(make_ta_info(b"key-aaaa", "A"), false).unwrap();
        store.accept_seq_num(b"key-aaaa", 10).unwrap();
        assert!(store.check_seq_num(b"key-aaaa", 10).is_err(), "equal seq must be replay");
        assert!(store.check_seq_num(b"key-aaaa", 9).is_err(), "lower seq must be replay");
        assert!(store.check_seq_num(b"key-aaaa", 11).is_ok(), "higher seq is fresh");
        store.accept_seq_num(b"key-aaaa", 11).unwrap();
        assert_eq!(store.find_by_key_id(b"key-aaaa").unwrap().last_seq_num, Some(11));
    }

    #[test]
    fn clear_non_apex_keeps_apex() {
        let mut store = TrustAnchorStore::new();
        store.upsert(make_ta_info(b"apex-aaaa", "Apex"), true).unwrap();
        store.upsert(make_ta_info(b"leaf-bbbb", "Leaf"), false).unwrap();
        store.clear_non_apex();
        assert_eq!(store.len(), 1);
        assert!(store.apex().is_some());
    }

    #[test]
    fn der_round_trip_preserves_everything() {
        let mut store = TrustAnchorStore::new();
        store.upsert(make_ta_info(b"key-1aaa", "Root A"), true).unwrap();
        store.upsert(make_ta_info(b"key-2bbb", "Root B"), false).unwrap();
        store.accept_seq_num(b"key-1aaa", 42).unwrap();

        let der = store.to_der().unwrap();
        let restored = TrustAnchorStore::from_der(&der).unwrap();
        assert_eq!(store, restored);
        assert_eq!(restored.find_by_key_id(b"key-1aaa").unwrap().last_seq_num, Some(42));
        assert!(restored.apex().is_some());
    }

    #[test]
    fn from_der_rejects_key_id_mismatch() {
        // A store whose persisted key_id does not match its anchor must be
        // rejected (tamper / corruption guard).
        let mut store = TrustAnchorStore::new();
        store.upsert(make_ta_info(b"key-1aaa", "Root A"), true).unwrap();
        let der = store.to_der().unwrap();
        // Decode, corrupt the key_id, re-encode, and confirm from_der rejects it.
        let mut persisted = PersistedStore::from_der(&der).unwrap();
        persisted.entries[0].key_id = OctetString::new(b"forged-key-id".to_vec()).unwrap();
        let tampered = persisted.to_der().unwrap();
        assert!(TrustAnchorStore::from_der(&tampered).is_err());
    }

    #[test]
    fn key_id_for_ta_info_uses_explicit_field() {
        let anchor = make_ta_info(b"explicit-id", "X");
        assert_eq!(derive_key_id(&anchor).unwrap(), b"explicit-id");
    }

    #[test]
    fn short_ta_info_key_id_falls_back_to_spki_digest() {
        // A too-short explicit keyId is replaced by the 32-byte SPKI digest.
        let anchor = make_ta_info(b"short", "X");
        let kid = derive_key_id(&anchor).unwrap();
        assert_eq!(kid.len(), 32, "fallback must be a SHA-256 digest");
    }
}
