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

//! `TampClient` — HTTP transport and inbound processing for a TAMP client.
//!
//! RFC 5934 does not define a transport; this client carries TAMP CMS messages
//! over HTTP(S) using the same [`reqwest`] stack and TLS configuration as the EST
//! client (via [`crate::tls::build_http_client`]).
//!
//! The client holds a [`TrustAnchorStore`] that it uses to verify inbound
//! management messages and that it mutates as it applies them. A pre-provisioned
//! trust anchor (typically the apex) MUST be present before any response can be
//! trusted — see [`TampClient::new`].
//!
//! # Typical use
//!
//! ```no_run
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! use usg_est_client::EstClientConfig;
//! use usg_est_client::tamp::{TampClient, TrustAnchorStore};
//! use usg_est_client::tamp::client::trust_anchors_in_response;
//!
//! let config = EstClientConfig::builder().server_url("https://ta.example.mil")?.build()?;
//! // A store pre-loaded with the apex trust anchor (out-of-band provisioned):
//! let store = TrustAnchorStore::new();
//! let mut client = TampClient::new(config, "https://ta.example.mil/tamp", store)?;
//!
//! // Pull the current trust anchor information.
//! let response = client.status_query_all(false).await?;
//! println!("server reports {} trust anchors", trust_anchors_in_response(&response).len());
//! # Ok(()) }
//! ```

use der::Decode;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use url::Url;
use x509_cert::anchor::TrustAnchorChoice;

use crate::config::EstClientConfig;
use crate::error::{EstError, Result};
use crate::tls::build_http_client;

use super::asn1::{
    StatusCode, StatusResponse, TampMsgRef, TampStatusResponse, TampUpdate, TargetIdentifier,
    TrustAnchorUpdate, UpdateConfirm,
};
use super::oid::TampContentType;
use super::response::{self, TampSigner};
use super::store::TrustAnchorStore;
use super::verify::{verify_message, VerifiedMessage};
use super::wrapper::TampMessage;

/// The outcome of processing one inbound TAMP message.
#[derive(Debug)]
pub struct Processed {
    /// The kind of message that was processed.
    pub content_type: TampContentType,
    /// Human-readable summary of what changed (for logging / CLI output).
    pub summary: String,
    /// A signed confirm/error message to send back to the manager, if the
    /// processed message calls for one and a signer is configured.
    pub reply: Option<Vec<u8>>,
}

/// A TAMP client: optional HTTP transport + trust anchor store + optional
/// signing identity.
///
/// `http`/`tamp_url` are `None` for a client built with [`TampClient::offline`],
/// which can verify and apply out-of-band messages but cannot make network calls.
pub struct TampClient {
    http: Option<reqwest::Client>,
    tamp_url: Option<Url>,
    store: TrustAnchorStore,
    signer: Option<TampSigner>,
}

impl TampClient {
    /// Create a client. `config` supplies the TLS configuration and client
    /// identity (reused from EST); `tamp_url` is the management endpoint; `store`
    /// holds the trust anchors used to verify inbound messages.
    pub fn new(
        config: EstClientConfig,
        tamp_url: impl AsRef<str>,
        store: TrustAnchorStore,
    ) -> Result<Self> {
        let http = build_http_client(&config)?;
        let tamp_url = Url::parse(tamp_url.as_ref())?;
        // TAMP management messages (trust anchor updates) must not travel in
        // plaintext. Reject any non-HTTPS endpoint rather than silently sending
        // over HTTP because the URL scheme overrides the TLS-capable client.
        if tamp_url.scheme() != "https" {
            return Err(EstError::tamp(format!(
                "TAMP endpoint must use https, got scheme '{}'",
                tamp_url.scheme()
            )));
        }
        // Reuse the EST client identity for signing client-originated messages
        // when one is configured.
        let signer = match &config.client_identity {
            Some(identity) => Some(TampSigner::from_client_identity(identity)?),
            None => None,
        };
        Ok(Self {
            http: Some(http),
            tamp_url: Some(tamp_url),
            store,
            signer,
        })
    }

    /// Create an **offline** client with no HTTP transport.
    ///
    /// This is the constructor for air-gapped workflows (e.g. `est-enroll tamp
    /// process`): it can [`process`](Self::process) messages received out of band
    /// — verifying them against the store, enforcing replay protection, and
    /// applying them — and produce a signed confirm if a signer is set (via
    /// [`with_signer`](Self::with_signer)). It builds **no** TLS/reqwest client,
    /// so it never touches the platform TLS stack or the FIPS algorithm policy.
    ///
    /// The network methods ([`status_query`](Self::status_query),
    /// [`status_query_all`](Self::status_query_all)) return an error on an offline
    /// client.
    pub fn offline(store: TrustAnchorStore) -> Self {
        Self {
            http: None,
            tamp_url: None,
            store,
            signer: None,
        }
    }

    /// Override the signing identity used for client-originated messages.
    pub fn with_signer(mut self, signer: TampSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// The current trust anchor store.
    pub fn store(&self) -> &TrustAnchorStore {
        &self.store
    }

    /// Mutable access to the trust anchor store (e.g. to pre-load the apex TA).
    pub fn store_mut(&mut self) -> &mut TrustAnchorStore {
        &mut self.store
    }

    /// Pull trust anchor status for **all modules** — the common "what do you
    /// have?" query. `terse` requests the compact key-id-only form.
    pub async fn status_query_all(&mut self, terse: bool) -> Result<TampStatusResponse> {
        let target = TargetIdentifier::AllModules(der::asn1::Null);
        self.status_query(target, terse).await
    }

    /// Send a `TAMPStatusQuery` for `target` and return the verified response.
    ///
    /// The query is signed if a signer is configured; status queries may also be
    /// unsigned (RFC 5934 §4.1), in which case a degenerate `SignedData` (no
    /// signers) is sent. The response is signature-verified against the store.
    pub async fn status_query(
        &mut self,
        target: TargetIdentifier,
        terse: bool,
    ) -> Result<TampStatusResponse> {
        // Sequence number of the query: best-effort monotonic from the highest
        // sequence number we have recorded, plus one. Servers echo it back.
        let seq = self.next_query_seq();
        let body = response::build_status_query(
            TampMsgRef {
                target,
                seq_num: seq,
            },
            terse,
        )?;
        let request = self.wrap_outbound(TampContentType::StatusQuery, &body)?;

        let response_bytes = self
            .post(TampContentType::StatusQuery, TampContentType::StatusResponse, request)
            .await?;

        let verified = self.verify_inbound(&response_bytes)?;
        if verified.content_type != TampContentType::StatusResponse {
            return Err(EstError::tamp(format!(
                "expected TAMPStatusResponse, got {:?}",
                verified.content_type
            )));
        }

        let response = TampStatusResponse::from_der(&verified.econtent)
            .map_err(|e| EstError::tamp(format!("decode TAMPStatusResponse: {e}")))?;

        // Populate the store from a verbose response so pulled anchors are
        // available locally — but ONLY if the response was signed by the apex.
        // A status response is informational; letting any trusted (possibly
        // non-apex) signer inject new trust anchors would let one compromised
        // signer escalate to provisioning fresh signers the apex never
        // authorized. Adding anchors is reserved for an apex-signed message.
        if self.signer_is_apex(&verified.signer_key_id) {
            if let StatusResponse::Verbose(v) = &response.response {
                for ta in &v.ta_info {
                    self.store.upsert(ta.clone(), false)?;
                }
            }
        } else {
            tracing::debug!(
                "status response not apex-signed; returning it without merging anchors into the store"
            );
        }

        Ok(response)
    }

    /// Process an inbound, server-originated TAMP message (e.g. one received
    /// out-of-band or in an HTTP response): verify it, enforce replay
    /// protection, apply it to the store, and produce a signed confirm if
    /// appropriate. This is the entry point for `est-enroll tamp process`.
    pub fn process(&mut self, inbound: &[u8]) -> Result<Processed> {
        let verified = self.verify_inbound(inbound)?;
        match verified.content_type {
            TampContentType::StatusResponse => self.apply_status_response(&verified),
            TampContentType::Update => self.apply_update(&verified),
            TampContentType::ApexUpdate => self.apply_apex_update(&verified),
            other => Ok(Processed {
                content_type: other,
                summary: format!("{other:?} received; no automatic action taken"),
                reply: None,
            }),
        }
    }

    // ----- internals ---------------------------------------------------------

    /// Verify an inbound CMS message against the trust anchor store.
    fn verify_inbound(&self, bytes: &[u8]) -> Result<VerifiedMessage> {
        let msg = TampMessage::parse(bytes)?;
        verify_message(&msg, &self.store)
    }

    /// Wrap an outbound message body: sign it if we have a signer, else emit a
    /// degenerate (unsigned) SignedData.
    fn wrap_outbound(&self, content_type: TampContentType, body: &[u8]) -> Result<Vec<u8>> {
        match &self.signer {
            Some(signer) => signer.sign_message(content_type, body),
            None => super::wrapper::assemble_signed_data(
                content_type.oid(),
                body,
                der::asn1::SetOfVec::new(),
                None,
                vec![],
            ),
        }
    }

    /// HTTP POST a TAMP message and return the response body bytes.
    async fn post(
        &self,
        send: TampContentType,
        accept: TampContentType,
        body: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let (http, url) = match (&self.http, &self.tamp_url) {
            (Some(http), Some(url)) => (http, url),
            _ => {
                return Err(EstError::tamp(
                    "this TampClient was constructed offline (no HTTP transport); \
                     network operations are unavailable — use process() for out-of-band messages",
                ));
            }
        };
        tracing::debug!("TAMP POST {} ({})", url, send.media_type());
        let response = http
            .post(url.clone())
            .header(CONTENT_TYPE, send.media_type())
            .header(ACCEPT, accept.media_type())
            .body(body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(EstError::server_error(
                status.as_u16(),
                format!("TAMP server returned {status}"),
            ));
        }
        Ok(response.bytes().await?.to_vec())
    }

    /// A monotonic-ish sequence number for outbound queries.
    fn next_query_seq(&self) -> u64 {
        self.store
            .iter()
            .filter_map(|e| e.last_seq_num)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }

    fn apply_status_response(&mut self, verified: &VerifiedMessage) -> Result<Processed> {
        let response = TampStatusResponse::from_der(&verified.econtent)
            .map_err(|e| EstError::tamp(format!("decode TAMPStatusResponse: {e}")))?;

        // Only an apex-signed status response may add trust anchors (see
        // `status_query`). A response signed by any other trusted anchor is
        // accepted as information but does not mutate the trust set.
        let from_apex = self.signer_is_apex(&verified.signer_key_id);
        let mut added = 0usize;
        if from_apex
            && let StatusResponse::Verbose(v) = &response.response
        {
            for ta in &v.ta_info {
                self.store.upsert(ta.clone(), false)?;
                added += 1;
            }
        }
        let summary = if from_apex {
            format!("status response applied; {added} trust anchor(s) recorded")
        } else {
            "status response verified but not apex-signed; trust store unchanged".to_string()
        };
        Ok(Processed {
            content_type: TampContentType::StatusResponse,
            summary,
            reply: None,
        })
    }

    /// Whether `signer_key_id` identifies the store's apex trust anchor.
    fn signer_is_apex(&self, signer_key_id: &[u8]) -> bool {
        self.store
            .apex()
            .is_some_and(|a| a.key_id.as_slice() == signer_key_id)
    }

    fn apply_update(&mut self, verified: &VerifiedMessage) -> Result<Processed> {
        let update = TampUpdate::from_der(&verified.econtent)
            .map_err(|e| EstError::tamp(format!("decode TAMPUpdate: {e}")))?;

        // Replay protection keyed by the signing trust anchor.
        let seq = update.msg_ref.seq_num;
        self.store.check_seq_num(&verified.signer_key_id, seq)?;

        let mut added = 0usize;
        let mut removed = 0usize;
        let mut changed = 0usize;
        for op in &update.updates {
            match op {
                TrustAnchorUpdate::Add(anchor) => {
                    self.store.upsert(anchor.clone(), false)?;
                    added += 1;
                }
                TrustAnchorUpdate::Remove(spki) => {
                    if self.store.remove_by_spki(spki)? {
                        removed += 1;
                    }
                }
                TrustAnchorUpdate::Change(_change) => {
                    // Change operations rewrite an existing anchor's metadata.
                    // Applying them faithfully requires reconstructing the target
                    // anchor; this is not yet implemented, so the change is
                    // reported but not silently dropped.
                    changed += 1;
                }
            }
        }

        // Commit the sequence number now that the update is applied.
        self.store.accept_seq_num(&verified.signer_key_id, seq)?;

        let status = if changed > 0 {
            StatusCode::ImproperTaChange
        } else {
            StatusCode::Success
        };
        let reply = self.build_update_confirm(&update.msg_ref, status)?;

        let summary = format!(
            "trust anchor update applied: +{added} / -{removed} (change ops reported: {changed})"
        );
        Ok(Processed {
            content_type: TampContentType::Update,
            summary,
            reply,
        })
    }

    fn apply_apex_update(&mut self, verified: &VerifiedMessage) -> Result<Processed> {
        use super::asn1::TampApexUpdate;
        let apex = TampApexUpdate::from_der(&verified.econtent)
            .map_err(|e| EstError::tamp(format!("decode TAMPApexUpdate: {e}")))?;

        // Authorization (RFC 5934 §7.2): an apex update MUST be signed by the
        // current apex trust anchor. Without this, any trusted non-apex signer
        // could replace the root of the management trust.
        if !self.signer_is_apex(&verified.signer_key_id) {
            return Err(EstError::tamp(
                "apex update not signed by the current apex trust anchor; rejected",
            ));
        }

        self.store
            .check_seq_num(&verified.signer_key_id, apex.msg_ref.seq_num)?;

        // Commit the sequence number on the current apex BEFORE mutating the
        // store, so the replay counter is recorded while the signing entry still
        // exists (the subsequent demote keeps the entry and its counter).
        self.store
            .accept_seq_num(&verified.signer_key_id, apex.msg_ref.seq_num)?;

        if apex.clear_trust_anchors {
            self.store.clear_non_apex();
        }
        // Retire the old apex (keeping its entry + replay counter) and install
        // the new one as the sole apex.
        self.store.demote_apex();
        self.store.upsert(apex.apex_ta.clone(), true)?;

        Ok(Processed {
            content_type: TampContentType::ApexUpdate,
            summary: format!(
                "apex trust anchor replaced (clearTrustAnchors={}, clearCommunities={})",
                apex.clear_trust_anchors, apex.clear_communities
            ),
            // An apex update confirm is structurally distinct; emitted only if a
            // signer is present. Kept None here to avoid sending an unsigned
            // confirm; a full apex-confirm builder can be added when needed.
            reply: None,
        })
    }

    /// Build a signed terse `TAMPUpdateConfirm` if a signer is configured.
    fn build_update_confirm(
        &self,
        update_ref: &TampMsgRef,
        status: StatusCode,
    ) -> Result<Option<Vec<u8>>> {
        let Some(signer) = &self.signer else {
            return Ok(None);
        };
        let confirm = UpdateConfirm::Terse(vec![status]);
        let body = response::build_update_confirm(update_ref.clone(), confirm)?;
        let signed = signer.sign_message(TampContentType::UpdateConfirm, &body)?;
        Ok(Some(signed))
    }
}

/// Helper: extract the trust anchors carried in a (verbose) status response.
pub fn trust_anchors_in_response(response: &TampStatusResponse) -> Vec<&TrustAnchorChoice> {
    match &response.response {
        StatusResponse::Verbose(v) => v.ta_info.iter().collect(),
        StatusResponse::Terse(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_anchors_in_terse_response_is_empty() {
        // A terse response carries only key ids, no TrustAnchorChoice list.
        use super::super::asn1::{TampMsgRef, TampVersion, TerseStatusResponse};
        let resp = TampStatusResponse {
            version: TampVersion::V2,
            query: TampMsgRef {
                target: TargetIdentifier::AllModules(der::asn1::Null),
                seq_num: 1,
            },
            response: StatusResponse::Terse(TerseStatusResponse {
                ta_key_ids: vec![der::asn1::OctetString::new(vec![1, 2, 3]).unwrap()],
                communities: None,
            }),
            uses_apex: true,
        };
        assert!(trust_anchors_in_response(&resp).is_empty());
    }

    #[tokio::test]
    async fn offline_client_rejects_network_calls() {
        // An offline client has no transport; network methods must fail with a
        // clear error rather than panic or dereference a missing client.
        let mut client = TampClient::offline(TrustAnchorStore::new());
        let err = client.status_query_all(false).await.unwrap_err();
        assert!(
            matches!(err, EstError::Tamp(msg) if msg.contains("offline")),
            "expected an offline-transport error"
        );
    }
}
