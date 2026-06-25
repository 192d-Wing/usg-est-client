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

//! Trust Anchor Management Protocol (TAMP) client — RFC 5934.
//!
//! TAMP is a CMS-based protocol for managing the set of trust anchors held by a
//! device or application. This module implements the **client (managed entity)**
//! role only: it can
//!
//! - build and send a [`TAMPStatusQuery`](asn1::TampStatusQuery) and parse the
//!   returned [`TAMPStatusResponse`](asn1::TampStatusResponse) to *pull the current
//!   trust anchor information* from a Trust Anchor Manager (the primary use case);
//! - receive, signature-verify, and apply Trust Anchor Update / Apex Update /
//!   Community Update / Sequence Number Adjust messages against a local
//!   [`store`]; and
//! - emit the corresponding client-originated, signed `*Confirm` and `TAMPError`
//!   messages.
//!
//! It does **not** implement the Trust Anchor Manager (server) role.
//!
//! # Transport
//!
//! RFC 5934 is transport-agnostic. This client carries TAMP CMS blobs over
//! HTTP(S) using the same [`reqwest`] stack and TLS configuration as the EST
//! client (see [`crate::tls::build_http_client`]). See [`client::TampClient`].
//!
//! # Trust Anchor Format
//!
//! Trust anchors themselves use the RFC 5914 `TrustAnchorChoice` type, which is
//! provided by the [`x509_cert::anchor`] module and re-exported here as
//! [`TrustAnchorChoice`].
//!
//! # FIPS
//!
//! When the crate is built with the `fips` feature, the `tamp` feature is enabled
//! automatically and all TAMP signature verification and message-signing routes
//! through the FIPS-validated provider (see [`crate::fips_crypto`]). TAMP is the
//! mechanism by which a FIPS deployment's roots of trust are managed, so the two
//! are coupled by design.
//!
//! # Security model (summary)
//!
//! Per RFC 5934 §5, a received management message is honored only if:
//! 1. its CMS `SignedData` signature verifies against a trust anchor that is
//!    authorized (via its `CMSContentConstraints`/usage) to sign that message
//!    type — see [`verify`]; and
//! 2. its sequence number is strictly greater than the last accepted sequence
//!    number for the signing trust anchor — replay protection, see [`store`].

pub mod asn1;
pub mod client;
pub mod oid;
pub mod response;
pub mod store;
pub mod verify;
pub mod wrapper;

#[doc(inline)]
pub use oid::TampContentType;

#[doc(inline)]
pub use client::TampClient;

#[doc(inline)]
pub use response::TampSigner;

#[doc(inline)]
pub use store::{TrustAnchorStore, TrustAnchorStoreEntry};

/// RFC 5914 `TrustAnchorChoice`, re-exported from `x509-cert`.
///
/// This is the unit of trust anchor information carried in TAMP status responses
/// and updates.
pub use x509_cert::anchor::{CertPathControls, TrustAnchorChoice, TrustAnchorInfo};
