// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Pull trust anchor information from a TAMP (RFC 5934) server.
//!
//! This example builds a [`TampClient`], seeds it with a pre-provisioned apex
//! trust anchor (the root of the management trust, distributed out of band), and
//! sends a `TAMPStatusQuery` for all modules. The signed `TAMPStatusResponse` is
//! verified against the seeded trust anchor and the resulting trust anchor list
//! is printed.
//!
//! Run with:
//!
//! ```text
//! cargo run --example tamp_status --features tamp -- \
//!     https://ta.example.mil/tamp  apex-trust-anchor.pem
//! ```
//!
//! Requires the `tamp` feature.

use std::error::Error;

use der::DecodePem;
use usg_est_client::tamp::client::trust_anchors_in_response;
use usg_est_client::tamp::{TampClient, TrustAnchorStore};
use usg_est_client::{Certificate, EstClientConfig};
use x509_cert::anchor::TrustAnchorChoice;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let tamp_url = args
        .next()
        .ok_or("usage: tamp_status <tamp-url> <apex-anchor.pem>")?;
    let apex_pem_path = args
        .next()
        .ok_or("usage: tamp_status <tamp-url> <apex-anchor.pem>")?;

    // Seed the store with the apex trust anchor (provisioned out of band).
    let apex_pem = std::fs::read(&apex_pem_path)?;
    let apex = Certificate::from_pem(&apex_pem)?;
    let mut store = TrustAnchorStore::new();
    store.upsert(TrustAnchorChoice::Certificate(apex), true)?;

    // Reuse the EST TLS stack for transport.
    let config = EstClientConfig::builder().server_url(&tamp_url)?.build()?;
    let mut client = TampClient::new(config, &tamp_url, store)?;

    println!("Pulling trust anchor status from {tamp_url} ...");
    let response = client.status_query_all(false).await?;

    let anchors = trust_anchors_in_response(&response);
    println!("Server reports {} trust anchor(s):", anchors.len());
    for (i, ta) in anchors.iter().enumerate() {
        let kind = match ta {
            TrustAnchorChoice::Certificate(_) => "certificate",
            TrustAnchorChoice::TbsCertificate(_) => "tbsCertificate",
            TrustAnchorChoice::TaInfo(info) => {
                if let Some(t) = &info.ta_title {
                    println!("  [{}] taInfo: {t}", i + 1);
                    continue;
                }
                "taInfo"
            }
        };
        println!("  [{}] {kind}", i + 1);
    }

    // The client's store now also contains the pulled anchors.
    println!(
        "\nLocal store now holds {} anchor(s).",
        client.store().len()
    );
    Ok(())
}
