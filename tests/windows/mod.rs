// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Windows-specific integration tests

#![cfg(windows)]

mod cng_tests;
mod enrollment_cng_tests;

/// Seconds since the Unix epoch, used to build unique key labels in tests.
#[cfg(feature = "windows-service")]
pub(crate) fn unique_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
