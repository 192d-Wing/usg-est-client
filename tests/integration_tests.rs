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

//! Integration tests for usg-est-client
//!
//! These tests use wiremock to create mock EST servers and test
//! all operations, authentication methods, and error handling.
//!
//! # Security Controls Tested
//!
//! **NIST SP 800-53 Rev 5:**
//! - SC-8: Transmission Confidentiality (TLS configuration tests)
//! - IA-2: Identification and Authentication (auth method tests)
//! - SC-13: Cryptographic Protection (algorithm validation tests)
//! - SI-10: Information Input Validation (error handling tests)
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000160 (CAT I): Authentication (mutual TLS, HTTP Basic)
//! - APSC-DV-000170 (CAT I): FIPS-validated cryptography
//! - APSC-DV-000500 (CAT I): Input validation (certificate parsing)
//! - APSC-DV-003235 (CAT I): Certificate validation (chain validation tests)
//!
//! # Test Coverage Areas
//!
//! - **Operations**: All EST protocol operations (/cacerts, /simpleenroll, etc.)
//! - **Authentication**: Client cert auth, HTTP Basic auth, channel binding
//! - **TLS**: TLS version enforcement, cipher suite validation
//! - **Errors**: Error handling, validation failures, timeout handling
//! - **Metrics**: Operation tracking and performance metrics (if enabled)
//! - **Platform**: Windows service integration, SIEM integration (if enabled)

mod integration;

#[path = "integration/operations/mod.rs"]
mod operations;

#[path = "integration/auth/mod.rs"]
mod auth;

#[path = "integration/tls/mod.rs"]
mod tls;

#[path = "integration/errors/mod.rs"]
mod errors;

#[cfg(feature = "metrics")]
#[path = "integration/metrics_test.rs"]
mod metrics_test;

#[cfg(all(windows, feature = "windows-service"))]
mod windows;

#[cfg(feature = "siem")]
mod siem;
