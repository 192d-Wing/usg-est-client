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
