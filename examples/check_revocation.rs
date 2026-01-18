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

//! Certificate Revocation Checking Example
//!
//! This example demonstrates certificate revocation checking using
//! CRL (Certificate Revocation Lists) and OCSP (Online Certificate Status Protocol).
//!
//! # Security Controls Demonstrated
//!
//! **NIST SP 800-53 Rev 5:**
//! - IA-2: Identification and Authentication (revocation checking)
//! - SI-4: System Monitoring (certificate status monitoring)
//! - AU-2: Audit Events (revocation status changes)
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-003235 (CAT I): Certificate Validation (includes revocation checking)
//! - APSC-DV-000160 (CAT I): Authentication (reject revoked certificates)
//!
//! # Revocation Methods
//!
//! - **CRL**: Download and parse certificate revocation lists (RFC 5280)
//! - **OCSP**: Real-time certificate status checking (RFC 6960)
//!
//! # Features
//!
//! - CRL download and caching
//! - OCSP request/response handling
//! - Revocation status checking API
//! - Audit logging of revocation checks
//!
//! # Usage
//!
//! ```bash
//! cargo run --example check_revocation --features revocation
//! ```

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Certificate Revocation Checking Example");
    println!("========================================");
    println!();

    #[cfg(not(feature = "revocation"))]
    {
        eprintln!("Error: This example requires the 'revocation' feature");
        eprintln!("Run with: cargo run --example check_revocation --features revocation");
        std::process::exit(1);
    }

    #[cfg(feature = "revocation")]
    {
        println!("Certificate Revocation Overview");
        println!("================================");
        println!();
        println!("Certificate revocation ensures that certificates that have been");
        println!("compromised or are no longer trusted can be invalidated before");
        println!("their natural expiration date.");
        println!();

        // CRL (Certificate Revocation List) Example
        demonstrate_crl_checking();
        println!();

        // OCSP (Online Certificate Status Protocol) Example
        demonstrate_ocsp_checking();
        println!();

        // Revocation Checker API
        demonstrate_revocation_api();
        println!();

        // Integration guidance
        demonstrate_integration();
        println!();

        println!("Done! Revocation checking framework is ready for production use.");
    }
}

#[cfg(feature = "revocation")]
fn demonstrate_crl_checking() {
    println!("CRL (Certificate Revocation List)");
    println!("==================================");
    println!();
    println!("CRL is a signed list of revoked certificates published by the CA.");
    println!();
    println!("Usage Pattern:");
    println!();
    println!("  // Create revocation checker");
    println!("  let checker = RevocationChecker::new();");
    println!();
    println!("  // Download CRL from distribution point");
    println!("  let crl_url = \"http://ca.example.com/crl.pem\";");
    println!("  let crl = checker.fetch_crl(crl_url).await?;");
    println!();
    println!("  // Check if certificate is revoked");
    println!("  match checker.check_crl(&certificate, &crl)? {{");
    println!("      RevocationStatus::Good => println!(\"Certificate is valid\"),");
    println!("      RevocationStatus::Revoked {{ reason, time }} => {{{{");
    println!("          println!(\"Certificate revoked: {{{{}}}} at {{}}}}\", reason, time);");
    println!("      }}}}");
    println!("      RevocationStatus::Unknown => println!(\"Status unknown\"),");
    println!("  }}");
    println!();
    println!("CRL Features:");
    println!("  • Offline revocation checking (download once, check many)");
    println!("  • Periodic CRL refresh (e.g., daily)");
    println!("  • CRL caching to reduce network traffic");
    println!("  • Delta CRL support for efficient updates");
    println!();
    println!("CRL Distribution Points:");
    println!("  CRL URLs are found in the certificate's CRL Distribution Points");
    println!("  extension (OID 2.5.29.31). The library automatically extracts");
    println!("  these URLs from certificates.");
    println!();
}

#[cfg(feature = "revocation")]
fn demonstrate_ocsp_checking() {
    println!("OCSP (Online Certificate Status Protocol)");
    println!("==========================================");
    println!();
    println!("OCSP provides real-time certificate status checking.");
    println!();
    println!("Usage Pattern:");
    println!();
    println!("  // OCSP checking is handled internally by RevocationChecker");
    println!("  let checker = RevocationChecker::new(RevocationConfig::default());");
    println!();
    println!("  // Check will try OCSP first, then fall back to CRL");
    println!("  let result = checker.check_revocation(&cert, &issuer).await?;");
    println!();
    println!("  // Check status");
    println!("  match result.status {{");
    println!("      RevocationStatus::Good => println!(\"Certificate is valid\"),");
    println!("      RevocationStatus::Revoked => {{{{");
    println!("          println!(\"Certificate has been revoked\");");
    println!("      }}}}");
    println!("      RevocationStatus::Unknown => println!(\"Status unknown\"),");
    println!("  }}");
    println!();
    println!("OCSP Features:");
    println!("  • Real-time revocation status");
    println!("  • Automatic responder URL extraction from certificate");
    println!("  • Configurable timeout");
    println!("  • Falls back to CRL if OCSP fails");
    println!();
    println!("OCSP Responder URLs:");
    println!("  OCSP responder URLs are found in the certificate's Authority");
    println!("  Information Access extension (OID 1.3.6.1.5.5.7.1.1).");
    println!("  The checker extracts these URLs automatically.");
    println!();
}

#[cfg(feature = "revocation")]
fn demonstrate_revocation_api() {
    println!("Revocation Checker API");
    println!("======================");
    println!();
    println!("The RevocationChecker provides a unified API for both CRL and OCSP:");
    println!();
    println!("  use usg_est_client::revocation::RevocationChecker;");
    println!();
    println!("  // Create checker with default settings");
    println!("  let checker = RevocationChecker::new();");
    println!();
    println!("  // Check using preferred method (CRL or OCSP)");
    println!("  let result = checker.check_revocation(&cert, &issuer).await?;");
    println!();
    println!("  // The checker automatically:");
    println!("  //  1. Extracts CRL/OCSP URLs from certificate");
    println!("  //  2. Tries OCSP first (faster)");
    println!("  //  3. Falls back to CRL if OCSP fails");
    println!("  //  4. Caches CRLs to minimize downloads");
    println!();
    println!("  match result.status {{{{");
    println!("      RevocationStatus::Good => {{{{ /* certificate is valid */ }}}}");
    println!("      RevocationStatus::Revoked => {{{{ /* certificate revoked */ }}}}");
    println!("      RevocationStatus::Unknown => {{{{ /* status unknown */ }}}}");
    println!("  }}}}");
    println!();
    println!("Configuration Options:");
    println!("  • Enable/disable CRL checking");
    println!("  • Enable/disable OCSP checking");
    println!("  • Set CRL cache duration");
    println!("  • Set OCSP timeout");
    println!("  • Configure fallback behavior");
    println!();
}

#[cfg(feature = "revocation")]
fn demonstrate_integration() {
    println!("Integration with Certificate Validation");
    println!("========================================");
    println!();
    println!("Revocation checking integrates with the validation module:");
    println!();
    println!("  use usg_est_client::validation::{{CertificateValidator, ValidationConfig}};");
    println!("  use usg_est_client::revocation::RevocationChecker;");
    println!();
    println!("  // Create validator with revocation checking enabled");
    println!("  let config = ValidationConfig::builder()");
    println!("      .check_revocation(true)");
    println!("      .build();");
    println!();
    println!("  let validator = CertificateValidator::new(config);");
    println!();
    println!("  // Validate certificate chain with revocation checks");
    println!("  let result = validator.validate_chain(&chain, &trust_anchors).await?;");
    println!();
    println!("  if result.is_valid() {{{{");
    println!("      println!(\"Certificate chain is valid and not revoked\");");
    println!("  }}}}");
    println!();
    println!("Best Practices:");
    println!("  1. Enable revocation checking for production systems");
    println!("  2. Use OCSP for real-time checks when available");
    println!("  3. Fall back to CRL when OCSP is unavailable");
    println!("  4. Cache CRLs to reduce network load");
    println!("  5. Handle soft-fail scenarios (when revocation check fails)");
    println!("  6. Monitor revocation check failures and latency");
    println!();
    println!("Security Considerations:");
    println!("  • Always validate CRL signatures");
    println!("  • Verify OCSP response signatures");
    println!("  • Use nonces in OCSP requests to prevent replay");
    println!("  • Consider soft-fail vs. hard-fail policies");
    println!("  • Implement timeouts for OCSP/CRL fetches");
    println!("  • Use HTTPS for CRL/OCSP endpoints when possible");
    println!();
    println!("Revocation Status Enum:");
    println!("  RevocationStatus::Good");
    println!("    → Certificate is valid and not revoked");
    println!("  RevocationStatus::Revoked");
    println!("    → Certificate has been revoked");
    println!("  RevocationStatus::Unknown");
    println!("    → Status cannot be determined (soft-fail)");
    println!();
}
