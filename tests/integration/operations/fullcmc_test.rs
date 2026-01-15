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

//! Integration tests for POST /fullcmc operation

use crate::integration::MockEstServer;
use usg_est_client::{
    CmcRequest, EstClient, EstClientConfig,
    types::cmc_full::{PkiDataBuilder, PkiResponse},
};
#[cfg(feature = "csr-gen")]
use usg_est_client::csr::CsrBuilder;

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_basic_cmc_request_response() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Create a simple PKIResponse for mocking
    let pki_response = PkiResponse::new();
    let pki_response_der = pki_response.to_der().unwrap_or_else(|_| vec![0x30, 0x00]);

    // Base64 encode the response
    use base64::prelude::*;
    let cmc_response_base64 = BASE64_STANDARD.encode(&pki_response_der);
    mock.mock_fullcmc(&cmc_response_base64).await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate a CSR
    let (csr_der, _key) = CsrBuilder::new()
        .common_name("test-cmc.example.com")
        .build()
        .expect("CSR generation failed");

    // Build a proper CMC PKIData request
    let pki_data = PkiDataBuilder::new()
        .transaction_id(12345)
        .random_sender_nonce()
        .identification("test-client".to_string())
        .add_certification_request(csr_der)
        .build()
        .expect("PKIData build failed");

    // Encode to DER
    let pki_data_der = pki_data.to_der().expect("DER encoding failed");

    // Create CMC request
    let cmc_request = CmcRequest::new(pki_data_der);

    // Test: Full CMC request/response
    let result = client.full_cmc(&cmc_request).await;

    // Should succeed with the mock server
    assert!(
        result.is_ok(),
        "CMC request should succeed, got: {:?}",
        result.err()
    );

    let response = result.unwrap();
    assert_eq!(response.data.len(), pki_response_der.len());
}

#[tokio::test]
async fn test_cmc_status_codes() {
    use usg_est_client::types::cmc_full::{BodyPartId, CmcFailInfo, CmcStatusInfo, CmcStatusValue};

    // Test all CMC status values
    let status_success = CmcStatusValue::Success;
    assert!(status_success.is_success());
    assert!(!status_success.is_failure());
    assert!(!status_success.is_pending());
    assert_eq!(status_success.to_u32(), 0);

    let status_failed = CmcStatusValue::Failed;
    assert!(!status_failed.is_success());
    assert!(status_failed.is_failure());
    assert_eq!(status_failed.to_u32(), 2);

    let status_pending = CmcStatusValue::Pending;
    assert!(status_pending.is_pending());
    assert_eq!(status_pending.to_u32(), 3);

    let status_no_support = CmcStatusValue::NoSupport;
    assert!(status_no_support.is_failure());
    assert_eq!(status_no_support.to_u32(), 4);

    let status_confirm = CmcStatusValue::ConfirmRequired;
    assert_eq!(status_confirm.to_u32(), 5);

    let status_pop = CmcStatusValue::PopRequired;
    assert_eq!(status_pop.to_u32(), 6);

    let status_partial = CmcStatusValue::Partial;
    assert_eq!(status_partial.to_u32(), 7);

    // Test round-trip conversion
    for code in 0..=7 {
        if let Some(status) = CmcStatusValue::from_u32(code) {
            assert_eq!(status.to_u32(), code);
        }
    }

    // Test CmcStatusInfo creation
    let success_info = CmcStatusInfo::success(vec![BodyPartId::new(1)]);
    assert!(success_info.status.is_success());
    assert!(success_info.fail_info.is_none());

    let failed_info = CmcStatusInfo::failed(vec![BodyPartId::new(2)], CmcFailInfo::BadRequest);
    assert!(failed_info.status.is_failure());
    assert!(failed_info.fail_info.is_some());
    assert_eq!(failed_info.fail_info.unwrap(), CmcFailInfo::BadRequest);

    // Test all failure codes
    let failure_codes = [
        CmcFailInfo::BadAlgorithm,
        CmcFailInfo::BadMessageCheck,
        CmcFailInfo::BadRequest,
        CmcFailInfo::BadTime,
        CmcFailInfo::BadCertId,
        CmcFailInfo::UnsupportedExt,
        CmcFailInfo::MustArchiveKeys,
        CmcFailInfo::BadIdentity,
        CmcFailInfo::PopRequired,
        CmcFailInfo::PopFailed,
        CmcFailInfo::NoKeyReuse,
        CmcFailInfo::InternalCaError,
        CmcFailInfo::TryLater,
        CmcFailInfo::AuthDataFail,
    ];

    for fail_code in &failure_codes {
        let code = fail_code.to_u32();
        assert_eq!(CmcFailInfo::from_u32(code), Some(*fail_code));
        assert!(!fail_code.description().is_empty());
    }
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_cmc_error_conditions() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Test 1: Server returns error status
    mock.mock_server_error(501, "Not Implemented").await;

    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate minimal CMC request
    let (csr_der, _) = CsrBuilder::new()
        .common_name("test.example.com")
        .build()
        .expect("CSR generation failed");

    let pki_data = PkiDataBuilder::new()
        .add_certification_request(csr_der)
        .build()
        .expect("PKIData build failed");

    let cmc_request = CmcRequest::new(pki_data.to_der().expect("DER encoding failed"));

    // Should get not supported error (501 is converted to NotSupported)
    let result = client.full_cmc(&cmc_request).await;
    assert!(result.is_err(), "Should fail when server returns 501");

    let err = result.unwrap_err();
    assert!(
        matches!(err, usg_est_client::EstError::NotSupported(_)),
        "Should be NotSupported error, got: {:?}",
        err
    );

    // Test 2: Malformed response body
    let mock2 = MockEstServer::start().await;
    mock2.mock_fullcmc("INVALID_BASE64!!!").await;

    let config2 = EstClientConfig::builder()
        .server_url(mock2.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client2 = EstClient::new(config2)
        .await
        .expect("Client creation failed");

    let (csr_der2, _) = CsrBuilder::new()
        .common_name("test2.example.com")
        .build()
        .expect("CSR generation failed");

    let pki_data2 = PkiDataBuilder::new()
        .add_certification_request(csr_der2)
        .build()
        .expect("PKIData build failed");

    let cmc_request2 = CmcRequest::new(pki_data2.to_der().expect("DER encoding failed"));

    // Should fail with base64 decoding error
    let result2 = client2.full_cmc(&cmc_request2).await;
    assert!(
        result2.is_err(),
        "Should fail with malformed base64 response"
    );

    // Test 3: PKIData builder validation
    // Empty PKIData should still be valid (server may reject it though)
    let empty_pki_data = PkiDataBuilder::new().build();
    assert!(empty_pki_data.is_ok(), "Empty PKIData should be buildable");

    // Test 4: PKIResponse parsing
    use usg_est_client::types::cmc_full::PkiResponse;

    // Empty data should return error
    let empty_result = PkiResponse::from_der(&[]);
    assert!(empty_result.is_err(), "Empty DER should fail parsing");

    // Non-SEQUENCE data should return error
    let invalid_result = PkiResponse::from_der(&[0x02, 0x01, 0x00]); // INTEGER instead of SEQUENCE
    assert!(
        invalid_result.is_err(),
        "Non-SEQUENCE DER should fail parsing"
    );
}
