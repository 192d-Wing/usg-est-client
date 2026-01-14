// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Common Event Format (CEF) integration tests

use std::collections::HashMap;
use usg_est_client::siem::cef::{extensions, from_est_event, CefEvent, CefSeverity};

#[test]
fn test_cef_basic_format() {
    let event = CefEvent::new("CERT-2002", "Certificate Enrolled")
        .with_severity(CefSeverity::Low);

    let cef = event.to_cef();

    assert!(cef.starts_with("CEF:0|"));
    assert!(cef.contains("U.S. Government"));
    assert!(cef.contains("EST Client"));
    assert!(cef.contains("CERT-2002"));
    assert!(cef.contains("Certificate Enrolled"));
    assert!(cef.ends_with("|3")); // Low severity (no extensions)
}

#[test]
fn test_cef_version_zero() {
    let event = CefEvent::new("TEST-001", "Test Event");
    let cef = event.to_cef();

    // CEF version should be 0
    assert!(cef.starts_with("CEF:0|"));
}

#[test]
fn test_cef_pipe_delimited() {
    let event = CefEvent::new("AUTH-1001", "Authentication Success");
    let cef = event.to_cef();

    // Should have exactly 6 pipes in header (CEF:0|vendor|product|version|sig|name|severity)
    let pipe_count = cef.chars().filter(|&c| c == '|').count();
    assert_eq!(pipe_count, 6);
}

#[test]
fn test_cef_severity_low() {
    let event = CefEvent::new("TEST-001", "Test").with_severity(CefSeverity::Low);
    let cef = event.to_cef();
    assert!(cef.ends_with("|3"));
}

#[test]
fn test_cef_severity_medium() {
    let event = CefEvent::new("TEST-001", "Test").with_severity(CefSeverity::Medium);
    let cef = event.to_cef();
    assert!(cef.ends_with("|6"));
}

#[test]
fn test_cef_severity_high() {
    let event = CefEvent::new("TEST-001", "Test").with_severity(CefSeverity::High);
    let cef = event.to_cef();
    assert!(cef.ends_with("|8"));
}

#[test]
fn test_cef_severity_critical() {
    let event = CefEvent::new("TEST-001", "Test").with_severity(CefSeverity::Critical);
    let cef = event.to_cef();
    assert!(cef.ends_with("|10"));
}

#[test]
fn test_cef_no_extensions() {
    let event = CefEvent::new("CERT-2001", "Certificate Request");
    let cef = event.to_cef();

    // Should end with severity, no trailing pipe
    assert!(cef.ends_with("|3"));
}

#[test]
fn test_cef_with_single_extension() {
    let event = CefEvent::new("AUTH-1002", "Authentication Failed")
        .with_severity(CefSeverity::High)
        .with_extension("src", "10.0.1.100");

    let cef = event.to_cef();

    assert!(cef.contains("src=10.0.1.100"));
}

#[test]
fn test_cef_with_multiple_extensions() {
    let event = CefEvent::new("AUTH-1002", "Authentication Failed")
        .with_severity(CefSeverity::High)
        .with_extension("src", "10.0.1.100")
        .with_extension("shost", "workstation01.example.mil")
        .with_extension("dst", "10.0.2.50")
        .with_extension("outcome", "failure");

    let cef = event.to_cef();

    assert!(cef.contains("src=10.0.1.100"));
    assert!(cef.contains("shost=workstation01.example.mil"));
    assert!(cef.contains("dst=10.0.2.50"));
    assert!(cef.contains("outcome=failure"));
}

#[test]
fn test_cef_extensions_space_delimited() {
    let event = CefEvent::new("TEST-001", "Test")
        .with_extension("field1", "value1")
        .with_extension("field2", "value2")
        .with_extension("field3", "value3");

    let cef = event.to_cef();

    // Extensions should be space-delimited
    let extensions_part = cef.split('|').last().unwrap();
    assert!(extensions_part.contains("field1=value1"));
    assert!(extensions_part.contains("field2=value2"));
    assert!(extensions_part.contains("field3=value3"));
    // Check for spaces between fields
    assert!(extensions_part.matches(' ').count() >= 2);
}

#[test]
fn test_cef_escape_pipes_in_header() {
    let event = CefEvent::new("TEST|WITH|PIPES", "Event|Name|With|Pipes");
    let cef = event.to_cef();

    assert!(cef.contains("TEST\\|WITH\\|PIPES"));
    assert!(cef.contains("Event\\|Name\\|With\\|Pipes"));
}

#[test]
fn test_cef_escape_backslash_in_header() {
    let event = CefEvent::new("TEST\\001", "Test Event");
    let cef = event.to_cef();

    assert!(cef.contains("TEST\\\\001"));
}

#[test]
fn test_cef_escape_newlines_in_extension() {
    let event = CefEvent::new("TEST-002", "Test Event")
        .with_extension("msg", "Line 1\nLine 2\rLine 3");

    let cef = event.to_cef();

    assert!(cef.contains("msg=Line 1\\nLine 2\\rLine 3"));
}

#[test]
fn test_cef_escape_backslash_in_extension() {
    let event = CefEvent::new("TEST-003", "Test Event")
        .with_extension("path", "C:\\Windows\\System32");

    let cef = event.to_cef();

    assert!(cef.contains("path=C:\\\\Windows\\\\System32"));
}

#[test]
fn test_cef_standard_source_extensions() {
    let event = CefEvent::new("AUTH-1001", "Authentication Success")
        .with_extension(extensions::SRC, "192.168.1.100")
        .with_extension(extensions::SHOST, "client.example.mil")
        .with_extension(extensions::SUSER, "jsmith")
        .with_extension(extensions::SPROC, "est-client.exe");

    let cef = event.to_cef();

    assert!(cef.contains("src=192.168.1.100"));
    assert!(cef.contains("shost=client.example.mil"));
    assert!(cef.contains("suser=jsmith"));
    assert!(cef.contains("sproc=est-client.exe"));
}

#[test]
fn test_cef_standard_destination_extensions() {
    let event = CefEvent::new("CERT-2001", "Certificate Request")
        .with_extension(extensions::DST, "10.0.2.50")
        .with_extension(extensions::DHOST, "est-server.example.mil")
        .with_extension(extensions::DPORT, "443");

    let cef = event.to_cef();

    assert!(cef.contains("dst=10.0.2.50"));
    assert!(cef.contains("dhost=est-server.example.mil"));
    assert!(cef.contains("dport=443"));
}

#[test]
fn test_cef_event_classification_extensions() {
    let event = CefEvent::new("SEC-9001", "Security Violation")
        .with_extension(extensions::CAT, "security_violation")
        .with_extension(extensions::ACT, "blocked")
        .with_extension(extensions::OUTCOME, "failure");

    let cef = event.to_cef();

    assert!(cef.contains("cat=security_violation"));
    assert!(cef.contains("act=blocked"));
    assert!(cef.contains("outcome=failure"));
}

#[test]
fn test_cef_certificate_custom_strings() {
    let event = CefEvent::new("CERT-2002", "Certificate Enrolled")
        .with_extension(extensions::CERT_SUBJECT, "CN=workstation01.example.mil")
        .with_extension(extensions::CERT_SUBJECT_LABEL, "Certificate Subject")
        .with_extension(extensions::CERT_ISSUER, "CN=EST CA")
        .with_extension(extensions::CERT_ISSUER_LABEL, "Certificate Issuer")
        .with_extension(extensions::CERT_SERIAL, "1A2B3C4D5E6F")
        .with_extension(extensions::CERT_SERIAL_LABEL, "Certificate Serial")
        .with_extension(extensions::CERT_THUMBPRINT, "ABC123DEF456")
        .with_extension(extensions::CERT_THUMBPRINT_LABEL, "Certificate Thumbprint");

    let cef = event.to_cef();

    assert!(cef.contains("cs1=CN=workstation01.example.mil"));
    assert!(cef.contains("cs1Label=Certificate Subject"));
    assert!(cef.contains("cs2=CN=EST CA"));
    assert!(cef.contains("cs2Label=Certificate Issuer"));
    assert!(cef.contains("cs3=1A2B3C4D5E6F"));
    assert!(cef.contains("cs4=ABC123DEF456"));
}

#[test]
fn test_cef_key_operation_custom_numbers() {
    let event = CefEvent::new("KEY-3001", "Key Generated")
        .with_extension(extensions::KEY_ALGORITHM, "RSA")
        .with_extension(extensions::KEY_ALGORITHM_LABEL, "Key Algorithm")
        .with_extension(extensions::KEY_SIZE, "2048")
        .with_extension(extensions::KEY_SIZE_LABEL, "Key Size");

    let cef = event.to_cef();

    assert!(cef.contains("cs5=RSA"));
    assert!(cef.contains("cs5Label=Key Algorithm"));
    assert!(cef.contains("cn1=2048"));
    assert!(cef.contains("cn1Label=Key Size"));
}

#[test]
fn test_cef_severity_from_category_security_violation() {
    let severity = CefSeverity::from_category("security_violation");
    assert_eq!(severity, CefSeverity::Critical);
}

#[test]
fn test_cef_severity_from_category_authentication_failure() {
    let severity = CefSeverity::from_category("authentication_failure");
    assert_eq!(severity, CefSeverity::Critical);
}

#[test]
fn test_cef_severity_from_category_certificate_expired() {
    let severity = CefSeverity::from_category("certificate_expired");
    assert_eq!(severity, CefSeverity::High);
}

#[test]
fn test_cef_severity_from_category_key_operation_failure() {
    let severity = CefSeverity::from_category("key_operation_failure");
    assert_eq!(severity, CefSeverity::High);
}

#[test]
fn test_cef_severity_from_category_certificate_expiring() {
    let severity = CefSeverity::from_category("certificate_expiring");
    assert_eq!(severity, CefSeverity::Medium);
}

#[test]
fn test_cef_severity_from_category_renewal_required() {
    let severity = CefSeverity::from_category("renewal_required");
    assert_eq!(severity, CefSeverity::Medium);
}

#[test]
fn test_cef_severity_from_category_default_low() {
    let severity = CefSeverity::from_category("certificate_lifecycle");
    assert_eq!(severity, CefSeverity::Low);
}

#[test]
fn test_cef_from_est_event_basic() {
    let details = HashMap::new();
    let event = from_est_event("CERT-2002", "Certificate Enrolled", "certificate_lifecycle", details);

    let cef = event.to_cef();

    assert!(cef.contains("CERT-2002"));
    assert!(cef.contains("Certificate Enrolled"));
    assert!(cef.contains("cat=certificate_lifecycle"));
    assert!(cef.contains("|3|")); // Low severity for lifecycle events
}

#[test]
fn test_cef_from_est_event_with_details() {
    let mut details = HashMap::new();
    details.insert("src".to_string(), "10.0.1.100".to_string());
    details.insert("shost".to_string(), "workstation01.example.mil".to_string());
    details.insert("cs1".to_string(), "CN=workstation01.example.mil".to_string());

    let event = from_est_event("CERT-2002", "Certificate Enrolled", "certificate_lifecycle", details);

    let cef = event.to_cef();

    assert!(cef.contains("src=10.0.1.100"));
    assert!(cef.contains("shost=workstation01.example.mil"));
    assert!(cef.contains("cs1=CN=workstation01.example.mil"));
}

#[test]
fn test_cef_from_est_event_security_violation() {
    let details = HashMap::new();
    let event = from_est_event("SEC-9001", "Security Violation", "security_violation", details);

    let cef = event.to_cef();

    assert!(cef.contains("|10|")); // Critical severity
}

#[test]
fn test_cef_complete_authentication_event() {
    let event = CefEvent::new("AUTH-1002", "Authentication Failed")
        .with_severity(CefSeverity::Critical)
        .with_extension(extensions::SRC, "192.168.1.100")
        .with_extension(extensions::SHOST, "attacker.example.com")
        .with_extension(extensions::SUSER, "admin")
        .with_extension(extensions::DST, "10.0.2.50")
        .with_extension(extensions::DHOST, "est-server.example.mil")
        .with_extension(extensions::DPORT, "443")
        .with_extension(extensions::CAT, "authentication_failure")
        .with_extension(extensions::ACT, "login")
        .with_extension(extensions::OUTCOME, "failure")
        .with_extension(extensions::MSG, "Invalid credentials")
        .with_extension(extensions::REASON, "Bad username or password");

    let cef = event.to_cef();

    // Verify complete CEF event
    assert!(cef.starts_with("CEF:0|U.S. Government|EST Client|"));
    assert!(cef.contains("AUTH-1002"));
    assert!(cef.contains("Authentication Failed"));
    assert!(cef.contains("|10|")); // Critical
    assert!(cef.contains("src=192.168.1.100"));
    assert!(cef.contains("outcome=failure"));
    assert!(cef.contains("msg=Invalid credentials"));
}

#[test]
fn test_cef_complete_certificate_event() {
    let event = CefEvent::new("CERT-2002", "Certificate Enrolled")
        .with_severity(CefSeverity::Low)
        .with_extension(extensions::SRC, "10.0.1.50")
        .with_extension(extensions::SHOST, "workstation01.example.mil")
        .with_extension(extensions::DST, "10.0.2.100")
        .with_extension(extensions::DHOST, "est-server.example.mil")
        .with_extension(extensions::CAT, "certificate_lifecycle")
        .with_extension(extensions::OUTCOME, "success")
        .with_extension(extensions::CERT_SUBJECT, "CN=workstation01.example.mil, O=U.S. Government")
        .with_extension(extensions::CERT_SUBJECT_LABEL, "Certificate Subject")
        .with_extension(extensions::CERT_ISSUER, "CN=EST CA, O=U.S. Government")
        .with_extension(extensions::CERT_ISSUER_LABEL, "Certificate Issuer")
        .with_extension(extensions::CERT_SERIAL, "1A:2B:3C:4D:5E:6F")
        .with_extension(extensions::CERT_SERIAL_LABEL, "Certificate Serial");

    let cef = event.to_cef();

    assert!(cef.contains("CERT-2002"));
    assert!(cef.contains("Certificate Enrolled"));
    assert!(cef.contains("|3|")); // Low severity
    assert!(cef.contains("cat=certificate_lifecycle"));
    assert!(cef.contains("cs1=CN=workstation01.example.mil, O=U.S. Government"));
    assert!(cef.contains("cs2=CN=EST CA, O=U.S. Government"));
}

#[test]
fn test_cef_device_fields_populated() {
    let event = CefEvent::new("TEST-001", "Test Event");

    // Check default values
    assert_eq!(event.device_vendor, "U.S. Government");
    assert_eq!(event.device_product, "EST Client");
    assert!(!event.device_version.is_empty()); // Should be from CARGO_PKG_VERSION
}

#[test]
fn test_cef_builder_pattern() {
    let event = CefEvent::new("KEY-3001", "Key Generated")
        .with_severity(CefSeverity::Low)
        .with_extension("cs5", "RSA")
        .with_extension("cn1", "2048")
        .with_extension("outcome", "success");

    assert_eq!(event.signature_id, "KEY-3001");
    assert_eq!(event.name, "Key Generated");
    assert_eq!(event.severity, CefSeverity::Low);
    assert_eq!(event.extensions.len(), 3);
}
