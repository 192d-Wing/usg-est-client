// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Log Event Extended Format (LEEF) integration tests

use std::collections::HashMap;
use usg_est_client::siem::leef::{attributes, from_est_event, LeefEvent, LeefSeverity};

#[test]
fn test_leef_basic_format() {
    let event = LeefEvent::new("CERT-2002");
    let leef = event.to_leef();

    assert!(leef.starts_with("LEEF:2.0|"));
    assert!(leef.contains("USGov"));
    assert!(leef.contains("EST-Client"));
    assert!(leef.contains("CERT-2002"));
}

#[test]
fn test_leef_version_2_0() {
    let event = LeefEvent::new("TEST-001");
    let leef = event.to_leef();

    assert!(leef.starts_with("LEEF:2.0|"));
}

#[test]
fn test_leef_pipe_delimited_header() {
    let event = LeefEvent::new("AUTH-1001");
    let leef = event.to_leef();

    // Should have 4 pipes in header: LEEF:2.0|Vendor|Product|Version|EventID
    let header_pipes = leef.chars().take_while(|&c| c != '\t').filter(|&c| c == '|').count();
    assert!(header_pipes >= 4);
}

#[test]
fn test_leef_no_attributes() {
    let event = LeefEvent::new("CERT-2001");
    let leef = event.to_leef();

    // Should end with event ID, no trailing pipe or tab
    assert!(!leef.ends_with('|'));
    assert!(!leef.ends_with('\t'));
}

#[test]
fn test_leef_with_single_attribute() {
    let event = LeefEvent::new("AUTH-1002").with_attribute("src", "10.0.1.100");

    let leef = event.to_leef();

    assert!(leef.contains("src=10.0.1.100"));
}

#[test]
fn test_leef_with_multiple_attributes() {
    let event = LeefEvent::new("AUTH-1002")
        .with_attribute("src", "10.0.1.100")
        .with_attribute("srcHost", "workstation01.example.mil")
        .with_attribute("dst", "10.0.2.50")
        .with_attribute("result", "failure");

    let leef = event.to_leef();

    assert!(leef.contains("src=10.0.1.100"));
    assert!(leef.contains("srcHost=workstation01.example.mil"));
    assert!(leef.contains("dst=10.0.2.50"));
    assert!(leef.contains("result=failure"));
}

#[test]
fn test_leef_attributes_tab_delimited() {
    let event = LeefEvent::new("TEST-001")
        .with_attribute("field1", "value1")
        .with_attribute("field2", "value2")
        .with_attribute("field3", "value3");

    let leef = event.to_leef();

    // Attributes should be tab-delimited
    let attributes_part = leef.split('|').last().unwrap();
    assert!(attributes_part.contains('\t'));
}

#[test]
fn test_leef_escape_pipes_in_header() {
    let event = LeefEvent::new("TEST|WITH|PIPES");
    let leef = event.to_leef();

    assert!(leef.contains("TEST\\|WITH\\|PIPES"));
}

#[test]
fn test_leef_escape_backslash_in_header() {
    let event = LeefEvent::new("TEST\\001");
    let leef = event.to_leef();

    assert!(leef.contains("TEST\\\\001"));
}

#[test]
fn test_leef_escape_tabs_in_attribute_value() {
    let event = LeefEvent::new("TEST-001").with_attribute("msg", "Tab\there");

    let leef = event.to_leef();

    assert!(leef.contains("msg=Tab\\there"));
}

#[test]
fn test_leef_escape_newlines_in_attribute_value() {
    let event = LeefEvent::new("TEST-002").with_attribute("msg", "Line 1\nLine 2\rLine 3");

    let leef = event.to_leef();

    assert!(leef.contains("msg=Line 1\\nLine 2\\rLine 3"));
}

#[test]
fn test_leef_escape_backslash_in_attribute_value() {
    let event = LeefEvent::new("TEST-003").with_attribute("path", "C:\\Windows\\System32");

    let leef = event.to_leef();

    assert!(leef.contains("path=C:\\\\Windows\\\\System32"));
}

#[test]
fn test_leef_escape_equals_in_attribute_key() {
    let event = LeefEvent::new("TEST-004").with_attribute("key=name", "value");

    let leef = event.to_leef();

    assert!(leef.contains("key\\=name=value"));
}

#[test]
fn test_leef_standard_event_attributes() {
    let event = LeefEvent::new("CERT-2002")
        .with_attribute(attributes::EVENT_ID, "CERT-2002")
        .with_attribute(attributes::EVENT_NAME, "Certificate Enrolled")
        .with_attribute(attributes::EVENT_DESC, "User certificate enrolled successfully")
        .with_attribute(attributes::CAT, "certificate_lifecycle")
        .with_attribute(attributes::SEV, "2");

    let leef = event.to_leef();

    assert!(leef.contains("eventId=CERT-2002"));
    assert!(leef.contains("eventName=Certificate Enrolled"));
    assert!(leef.contains("eventDesc=User certificate enrolled successfully"));
    assert!(leef.contains("cat=certificate_lifecycle"));
    assert!(leef.contains("sev=2"));
}

#[test]
fn test_leef_source_fields() {
    let event = LeefEvent::new("AUTH-1001")
        .with_attribute(attributes::SRC, "192.168.1.100")
        .with_attribute(attributes::SRC_PORT, "54321")
        .with_attribute(attributes::SRC_HOST, "client.example.mil")
        .with_attribute(attributes::USRNAME, "jsmith")
        .with_attribute(attributes::IDENTHOST_NAME, "workstation01");

    let leef = event.to_leef();

    assert!(leef.contains("src=192.168.1.100"));
    assert!(leef.contains("srcPort=54321"));
    assert!(leef.contains("srcHost=client.example.mil"));
    assert!(leef.contains("usrName=jsmith"));
    assert!(leef.contains("identHostName=workstation01"));
}

#[test]
fn test_leef_destination_fields() {
    let event = LeefEvent::new("CERT-2001")
        .with_attribute(attributes::DST, "10.0.2.50")
        .with_attribute(attributes::DST_PORT, "443")
        .with_attribute(attributes::DST_HOST, "est-server.example.mil")
        .with_attribute(attributes::PROTO, "https");

    let leef = event.to_leef();

    assert!(leef.contains("dst=10.0.2.50"));
    assert!(leef.contains("dstPort=443"));
    assert!(leef.contains("dstHost=est-server.example.mil"));
    assert!(leef.contains("proto=https"));
}

#[test]
fn test_leef_certificate_fields() {
    let event = LeefEvent::new("CERT-2002")
        .with_attribute(attributes::CERT_SUBJECT, "CN=workstation01.example.mil")
        .with_attribute(attributes::CERT_ISSUER, "CN=EST CA")
        .with_attribute(attributes::CERT_SERIAL, "1A:2B:3C:4D:5E:6F")
        .with_attribute(attributes::CERT_THUMBPRINT, "ABC123DEF456")
        .with_attribute(attributes::CERT_NOT_BEFORE, "2026-01-01T00:00:00Z")
        .with_attribute(attributes::CERT_NOT_AFTER, "2027-01-01T00:00:00Z");

    let leef = event.to_leef();

    assert!(leef.contains("certSubject=CN=workstation01.example.mil"));
    assert!(leef.contains("certIssuer=CN=EST CA"));
    assert!(leef.contains("certSerial=1A:2B:3C:4D:5E:6F"));
    assert!(leef.contains("certThumbprint=ABC123DEF456"));
    assert!(leef.contains("certNotBefore=2026-01-01T00:00:00Z"));
    assert!(leef.contains("certNotAfter=2027-01-01T00:00:00Z"));
}

#[test]
fn test_leef_key_operation_fields() {
    let event = LeefEvent::new("KEY-3001")
        .with_attribute(attributes::KEY_ALGORITHM, "RSA")
        .with_attribute(attributes::KEY_SIZE, "2048")
        .with_attribute(attributes::KEY_CONTAINER, "EST-workstation01-rsa2048");

    let leef = event.to_leef();

    assert!(leef.contains("keyAlgorithm=RSA"));
    assert!(leef.contains("keySize=2048"));
    assert!(leef.contains("keyContainer=EST-workstation01-rsa2048"));
}

#[test]
fn test_leef_authentication_fields() {
    let event = LeefEvent::new("AUTH-1001")
        .with_attribute(attributes::AUTH_METHOD, "TLS-Client-Auth")
        .with_attribute(attributes::TLS_VERSION, "TLS 1.3")
        .with_attribute(attributes::CIPHER_SUITE, "TLS_AES_256_GCM_SHA384");

    let leef = event.to_leef();

    assert!(leef.contains("authMethod=TLS-Client-Auth"));
    assert!(leef.contains("tlsVersion=TLS 1.3"));
    assert!(leef.contains("cipherSuite=TLS_AES_256_GCM_SHA384"));
}

#[test]
fn test_leef_outcome_fields() {
    let event = LeefEvent::new("CERT-2003")
        .with_attribute(attributes::RESULT, "failure")
        .with_attribute(attributes::REASON, "Invalid certificate request format");

    let leef = event.to_leef();

    assert!(leef.contains("result=failure"));
    assert!(leef.contains("reason=Invalid certificate request format"));
}

#[test]
fn test_leef_timestamp_fields() {
    let event = LeefEvent::new("TEST-001")
        .with_attribute(attributes::DEV_TIME, "2026-01-13 12:34:56.789")
        .with_attribute(attributes::DEV_TIME_FORMAT, "yyyy-MM-dd HH:mm:ss.SSS");

    let leef = event.to_leef();

    assert!(leef.contains("devTime=2026-01-13 12:34:56.789"));
    assert!(leef.contains("devTimeFormat=yyyy-MM-dd HH:mm:ss.SSS"));
}

#[test]
fn test_leef_severity_info() {
    let severity = LeefSeverity::Info;
    assert_eq!(severity as u8, 2);
}

#[test]
fn test_leef_severity_warning() {
    let severity = LeefSeverity::Warning;
    assert_eq!(severity as u8, 5);
}

#[test]
fn test_leef_severity_error() {
    let severity = LeefSeverity::Error;
    assert_eq!(severity as u8, 7);
}

#[test]
fn test_leef_severity_critical() {
    let severity = LeefSeverity::Critical;
    assert_eq!(severity as u8, 10);
}

#[test]
fn test_leef_severity_from_category_security_violation() {
    let severity = LeefSeverity::from_category("security_violation");
    assert_eq!(severity, LeefSeverity::Critical);
}

#[test]
fn test_leef_severity_from_category_authentication_failure() {
    let severity = LeefSeverity::from_category("authentication_failure");
    assert_eq!(severity, LeefSeverity::Critical);
}

#[test]
fn test_leef_severity_from_category_certificate_expired() {
    let severity = LeefSeverity::from_category("certificate_expired");
    assert_eq!(severity, LeefSeverity::Error);
}

#[test]
fn test_leef_severity_from_category_key_operation_failure() {
    let severity = LeefSeverity::from_category("key_operation_failure");
    assert_eq!(severity, LeefSeverity::Error);
}

#[test]
fn test_leef_severity_from_category_certificate_expiring() {
    let severity = LeefSeverity::from_category("certificate_expiring");
    assert_eq!(severity, LeefSeverity::Warning);
}

#[test]
fn test_leef_severity_from_category_renewal_required() {
    let severity = LeefSeverity::from_category("renewal_required");
    assert_eq!(severity, LeefSeverity::Warning);
}

#[test]
fn test_leef_severity_from_category_default_info() {
    let severity = LeefSeverity::from_category("certificate_lifecycle");
    assert_eq!(severity, LeefSeverity::Info);
}

#[test]
fn test_leef_from_est_event_basic() {
    let details = HashMap::new();
    let event = from_est_event("CERT-2002", "Certificate Enrolled", "certificate_lifecycle", details);

    let leef = event.to_leef();

    assert!(leef.contains("CERT-2002"));
    assert!(leef.contains("eventId=CERT-2002"));
    assert!(leef.contains("eventName=Certificate Enrolled"));
    assert!(leef.contains("cat=certificate_lifecycle"));
    assert!(leef.contains("sev=2")); // Info severity
}

#[test]
fn test_leef_from_est_event_with_details() {
    let mut details = HashMap::new();
    details.insert("src".to_string(), "10.0.1.100".to_string());
    details.insert("srcHost".to_string(), "workstation01.example.mil".to_string());
    details.insert("certSubject".to_string(), "CN=workstation01.example.mil".to_string());

    let event = from_est_event("CERT-2002", "Certificate Enrolled", "certificate_lifecycle", details);

    let leef = event.to_leef();

    assert!(leef.contains("src=10.0.1.100"));
    assert!(leef.contains("srcHost=workstation01.example.mil"));
    assert!(leef.contains("certSubject=CN=workstation01.example.mil"));
}

#[test]
fn test_leef_from_est_event_security_violation() {
    let details = HashMap::new();
    let event = from_est_event("SEC-9001", "Security Violation", "security_violation", details);

    let leef = event.to_leef();

    assert!(leef.contains("sev=10")); // Critical severity
}

#[test]
fn test_leef_from_est_event_includes_timestamp() {
    let details = HashMap::new();
    let event = from_est_event("TEST-001", "Test Event", "test_category", details);

    let leef = event.to_leef();

    // Should include devTime and devTimeFormat
    assert!(leef.contains("devTime="));
    assert!(leef.contains("devTimeFormat=yyyy-MM-dd HH:mm:ss.SSS"));
}

#[test]
fn test_leef_complete_authentication_event() {
    let event = LeefEvent::new("AUTH-1002")
        .with_attribute(attributes::EVENT_ID, "AUTH-1002")
        .with_attribute(attributes::EVENT_NAME, "Authentication Failed")
        .with_attribute(attributes::CAT, "authentication_failure")
        .with_attribute(attributes::SEV, "10")
        .with_attribute(attributes::SRC, "192.168.1.100")
        .with_attribute(attributes::SRC_HOST, "attacker.example.com")
        .with_attribute(attributes::USRNAME, "admin")
        .with_attribute(attributes::DST, "10.0.2.50")
        .with_attribute(attributes::DST_HOST, "est-server.example.mil")
        .with_attribute(attributes::DST_PORT, "443")
        .with_attribute(attributes::RESULT, "failure")
        .with_attribute(attributes::REASON, "Invalid credentials");

    let leef = event.to_leef();

    // Verify complete LEEF event
    assert!(leef.starts_with("LEEF:2.0|USGov|EST-Client|"));
    assert!(leef.contains("AUTH-1002"));
    assert!(leef.contains("eventName=Authentication Failed"));
    assert!(leef.contains("cat=authentication_failure"));
    assert!(leef.contains("sev=10"));
    assert!(leef.contains("src=192.168.1.100"));
    assert!(leef.contains("result=failure"));
    assert!(leef.contains("reason=Invalid credentials"));
}

#[test]
fn test_leef_complete_certificate_event() {
    let event = LeefEvent::new("CERT-2002")
        .with_attribute(attributes::EVENT_ID, "CERT-2002")
        .with_attribute(attributes::EVENT_NAME, "Certificate Enrolled")
        .with_attribute(attributes::CAT, "certificate_lifecycle")
        .with_attribute(attributes::SEV, "2")
        .with_attribute(attributes::SRC, "10.0.1.50")
        .with_attribute(attributes::SRC_HOST, "workstation01.example.mil")
        .with_attribute(attributes::DST, "10.0.2.100")
        .with_attribute(attributes::DST_HOST, "est-server.example.mil")
        .with_attribute(attributes::CERT_SUBJECT, "CN=workstation01.example.mil, O=U.S. Government")
        .with_attribute(attributes::CERT_ISSUER, "CN=EST CA, O=U.S. Government")
        .with_attribute(attributes::CERT_SERIAL, "1A:2B:3C:4D:5E:6F")
        .with_attribute(attributes::RESULT, "success");

    let leef = event.to_leef();

    assert!(leef.contains("CERT-2002"));
    assert!(leef.contains("eventName=Certificate Enrolled"));
    assert!(leef.contains("cat=certificate_lifecycle"));
    assert!(leef.contains("sev=2"));
    assert!(leef.contains("certSubject=CN=workstation01.example.mil, O=U.S. Government"));
    assert!(leef.contains("certIssuer=CN=EST CA, O=U.S. Government"));
}

#[test]
fn test_leef_complete_key_generation_event() {
    let event = LeefEvent::new("KEY-3001")
        .with_attribute(attributes::EVENT_ID, "KEY-3001")
        .with_attribute(attributes::EVENT_NAME, "Key Generated")
        .with_attribute(attributes::CAT, "key_operation")
        .with_attribute(attributes::SEV, "2")
        .with_attribute(attributes::SRC_HOST, "workstation01.example.mil")
        .with_attribute(attributes::KEY_ALGORITHM, "RSA")
        .with_attribute(attributes::KEY_SIZE, "2048")
        .with_attribute(attributes::KEY_CONTAINER, "EST-workstation01-rsa2048-1736779200")
        .with_attribute(attributes::RESULT, "success");

    let leef = event.to_leef();

    assert!(leef.contains("KEY-3001"));
    assert!(leef.contains("keyAlgorithm=RSA"));
    assert!(leef.contains("keySize=2048"));
    assert!(leef.contains("keyContainer=EST-workstation01-rsa2048-1736779200"));
}

#[test]
fn test_leef_vendor_product_defaults() {
    let event = LeefEvent::new("TEST-001");

    assert_eq!(event.vendor, "USGov");
    assert_eq!(event.product, "EST-Client");
    assert!(!event.version.is_empty()); // Should be from CARGO_PKG_VERSION
}

#[test]
fn test_leef_builder_pattern() {
    let event = LeefEvent::new("KEY-3001")
        .with_attribute("keyAlgorithm", "RSA")
        .with_attribute("keySize", "2048")
        .with_attribute("result", "success");

    assert_eq!(event.event_id, "KEY-3001");
    assert_eq!(event.attributes.len(), 3);
    assert_eq!(event.attributes.get("keyAlgorithm"), Some(&"RSA".to_string()));
    assert_eq!(event.attributes.get("keySize"), Some(&"2048".to_string()));
}
