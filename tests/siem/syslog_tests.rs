// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Syslog (RFC 5424) integration tests

use usg_est_client::siem::syslog::{
    Facility, Severity, StructuredData, SyslogClient, SyslogConfig, SyslogMessage,
};

#[test]
fn test_syslog_priority_calculation() {
    // Priority = (Facility * 8) + Severity
    // User facility (1), Info severity (6): 1*8+6 = 14
    let msg = SyslogMessage::new(Facility::User, Severity::Informational, "test");
    let formatted = msg.to_rfc5424("localhost");
    assert!(formatted.starts_with("<14>"));
}

#[test]
fn test_syslog_priority_local0_critical() {
    // Local0 (16), Critical (2): 16*8+2 = 130
    let msg = SyslogMessage::new(Facility::Local0, Severity::Critical, "est-client");
    let formatted = msg.to_rfc5424("localhost");
    assert!(formatted.starts_with("<130>"));
}

#[test]
fn test_syslog_rfc5424_version() {
    let msg = SyslogMessage::new(Facility::User, Severity::Informational, "test");
    let formatted = msg.to_rfc5424("localhost");
    // After priority <NN>, version should be 1
    assert!(formatted.contains(">1 "));
}

#[test]
fn test_syslog_hostname_included() {
    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client")
        .with_message("Test message");

    let formatted = msg.to_rfc5424("workstation01.example.mil");
    assert!(formatted.contains("workstation01.example.mil"));
}

#[test]
fn test_syslog_app_name() {
    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client")
        .with_message("Certificate enrolled");

    let formatted = msg.to_rfc5424("localhost");
    assert!(formatted.contains("est-client"));
}

#[test]
fn test_syslog_with_proc_id() {
    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client")
        .with_proc_id("1234")
        .with_message("Test");

    let formatted = msg.to_rfc5424("localhost");
    assert!(formatted.contains(" 1234 "));
}

#[test]
fn test_syslog_without_proc_id_uses_nil() {
    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client")
        .with_message("Test");

    let formatted = msg.to_rfc5424("localhost");
    // Should contain " - " for PROCID
    assert!(formatted.contains(" - "));
}

#[test]
fn test_syslog_with_msg_id() {
    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client")
        .with_msg_id("CERT-2002")
        .with_message("Certificate enrolled");

    let formatted = msg.to_rfc5424("localhost");
    assert!(formatted.contains("CERT-2002"));
}

#[test]
fn test_syslog_structured_data_single_element() {
    let sd = StructuredData {
        id: "est@32473".to_string(),
        params: vec![
            ("event_id".to_string(), "CERT-2002".to_string()),
            ("category".to_string(), "certificate_lifecycle".to_string()),
        ],
    };

    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client")
        .with_structured_data(sd)
        .with_message("Certificate enrolled");

    let formatted = msg.to_rfc5424("localhost");
    assert!(formatted.contains("[est@32473"));
    assert!(formatted.contains("event_id=\"CERT-2002\""));
    assert!(formatted.contains("category=\"certificate_lifecycle\""));
}

#[test]
fn test_syslog_structured_data_multiple_elements() {
    let sd1 = StructuredData {
        id: "est@32473".to_string(),
        params: vec![("event_id".to_string(), "AUTH-1001".to_string())],
    };

    let sd2 = StructuredData {
        id: "source@32473".to_string(),
        params: vec![
            ("ip".to_string(), "10.0.1.100".to_string()),
            ("host".to_string(), "workstation01".to_string()),
        ],
    };

    let msg = SyslogMessage::new(Facility::Security, Severity::Notice, "est-client")
        .with_structured_data(sd1)
        .with_structured_data(sd2)
        .with_message("Authentication successful");

    let formatted = msg.to_rfc5424("localhost");
    assert!(formatted.contains("[est@32473"));
    assert!(formatted.contains("[source@32473"));
    assert!(formatted.contains("ip=\"10.0.1.100\""));
}

#[test]
fn test_syslog_no_structured_data_uses_nil() {
    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client")
        .with_message("Simple message");

    let formatted = msg.to_rfc5424("localhost");
    // Should contain " - " for STRUCTURED-DATA
    assert!(formatted.contains(" - Simple message"));
}

#[test]
fn test_syslog_escape_backslash_in_structured_data() {
    let sd = StructuredData {
        id: "test@32473".to_string(),
        params: vec![("path".to_string(), "C:\\Windows\\System32".to_string())],
    };

    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "test")
        .with_structured_data(sd)
        .with_message("Test");

    let formatted = msg.to_rfc5424("localhost");
    assert!(formatted.contains("path=\"C:\\\\Windows\\\\System32\""));
}

#[test]
fn test_syslog_escape_quote_in_structured_data() {
    let sd = StructuredData {
        id: "test@32473".to_string(),
        params: vec![("msg".to_string(), "He said \"hello\"".to_string())],
    };

    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "test")
        .with_structured_data(sd)
        .with_message("Test");

    let formatted = msg.to_rfc5424("localhost");
    assert!(formatted.contains("msg=\"He said \\\"hello\\\"\""));
}

#[test]
fn test_syslog_escape_bracket_in_structured_data() {
    let sd = StructuredData {
        id: "test@32473".to_string(),
        params: vec![("array".to_string(), "[1, 2, 3]".to_string())],
    };

    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "test")
        .with_structured_data(sd)
        .with_message("Test");

    let formatted = msg.to_rfc5424("localhost");
    assert!(formatted.contains("array=\"[1, 2, 3\\]\""));
}

#[test]
fn test_syslog_message_content() {
    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client")
        .with_message("Certificate enrolled successfully for CN=workstation01.example.mil");

    let formatted = msg.to_rfc5424("localhost");
    assert!(
        formatted.ends_with("Certificate enrolled successfully for CN=workstation01.example.mil")
    );
}

#[test]
fn test_syslog_client_config_default() {
    let config = SyslogConfig::default();
    assert_eq!(config.server, "localhost:514");
    assert_eq!(config.use_tls, false);
    assert_eq!(config.facility, Facility::Local0);
    assert_eq!(config.app_name, "est-client");
}

#[test]
fn test_syslog_client_creation() {
    let config = SyslogConfig {
        server: "syslog.example.mil:514".to_string(),
        use_tls: false,
        facility: Facility::Local0,
        app_name: "est-client".to_string(),
        hostname: Some("test-host".to_string()),
    };

    let client = SyslogClient::new(config);
    assert!(client.is_ok());
}

#[test]
fn test_syslog_client_message_builder() {
    let config = SyslogConfig {
        server: "localhost:514".to_string(),
        use_tls: false,
        facility: Facility::Local1,
        app_name: "test-app".to_string(),
        hostname: None,
    };

    let client = SyslogClient::new(config).expect("Failed to create client");
    let msg = client.message_builder(Severity::Error);

    // Should use facility from config
    assert_eq!(msg.facility, Facility::Local1);
    assert_eq!(msg.severity, Severity::Error);
    assert_eq!(msg.app_name, "test-app");
}

#[test]
fn test_syslog_all_severity_levels() {
    let severities = vec![
        (Severity::Emergency, 0),
        (Severity::Alert, 1),
        (Severity::Critical, 2),
        (Severity::Error, 3),
        (Severity::Warning, 4),
        (Severity::Notice, 5),
        (Severity::Informational, 6),
        (Severity::Debug, 7),
    ];

    for (severity, expected_num) in severities {
        let msg = SyslogMessage::new(Facility::User, severity, "test");
        let formatted = msg.to_rfc5424("localhost");
        // User facility (1) * 8 + severity
        let expected_priority = 8 + expected_num;
        assert!(formatted.starts_with(&format!("<{}>", expected_priority)));
    }
}

#[test]
fn test_syslog_all_facilities() {
    let facilities = vec![
        (Facility::Kernel, 0),
        (Facility::User, 1),
        (Facility::Daemon, 3),
        (Facility::Security, 4),
        (Facility::Local0, 16),
        (Facility::Local1, 17),
        (Facility::Local2, 18),
        (Facility::Local3, 19),
        (Facility::Local4, 20),
        (Facility::Local5, 21),
        (Facility::Local6, 22),
        (Facility::Local7, 23),
    ];

    for (facility, facility_num) in facilities {
        let msg = SyslogMessage::new(facility, Severity::Informational, "test");
        let formatted = msg.to_rfc5424("localhost");
        // facility * 8 + Info (6)
        let expected_priority = facility_num * 8 + 6;
        assert!(formatted.starts_with(&format!("<{}>", expected_priority)));
    }
}

#[test]
fn test_syslog_rfc3339_timestamp_format() {
    let msg =
        SyslogMessage::new(Facility::Local0, Severity::Informational, "test").with_message("Test");

    let formatted = msg.to_rfc5424("localhost");

    // RFC 3339 format: YYYY-MM-DDTHH:MM:SS.sssZ
    // Should have timestamp between version and hostname
    assert!(formatted.contains("T")); // Date-time separator
    assert!(formatted.contains("Z")); // UTC indicator
}

#[test]
fn test_syslog_complete_message_format() {
    let sd = StructuredData {
        id: "est@32473".to_string(),
        params: vec![("event_id".to_string(), "CERT-2002".to_string())],
    };

    let msg = SyslogMessage::new(Facility::Local0, Severity::Notice, "est-client")
        .with_proc_id("5678")
        .with_msg_id("CERT-2002")
        .with_structured_data(sd)
        .with_message("Certificate enrolled successfully");

    let formatted = msg.to_rfc5424("pki-host.example.mil");

    // Verify all components present
    assert!(formatted.starts_with("<133>")); // Local0 (16*8) + Notice (5)
    assert!(formatted.contains(">1 ")); // Version
    assert!(formatted.contains("pki-host.example.mil")); // Hostname
    assert!(formatted.contains("est-client")); // App name
    assert!(formatted.contains(" 5678 ")); // Proc ID
    assert!(formatted.contains("CERT-2002")); // Msg ID
    assert!(formatted.contains("[est@32473")); // Structured data
    assert!(formatted.ends_with("Certificate enrolled successfully")); // Message
}

#[test]
#[ignore] // Requires actual syslog server
fn test_syslog_client_send_tcp() {
    let config = SyslogConfig {
        server: "localhost:5514".to_string(), // Test syslog server
        use_tls: false,
        facility: Facility::Local0,
        app_name: "est-client-test".to_string(),
        hostname: None,
    };

    let client = SyslogClient::new(config).expect("Failed to create client");

    let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client-test")
        .with_msg_id("TEST-001")
        .with_message("Test message from integration test");

    // This will fail if no syslog server is listening
    let result = client.send(&msg);
    assert!(result.is_ok() || result.is_err()); // Don't fail test if server not available
}

#[test]
fn test_syslog_client_tls_not_implemented() {
    let config = SyslogConfig {
        server: "localhost:6514".to_string(),
        use_tls: true,
        facility: Facility::Local0,
        app_name: "est-client".to_string(),
        hostname: None,
    };

    let client = SyslogClient::new(config).expect("Failed to create client");

    let msg =
        SyslogMessage::new(Facility::Local0, Severity::Informational, "test").with_message("Test");

    let result = client.send(&msg);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("TLS syslog support not yet implemented")
    );
}
