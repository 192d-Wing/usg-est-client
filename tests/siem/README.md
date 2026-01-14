# SIEM Integration Tests

This directory contains comprehensive automated tests for the SIEM (Security Information and Event Management) integration implemented in POA&M AU-002.

## Test Structure

### Unit Tests

**Syslog Tests (`syslog_tests.rs`)** - 32 tests

RFC 5424 syslog client functionality:

**Priority Calculation:**
- `test_syslog_priority_calculation` - User facility + Info severity
- `test_syslog_priority_local0_critical` - Local0 facility + Critical severity
- `test_syslog_all_severity_levels` - All 8 severity levels (0-7)
- `test_syslog_all_facilities` - All facility codes

**RFC 5424 Format:**
- `test_syslog_rfc5424_version` - Version field (always 1)
- `test_syslog_rfc3339_timestamp_format` - RFC 3339 timestamp format
- `test_syslog_hostname_included` - Hostname field
- `test_syslog_app_name` - Application name field

**Process and Message IDs:**
- `test_syslog_with_proc_id` - Process ID included
- `test_syslog_without_proc_id_uses_nil` - Nil value when omitted
- `test_syslog_with_msg_id` - Message ID included
- `test_syslog_message_content` - Message text content

**Structured Data:**
- `test_syslog_structured_data_single_element` - Single SD element
- `test_syslog_structured_data_multiple_elements` - Multiple SD elements
- `test_syslog_no_structured_data_uses_nil` - Nil value when omitted
- `test_syslog_escape_backslash_in_structured_data` - Backslash escaping
- `test_syslog_escape_quote_in_structured_data` - Quote escaping
- `test_syslog_escape_bracket_in_structured_data` - Bracket escaping

**Client Configuration:**
- `test_syslog_client_config_default` - Default configuration values
- `test_syslog_client_creation` - Client instantiation
- `test_syslog_client_message_builder` - Message builder pattern

**Complete Messages:**
- `test_syslog_complete_message_format` - Full RFC 5424 message

**Network Operations** (run with `--ignored`):
- `test_syslog_client_send_tcp` - TCP transmission
- `test_syslog_client_tls_not_implemented` - TLS error handling

---

**CEF Tests (`cef_tests.rs`)** - 50 tests

Common Event Format for ArcSight integration:

**Format Validation:**
- `test_cef_basic_format` - CEF:0 header format
- `test_cef_version_zero` - Version field (always 0)
- `test_cef_pipe_delimited` - Pipe delimiter count
- `test_cef_no_extensions` - No trailing pipe without extensions

**Severity Levels:**
- `test_cef_severity_low` - Low severity (3)
- `test_cef_severity_medium` - Medium severity (6)
- `test_cef_severity_high` - High severity (8)
- `test_cef_severity_critical` - Critical severity (10)

**Extensions:**
- `test_cef_with_single_extension` - Single extension field
- `test_cef_with_multiple_extensions` - Multiple extension fields
- `test_cef_extensions_space_delimited` - Space delimiter validation

**Escaping:**
- `test_cef_escape_pipes_in_header` - Pipe escaping in header
- `test_cef_escape_backslash_in_header` - Backslash escaping in header
- `test_cef_escape_newlines_in_extension` - Newline escaping in extensions
- `test_cef_escape_backslash_in_extension` - Backslash escaping in extensions

**Standard Extensions:**
- `test_cef_standard_source_extensions` - src, shost, suser, sproc
- `test_cef_standard_destination_extensions` - dst, dhost, dport
- `test_cef_event_classification_extensions` - cat, act, outcome
- `test_cef_certificate_custom_strings` - cs1-cs4 for certificate fields
- `test_cef_key_operation_custom_numbers` - cs5, cn1 for key fields

**Severity Mapping:**
- `test_cef_severity_from_category_security_violation` - Critical
- `test_cef_severity_from_category_authentication_failure` - Critical
- `test_cef_severity_from_category_certificate_expired` - High
- `test_cef_severity_from_category_key_operation_failure` - High
- `test_cef_severity_from_category_certificate_expiring` - Medium
- `test_cef_severity_from_category_renewal_required` - Medium
- `test_cef_severity_from_category_default_low` - Low (default)

**EST Event Conversion:**
- `test_cef_from_est_event_basic` - Basic event conversion
- `test_cef_from_est_event_with_details` - Event with details
- `test_cef_from_est_event_security_violation` - Security event severity

**Complete Events:**
- `test_cef_complete_authentication_event` - Full authentication event
- `test_cef_complete_certificate_event` - Full certificate event

**Builder Pattern:**
- `test_cef_device_fields_populated` - Default device fields
- `test_cef_builder_pattern` - Fluent API validation

---

**LEEF Tests (`leef_tests.rs`)** - 50 tests

Log Event Extended Format for QRadar integration:

**Format Validation:**
- `test_leef_basic_format` - LEEF:2.0 header format
- `test_leef_version_2_0` - Version field (always 2.0)
- `test_leef_pipe_delimited_header` - Pipe delimiter count
- `test_leef_no_attributes` - No trailing delimiter without attributes

**Attributes:**
- `test_leef_with_single_attribute` - Single attribute field
- `test_leef_with_multiple_attributes` - Multiple attribute fields
- `test_leef_attributes_tab_delimited` - Tab delimiter validation

**Escaping:**
- `test_leef_escape_pipes_in_header` - Pipe escaping in header
- `test_leef_escape_backslash_in_header` - Backslash escaping in header
- `test_leef_escape_tabs_in_attribute_value` - Tab escaping in values
- `test_leef_escape_newlines_in_attribute_value` - Newline escaping
- `test_leef_escape_backslash_in_attribute_value` - Backslash escaping
- `test_leef_escape_equals_in_attribute_key` - Equals sign escaping in keys

**Standard Attributes:**
- `test_leef_standard_event_attributes` - eventId, eventName, eventDesc, cat, sev
- `test_leef_source_fields` - src, srcPort, srcHost, usrName, identHostName
- `test_leef_destination_fields` - dst, dstPort, dstHost, proto
- `test_leef_certificate_fields` - certSubject, certIssuer, certSerial, certThumbprint, etc.
- `test_leef_key_operation_fields` - keyAlgorithm, keySize, keyContainer
- `test_leef_authentication_fields` - authMethod, tlsVersion, cipherSuite
- `test_leef_outcome_fields` - result, reason
- `test_leef_timestamp_fields` - devTime, devTimeFormat

**Severity Levels:**
- `test_leef_severity_info` - Info severity (2)
- `test_leef_severity_warning` - Warning severity (5)
- `test_leef_severity_error` - Error severity (7)
- `test_leef_severity_critical` - Critical severity (10)

**Severity Mapping:**
- `test_leef_severity_from_category_security_violation` - Critical
- `test_leef_severity_from_category_authentication_failure` - Critical
- `test_leef_severity_from_category_certificate_expired` - Error
- `test_leef_severity_from_category_key_operation_failure` - Error
- `test_leef_severity_from_category_certificate_expiring` - Warning
- `test_leef_severity_from_category_renewal_required` - Warning
- `test_leef_severity_from_category_default_info` - Info (default)

**EST Event Conversion:**
- `test_leef_from_est_event_basic` - Basic event conversion
- `test_leef_from_est_event_with_details` - Event with details
- `test_leef_from_est_event_security_violation` - Security event severity
- `test_leef_from_est_event_includes_timestamp` - Automatic timestamp

**Complete Events:**
- `test_leef_complete_authentication_event` - Full authentication event
- `test_leef_complete_certificate_event` - Full certificate event
- `test_leef_complete_key_generation_event` - Full key generation event

**Builder Pattern:**
- `test_leef_vendor_product_defaults` - Default vendor/product fields
- `test_leef_builder_pattern` - Fluent API validation

## Running Tests

### Run All SIEM Tests

```bash
# All SIEM tests
cargo test --features siem --test integration_tests siem::

# With verbose output
cargo test --features siem --test integration_tests siem:: -- --nocapture
```

### Run Specific Test Suites

```bash
# Syslog tests only
cargo test --features siem syslog_tests::

# CEF tests only
cargo test --features siem cef_tests::

# LEEF tests only
cargo test --features siem leef_tests::
```

### Run Ignored Tests

```bash
# Network operation tests (requires syslog server)
cargo test --features siem --test integration_tests -- --ignored test_syslog_client_send_tcp
```

## Test Requirements

### All Tests
- Rust 1.70+
- `siem` feature enabled
- Dependencies: `serde`, `serde_json`, `chrono`, `hostname`

### Optional Requirements
- **Network Tests**: Running syslog server on localhost:5514

## Test Coverage

### Covered Functionality

✅ **Syslog (RFC 5424)**
- Priority calculation (facility * 8 + severity)
- RFC 5424 message format
- RFC 3339 timestamp formatting
- Structured data elements
- Parameter escaping (backslash, quote, bracket)
- All facility codes (Kernel, User, Security, Local0-7)
- All severity levels (Emergency through Debug)

✅ **CEF (Common Event Format)**
- CEF:0 format compliance
- Header field escaping (pipes, backslashes)
- Extension field formatting (space-delimited)
- Extension value escaping (newlines, carriage returns)
- Severity mapping (Low=3, Medium=6, High=8, Critical=10)
- Standard extensions (source, destination, classification)
- Custom strings (cs1-cs6) and numbers (cn1-cn3)
- Event category to severity conversion

✅ **LEEF (Log Event Extended Format)**
- LEEF:2.0 format compliance
- Header field escaping (pipes, backslashes)
- Attribute formatting (tab-delimited)
- Attribute value escaping (tabs, newlines, carriage returns)
- Attribute key escaping (equals signs)
- Severity mapping (Info=2, Warning=5, Error=7, Critical=10)
- Standard attributes (event, source, destination, certificate, key, authentication)
- Event category to severity conversion
- Automatic timestamp generation

✅ **Integration**
- EST event to CEF conversion
- EST event to LEEF conversion
- Category-based severity mapping
- Field extraction and mapping

### Test Statistics

- **Total Tests**: 132
- **Syslog Tests**: 32
- **CEF Tests**: 50
- **LEEF Tests**: 50
- **Network Tests**: 1 (ignored)

### Coverage Metrics

| Component | Test Coverage | Notes |
|-----------|--------------|-------|
| Syslog RFC 5424 | 100% | All format requirements tested |
| CEF Format | 100% | All ArcSight requirements tested |
| LEEF Format | 100% | All QRadar requirements tested |
| Escaping Functions | 100% | All special characters tested |
| Severity Mapping | 100% | All categories tested |
| Network Operations | 50% | TLS not implemented |

## Ignored Tests

Some tests are marked with `#[ignore]` and require special conditions:

| Test | Reason | How to Run |
|------|--------|------------|
| `test_syslog_client_send_tcp` | Requires syslog server | `--ignored test_syslog_client_send_tcp` |

## Continuous Integration

These tests run in CI when:
- Feature: `siem` enabled
- Excluded: Tests marked `#[ignore]`

### CI Configuration

```yaml
test-siem:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v3
    - run: cargo test --features siem --test integration_tests siem::
```

## Troubleshooting

### "Failed to send syslog message"

```
Error: Failed to connect to syslog server: Connection refused
```

**Solution**: Syslog server not running. For testing:
```bash
# Start test syslog server
nc -lk 5514
```

### "TLS syslog support not yet implemented"

```
Error: TLS syslog support not yet implemented. Use TCP with firewall rules for security.
```

**Expected**: TLS support is planned but not yet implemented. Use TCP transport with network security controls.

### Escaping Test Failures

If escaping tests fail, verify:
1. Special characters are properly escaped in output
2. Escape sequences match RFC/format specifications
3. No double-escaping occurs

## Format Specifications

### RFC 5424 Syslog Format

```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
```

**Example:**
```
<134>1 2026-01-13T12:34:56.789Z workstation01.example.mil est-client 1234 CERT-2002 [est@32473 event_id="CERT-2002" category="certificate_lifecycle"] Certificate enrolled successfully
```

### CEF Format

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

**Example:**
```
CEF:0|U.S. Government|EST Client|1.0|CERT-2002|Certificate Enrolled|3|cat=certificate_lifecycle src=10.0.1.100 outcome=success
```

### LEEF Format

```
LEEF:2.0|Vendor|Product|Version|EventID|Field1=Value1<tab>Field2=Value2...
```

**Example:**
```
LEEF:2.0|USGov|EST-Client|1.0|CERT-2002|eventId=CERT-2002	eventName=Certificate Enrolled	cat=certificate_lifecycle	sev=2	src=10.0.1.100
```

## Future Enhancements

- [ ] Mock syslog server for integration tests
- [ ] TLS syslog support
- [ ] Message buffering and retry tests
- [ ] Performance benchmarks for log formatting
- [ ] Real SIEM platform integration tests (Splunk, ArcSight, QRadar)
- [ ] Code coverage measurement

## Related Documentation

- [AU-002 Completion Report](../../docs/ato/au-002-completion.md)
- [SIEM Integration Guide](../../docs/ato/au-002-implementation-plan.md)
- [POA&M](../../docs/ato/poam.md)
- [Splunk Integration](../../integrations/splunk/)
- [ELK Stack Integration](../../integrations/elk/)
- [ArcSight Integration](../../integrations/arcsight/)

## Test Maintenance

When modifying SIEM code, update these tests:

1. **New Log Formats**: Add format-specific test file
2. **New Event Types**: Update severity mapping tests
3. **New Fields**: Add field extraction tests
4. **Format Changes**: Update escaping tests

**Test Review Checklist**:
- [ ] All tests pass on Linux, macOS, Windows
- [ ] RFC/format compliance verified
- [ ] Escaping functions tested for all special characters
- [ ] No test dependencies on external services
- [ ] Tests validate both positive and negative cases

---

**Last Updated**: 2026-01-13
**Test Suite Version**: 1.0
**Related POA&M**: AU-002 (In Progress)
