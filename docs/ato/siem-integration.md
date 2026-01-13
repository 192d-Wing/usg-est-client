# SIEM Integration and Audit Logging Guide

## EST Client Library for Windows

**Version:** 1.0
**Date:** 2026-01-13
**Classification:** UNCLASSIFIED

---

## 1. Overview

This document provides guidance for integrating the EST Client with Security Information and Event Management (SIEM) solutions commonly used in Department of Defense and federal environments. It covers enhanced audit logging, structured log formats, and integration patterns for enterprise security monitoring.

### 1.1 Purpose

The EST Client generates comprehensive audit logs for security-relevant events. This guide helps security teams:

- Configure enhanced audit logging
- Integrate with enterprise SIEM platforms
- Create security monitoring dashboards
- Establish alerting rules for critical events
- Meet NIST SP 800-53 AU family requirements

### 1.2 Scope

**SIEM Platforms Covered:**
- Splunk Enterprise
- Elastic Stack (ELK)
- ArcSight Enterprise Security Manager (ESM)
- QRadar SIEM
- Generic syslog collectors

**Audit Events Covered:**
- Certificate enrollment and renewal
- Authentication events
- Certificate validation and revocation checking
- Key generation and operations
- Configuration changes
- Security violations and errors

---

## 2. Audit Event Taxonomy

### 2.1 Event Categories

The EST Client generates audit events in the following categories:

| Category | Event Count | Criticality | STIG Mapping |
|----------|-------------|-------------|--------------|
| Authentication | 6 | HIGH | APSC-DV-000160 |
| Certificate Lifecycle | 8 | MEDIUM | APSC-DV-002560 |
| Key Operations | 5 | HIGH | APSC-DV-002520 |
| Validation | 7 | MEDIUM | APSC-DV-003235 |
| Configuration | 4 | MEDIUM | APSC-DV-000020 |
| Security Violations | 6 | CRITICAL | Multiple |
| System Events | 5 | LOW | APSC-DV-000050 |

### 2.2 Authentication Events

**Event ID Range:** AUTH-1000 to AUTH-1999

| Event ID | Event Name | Description | Severity |
|----------|-----------|-------------|----------|
| AUTH-1001 | Authentication Success | Successful EST server authentication | INFO |
| AUTH-1002 | Authentication Failure | Failed EST server authentication | WARNING |
| AUTH-1003 | Authentication Lockout | Account locked due to failed attempts | CRITICAL |
| AUTH-1010 | TLS Handshake Success | Successful TLS connection established | INFO |
| AUTH-1011 | TLS Handshake Failure | TLS connection failed | ERROR |
| AUTH-1020 | Certificate Auth Success | Client certificate authentication succeeded | INFO |
| AUTH-1021 | Certificate Auth Failure | Client certificate authentication failed | WARNING |

**Example Event (JSON):**
```json
{
  "timestamp": "2026-01-13T15:30:45.123Z",
  "event_id": "AUTH-1001",
  "event_name": "Authentication Success",
  "severity": "INFO",
  "category": "authentication",
  "source": {
    "host": "WORKSTATION01.example.mil",
    "ip": "10.0.1.100",
    "user": "WORKSTATION01$",
    "process": "est-client.exe",
    "pid": 1234
  },
  "target": {
    "url": "https://est.example.mil/.well-known/est",
    "host": "est.example.mil",
    "port": 443
  },
  "details": {
    "auth_method": "http_basic",
    "tls_version": "TLS 1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384"
  },
  "outcome": "success",
  "stig_id": "APSC-DV-000160"
}
```

### 2.3 Certificate Lifecycle Events

**Event ID Range:** CERT-2000 to CERT-2999

| Event ID | Event Name | Description | Severity |
|----------|-----------|-------------|----------|
| CERT-2001 | Enrollment Request | Certificate enrollment initiated | INFO |
| CERT-2002 | Enrollment Success | Certificate successfully enrolled | INFO |
| CERT-2003 | Enrollment Failure | Certificate enrollment failed | ERROR |
| CERT-2010 | Renewal Check | Certificate renewal check performed | DEBUG |
| CERT-2011 | Renewal Required | Certificate requires renewal | WARNING |
| CERT-2012 | Renewal Success | Certificate successfully renewed | INFO |
| CERT-2013 | Renewal Failure | Certificate renewal failed | ERROR |
| CERT-2020 | Certificate Expiring | Certificate expiring within threshold | WARNING |
| CERT-2021 | Certificate Expired | Certificate has expired | CRITICAL |
| CERT-2030 | Certificate Installed | Certificate installed in cert store | INFO |
| CERT-2031 | Certificate Archived | Old certificate archived | INFO |

**Example Event (JSON):**
```json
{
  "timestamp": "2026-01-13T15:31:20.456Z",
  "event_id": "CERT-2002",
  "event_name": "Enrollment Success",
  "severity": "INFO",
  "category": "certificate_lifecycle",
  "source": {
    "host": "WORKSTATION01.example.mil",
    "ip": "10.0.1.100"
  },
  "certificate": {
    "subject": "CN=WORKSTATION01.example.mil, O=Department of War, C=US",
    "serial": "1A:2B:3C:4D:5E:6F",
    "issuer": "CN=DoD Root CA 3, O=U.S. Government, C=US",
    "not_before": "2026-01-13T15:31:00Z",
    "not_after": "2027-01-13T15:31:00Z",
    "key_algorithm": "RSA",
    "key_size": 3072,
    "signature_algorithm": "SHA256-RSA"
  },
  "details": {
    "enrollment_type": "initial",
    "san_dns": ["WORKSTATION01.example.mil", "WORKSTATION01"],
    "key_usage": ["digitalSignature", "keyEncipherment"],
    "extended_key_usage": ["clientAuth", "serverAuth"]
  },
  "outcome": "success",
  "stig_id": "APSC-DV-002560"
}
```

### 2.4 Key Operations Events

**Event ID Range:** KEY-3000 to KEY-3999

| Event ID | Event Name | Description | Severity |
|----------|-----------|-------------|----------|
| KEY-3001 | Key Generation Started | Private key generation initiated | INFO |
| KEY-3002 | Key Generation Success | Private key successfully generated | INFO |
| KEY-3003 | Key Generation Failure | Private key generation failed | ERROR |
| KEY-3010 | Key Storage Success | Private key stored securely | INFO |
| KEY-3011 | Key Storage Failure | Private key storage failed | CRITICAL |
| KEY-3020 | Key Access | Private key accessed for operation | DEBUG |
| KEY-3021 | Key Access Denied | Unauthorized key access attempt | CRITICAL |

**Example Event (JSON):**
```json
{
  "timestamp": "2026-01-13T15:30:50.789Z",
  "event_id": "KEY-3002",
  "event_name": "Key Generation Success",
  "severity": "INFO",
  "category": "key_operations",
  "source": {
    "host": "WORKSTATION01.example.mil",
    "process": "est-client.exe"
  },
  "key": {
    "algorithm": "RSA",
    "size": 3072,
    "type": "private",
    "fips_mode": true,
    "provider": "OpenSSL FIPS"
  },
  "details": {
    "generation_time_ms": 234,
    "entropy_source": "CNG",
    "key_id": "a1b2c3d4e5f6..."
  },
  "outcome": "success",
  "stig_id": "APSC-DV-002520"
}
```

### 2.5 Validation Events

**Event ID Range:** VAL-4000 to VAL-4999

| Event ID | Event Name | Description | Severity |
|----------|-----------|-------------|----------|
| VAL-4001 | Chain Validation Success | Certificate chain validated successfully | INFO |
| VAL-4002 | Chain Validation Failure | Certificate chain validation failed | ERROR |
| VAL-4010 | Revocation Check Success | Certificate revocation check passed | INFO |
| VAL-4011 | Revocation Check Failure | Certificate revocation check failed | ERROR |
| VAL-4012 | Certificate Revoked | Certificate is revoked | CRITICAL |
| VAL-4020 | OCSP Request | OCSP revocation check initiated | DEBUG |
| VAL-4021 | OCSP Response Good | OCSP: Certificate is valid | INFO |
| VAL-4022 | OCSP Response Revoked | OCSP: Certificate is revoked | CRITICAL |
| VAL-4030 | CRL Download | CRL download initiated | DEBUG |
| VAL-4031 | CRL Validation Success | CRL signature validated | INFO |

**Example Event (JSON):**
```json
{
  "timestamp": "2026-01-13T15:31:15.234Z",
  "event_id": "VAL-4001",
  "event_name": "Chain Validation Success",
  "severity": "INFO",
  "category": "validation",
  "certificate": {
    "subject": "CN=est.example.mil, O=Department of War, C=US",
    "serial": "7A:8B:9C:0D:1E:2F",
    "issuer": "CN=DoD Root CA 3, O=U.S. Government, C=US"
  },
  "chain": {
    "depth": 3,
    "root_ca": "CN=DoD Root CA 3",
    "intermediate_cas": [
      "CN=DoD Issuing CA-1"
    ]
  },
  "validation": {
    "trust_anchor": "DoD Root CA Bundle",
    "policy_check": true,
    "revocation_check": true,
    "hostname_verification": true
  },
  "outcome": "success",
  "stig_id": "APSC-DV-003235"
}
```

### 2.6 Configuration Events

**Event ID Range:** CFG-5000 to CFG-5999

| Event ID | Event Name | Description | Severity |
|----------|-----------|-------------|----------|
| CFG-5001 | Configuration Loaded | Configuration file loaded successfully | INFO |
| CFG-5002 | Configuration Error | Configuration file has errors | ERROR |
| CFG-5010 | Configuration Changed | Configuration file modified | WARNING |
| CFG-5020 | FIPS Mode Enabled | FIPS 140-2 mode activated | INFO |
| CFG-5021 | FIPS Mode Failed | FIPS 140-2 mode activation failed | CRITICAL |

### 2.7 Security Violation Events

**Event ID Range:** SEC-6000 to SEC-6999

| Event ID | Event Name | Description | Severity |
|----------|-----------|-------------|----------|
| SEC-6001 | Weak Algorithm Blocked | Attempted use of weak algorithm | CRITICAL |
| SEC-6002 | Invalid Certificate | Invalid certificate detected | ERROR |
| SEC-6003 | TLS Downgrade Attempt | TLS version downgrade attempted | CRITICAL |
| SEC-6010 | Access Control Violation | File/resource access denied | WARNING |
| SEC-6020 | Integrity Check Failure | File or data integrity check failed | CRITICAL |
| SEC-6030 | Unauthorized Configuration | Unauthorized config change attempt | CRITICAL |

---

## 3. Log Formats

### 3.1 JSON Format (Recommended)

**Configuration:**
```toml
[logging.file]
format = "json"
```

**Advantages:**
- Machine-parseable
- Structured data
- Easy SIEM ingestion
- Rich context

**Example:**
```json
{
  "timestamp": "2026-01-13T15:30:45.123Z",
  "level": "INFO",
  "event_id": "CERT-2002",
  "category": "certificate_lifecycle",
  "message": "Certificate enrollment successful",
  "fields": {
    "host": "WORKSTATION01.example.mil",
    "subject": "CN=WORKSTATION01.example.mil",
    "serial": "1A:2B:3C:4D:5E:6F"
  }
}
```

### 3.2 CEF Format (Common Event Format)

**Use Case:** ArcSight, QRadar, and CEF-compatible SIEMs

**Configuration:**
```toml
[logging.siem]
enabled = true
format = "CEF"
server = "siem.example.mil"
port = 514
protocol = "TCP"
```

**Format Specification:**
```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

**Example:**
```
CEF:0|Department of War|EST Client|1.0|CERT-2002|Certificate Enrollment Success|5|src=10.0.1.100 shost=WORKSTATION01.example.mil dhost=est.example.mil dport=443 outcome=success cs1=CN=WORKSTATION01.example.mil cs1Label=Subject cs2=1A:2B:3C:4D:5E:6F cs2Label=Serial
```

### 3.3 LEEF Format (Log Event Extended Format)

**Use Case:** QRadar SIEM

**Format Specification:**
```
LEEF:Version|Vendor|Product|Version|EventID|Tab-delimited fields
```

**Example:**
```
LEEF:2.0|Department of War|EST Client|1.0|CERT-2002|devTime=Jan 13 2026 15:30:45	severity=5	src=10.0.1.100	shost=WORKSTATION01.example.mil	dst=est.example.mil	dstPort=443	eventId=CERT-2002	cat=certificate_lifecycle	msg=Certificate enrollment successful	subject=CN=WORKSTATION01.example.mil	serial=1A:2B:3C:4D:5E:6F
```

### 3.4 Syslog Format (RFC 5424)

**Use Case:** Generic syslog collectors, Splunk, rsyslog

**Configuration:**
```toml
[logging.syslog]
enabled = true
server = "syslog.example.mil"
port = 514
protocol = "TCP"  # or "TLS" for RFC 5425
facility = "local0"
```

**Format:**
```
<134>1 2026-01-13T15:30:45.123Z WORKSTATION01.example.mil est-client 1234 CERT-2002 [meta category="certificate_lifecycle" severity="INFO"] Certificate enrollment successful: CN=WORKSTATION01.example.mil
```

---

## 4. Splunk Integration

### 4.1 Architecture Overview

```
┌─────────────────┐
│  EST Client     │
│  (Windows Host) │
│                 │
│  Logs:          │
│  est-client.log │
└────────┬────────┘
         │
         │ monitors
         ▼
┌─────────────────┐
│ Splunk          │
│ Universal       │
│ Forwarder       │
└────────┬────────┘
         │
         │ forwards
         ▼
┌─────────────────┐      ┌──────────────┐
│ Splunk Indexer  │◄─────┤ Heavy        │
│                 │      │ Forwarder    │
│ Index: est      │      │ (optional)   │
└────────┬────────┘      └──────────────┘
         │
         │
         ▼
┌─────────────────┐
│ Splunk Search   │
│ Head / ES       │
│                 │
│ Dashboards      │
│ Alerts          │
└─────────────────┘
```

### 4.2 Splunk Universal Forwarder Configuration

**Install Location:** Same Windows host as EST Client

**inputs.conf:**
```ini
[monitor://C:\ProgramData\Department of War\EST\logs\est-client.log]
disabled = false
sourcetype = est:json
index = est
host = $decideOnStartup

# Optional: Monitor Windows Event Log (when Windows Event Log integration available)
[WinEventLog://Application]
disabled = false
index = est
sourcetype = WinEventLog:Application
whitelist = Source="EST Client"
```

**props.conf (on indexer or heavy forwarder):**
```ini
[est:json]
SHOULD_LINEMERGE = false
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3NZ
MAX_TIMESTAMP_LOOKAHEAD = 28
TRUNCATE = 0
KV_MODE = json

# Field extractions
EVAL-vendor = "Department of War"
EVAL-product = "EST Client"
EVAL-app = "est-client"

# CIM compliance (Common Information Model)
FIELDALIAS-dest = target.host AS dest
FIELDALIAS-src = source.host AS src
FIELDALIAS-user = source.user AS user
FIELDALIAS-signature = event_id AS signature
FIELDALIAS-signature_id = event_id AS signature_id
```

**transforms.conf:**
```ini
[est_severity_lookup]
filename = est_severity.csv
max_matches = 1
min_matches = 1
default_match = unknown

[est_category_lookup]
filename = est_category.csv
max_matches = 1
min_matches = 1
default_match = other
```

### 4.3 Splunk Queries

**Certificate Enrollment Activity:**
```spl
index=est sourcetype=est:json category=certificate_lifecycle
| stats count by event_name, outcome, source.host
| sort -count
```

**Authentication Failures (Last 24 Hours):**
```spl
index=est sourcetype=est:json category=authentication outcome=failure earliest=-24h
| stats count by source.host, target.host, details.auth_method
| where count > 3
| sort -count
```

**Certificate Expiration Monitoring:**
```spl
index=est sourcetype=est:json event_id=CERT-2020 OR event_id=CERT-2021
| eval days_until_expiry = round((strptime(certificate.not_after, "%Y-%m-%dT%H:%M:%SZ") - now()) / 86400, 0)
| table _time, source.host, certificate.subject, certificate.not_after, days_until_expiry
| sort days_until_expiry
```

**Security Violations (Real-time):**
```spl
index=est sourcetype=est:json category=security_violations severity=CRITICAL
| table _time, event_name, source.host, details.*
```

**FIPS Mode Violations:**
```spl
index=est sourcetype=est:json event_id=SEC-6001
| stats count by source.host, details.blocked_algorithm
| sort -count
```

**Top 10 Hosts by Certificate Renewals:**
```spl
index=est sourcetype=est:json event_id=CERT-2012 earliest=-30d
| stats count by source.host
| sort -count
| head 10
```

### 4.4 Splunk Dashboard (XML)

**Save as:** `est_client_overview.xml`

```xml
<dashboard version="1.1">
  <label>EST Client - Security Overview</label>
  <description>Certificate lifecycle and security monitoring for EST Client</description>

  <row>
    <panel>
      <title>Certificate Enrollments (24h)</title>
      <single>
        <search>
          <query>
index=est sourcetype=est:json event_id=CERT-2002 earliest=-24h
| stats count
          </query>
        </search>
        <option name="drilldown">all</option>
        <option name="colorMode">block</option>
        <option name="rangeColors">["0x65A637","0x6DB7C6"]</option>
        <option name="underLabel">Successful Enrollments</option>
      </single>
    </panel>

    <panel>
      <title>Enrollment Failures (24h)</title>
      <single>
        <search>
          <query>
index=est sourcetype=est:json event_id=CERT-2003 earliest=-24h
| stats count
          </query>
        </search>
        <option name="drilldown">all</option>
        <option name="colorMode">block</option>
        <option name="rangeColors">["0x65A637","0xD93F3C"]</option>
        <option name="rangeValues">[0]</option>
        <option name="underLabel">Failed Enrollments</option>
      </single>
    </panel>

    <panel>
      <title>Certificates Expiring Soon</title>
      <single>
        <search>
          <query>
index=est sourcetype=est:json event_id=CERT-2020
| dedup source.host
| stats count
          </query>
        </search>
        <option name="drilldown">all</option>
        <option name="colorMode">block</option>
        <option name="rangeColors">["0x65A637","0xF7BC38","0xD93F3C"]</option>
        <option name="rangeValues">[5,20]</option>
        <option name="underLabel">Hosts with Expiring Certs</option>
      </single>
    </panel>

    <panel>
      <title>Security Violations (24h)</title>
      <single>
        <search>
          <query>
index=est sourcetype=est:json category=security_violations earliest=-24h
| stats count
          </query>
        </search>
        <option name="drilldown">all</option>
        <option name="colorMode">block</option>
        <option name="rangeColors">["0x65A637","0xD93F3C"]</option>
        <option name="rangeValues">[0]</option>
        <option name="underLabel">Critical Security Events</option>
      </single>
    </panel>
  </row>

  <row>
    <panel>
      <title>Enrollment Success Rate (7 days)</title>
      <chart>
        <search>
          <query>
index=est sourcetype=est:json (event_id=CERT-2002 OR event_id=CERT-2003) earliest=-7d
| timechart span=1h count by outcome
          </query>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Authentication Events by Host</title>
      <chart>
        <search>
          <query>
index=est sourcetype=est:json category=authentication earliest=-24h
| stats count by source.host, outcome
| xyseries source.host outcome count
          </query>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>

    <panel>
      <title>Certificate Lifecycle Events</title>
      <chart>
        <search>
          <query>
index=est sourcetype=est:json category=certificate_lifecycle earliest=-24h
| stats count by event_name
| sort -count
          </query>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Recent Certificate Operations</title>
      <table>
        <search>
          <query>
index=est sourcetype=est:json category=certificate_lifecycle earliest=-1h
| table _time, source.host, event_name, outcome, certificate.subject, certificate.serial
| sort -_time
| head 20
          </query>
        </search>
        <option name="drilldown">row</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Certificates by Expiration Status</title>
      <table>
        <search>
          <query>
index=est sourcetype=est:json event_id=CERT-2020 OR event_id=CERT-2021
| eval days_until_expiry = round((strptime(certificate.not_after, "%Y-%m-%dT%H:%M:%SZ") - now()) / 86400, 0)
| eval status = case(
    days_until_expiry < 0, "EXPIRED",
    days_until_expiry < 7, "CRITICAL",
    days_until_expiry < 30, "WARNING",
    1=1, "OK"
  )
| table source.host, certificate.subject, certificate.not_after, days_until_expiry, status
| sort days_until_expiry
          </query>
        </search>
        <option name="drilldown">row</option>
        <format type="color" field="status">
          <colorPalette type="map">{"EXPIRED":#D93F3C,"CRITICAL":#F7BC38,"WARNING":#F58F39,"OK":#65A637}</colorPalette>
        </format>
      </table>
    </panel>
  </row>
</dashboard>
```

### 4.5 Splunk Alerts

**Alert 1: Certificate Enrollment Failure**
```spl
index=est sourcetype=est:json event_id=CERT-2003
| stats count by source.host
| where count > 3
```
- **Trigger:** More than 3 enrollment failures for a host in 1 hour
- **Severity:** HIGH
- **Action:** Email ISSO, create ticket

**Alert 2: Certificate Expiring Within 7 Days**
```spl
index=est sourcetype=est:json event_id=CERT-2020
| eval days_until_expiry = round((strptime(certificate.not_after, "%Y-%m-%dT%H:%M:%SZ") - now()) / 86400, 0)
| where days_until_expiry <= 7
```
- **Trigger:** Certificate expiring in 7 days or less
- **Severity:** MEDIUM
- **Action:** Email system owner

**Alert 3: Security Violation**
```spl
index=est sourcetype=est:json category=security_violations severity=CRITICAL
```
- **Trigger:** Any critical security violation
- **Severity:** CRITICAL
- **Action:** Page security team, email ISSO

**Alert 4: FIPS Mode Failure**
```spl
index=est sourcetype=est:json event_id=CFG-5021
```
- **Trigger:** FIPS mode activation failure
- **Severity:** CRITICAL
- **Action:** Page security team, halt operations

---

## 5. Elastic Stack (ELK) Integration

### 5.1 Architecture Overview

```
┌─────────────────┐
│  EST Client     │
│  (Windows Host) │
│                 │
│  Logs:          │
│  est-client.log │
└────────┬────────┘
         │
         │ ships
         ▼
┌─────────────────┐
│  Filebeat       │
│  (Windows)      │
│                 │
│  Module: custom │
└────────┬────────┘
         │
         │ forwards
         ▼
┌─────────────────┐
│  Logstash       │
│                 │
│  Pipeline:      │
│  est-client     │
└────────┬────────┘
         │
         │ indexes
         ▼
┌─────────────────┐
│  Elasticsearch  │
│                 │
│  Index:         │
│  est-client-*   │
└────────┬────────┘
         │
         │ visualizes
         ▼
┌─────────────────┐
│  Kibana         │
│                 │
│  Dashboards     │
│  Discover       │
└─────────────────┘
```

### 5.2 Filebeat Configuration

**filebeat.yml:**
```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - C:\ProgramData\Department of War\EST\logs\est-client.log

  # JSON parsing
  json.keys_under_root: true
  json.add_error_key: true
  json.message_key: message

  # Additional fields
  fields:
    service: est-client
    environment: production
    classification: unclassified

  # Multiline handling (in case JSON spans multiple lines)
  multiline.type: pattern
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after

# Logstash output
output.logstash:
  hosts: ["logstash.example.mil:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["C:\\ProgramData\\Elastic\\ca.pem"]
  ssl.certificate: "C:\\ProgramData\\Elastic\\filebeat.crt"
  ssl.key: "C:\\ProgramData\\Elastic\\filebeat.key"

# Processor pipeline
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~

  # Drop debug events (optional)
  - drop_event:
      when:
        equals:
          severity: DEBUG

# Monitoring
monitoring.enabled: true
monitoring.elasticsearch:
  hosts: ["https://es.example.mil:9200"]
```

### 5.3 Logstash Pipeline

**est-client.conf:**
```ruby
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key => "/etc/logstash/certs/logstash.key"
    ssl_certificate_authorities => ["/etc/logstash/certs/ca.pem"]
  }
}

filter {
  # Already parsed as JSON by Filebeat

  # Parse timestamp
  date {
    match => [ "timestamp", "ISO8601" ]
    target => "@timestamp"
  }

  # Add ECS fields (Elastic Common Schema)
  mutate {
    rename => {
      "source.host" => "[host][hostname]"
      "source.ip" => "[host][ip]"
      "target.host" => "[destination][domain]"
      "target.port" => "[destination][port]"
    }

    add_field => {
      "[ecs][version]" => "8.0"
      "[event][dataset]" => "est.client"
      "[event][module]" => "est"
    }
  }

  # Convert severity to numeric level
  translate {
    field => "severity"
    destination => "[log][level_value]"
    dictionary => {
      "TRACE" => "10"
      "DEBUG" => "20"
      "INFO" => "30"
      "WARNING" => "40"
      "ERROR" => "50"
      "CRITICAL" => "60"
    }
    fallback => "30"
  }

  # Event categorization (ECS)
  if [category] == "authentication" {
    mutate {
      add_field => {
        "[event][category]" => "authentication"
        "[event][type]" => "info"
      }
    }
  } else if [category] == "certificate_lifecycle" {
    mutate {
      add_field => {
        "[event][category]" => "iam"
        "[event][type]" => "change"
      }
    }
  } else if [category] == "security_violations" {
    mutate {
      add_field => {
        "[event][category]" => "intrusion_detection"
        "[event][type]" => "denied"
        "[event][kind]" => "alert"
      }
    }
  }

  # GeoIP enrichment (optional)
  if [host][ip] {
    geoip {
      source => "[host][ip]"
      target => "[host][geo]"
    }
  }

  # STIG tagging
  if [stig_id] {
    mutate {
      add_tag => [ "stig_compliance", "%{stig_id}" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://es.example.mil:9200"]
    index => "est-client-%{+YYYY.MM.dd}"
    user => "logstash_writer"
    password => "${LOGSTASH_ES_PASSWORD}"
    ssl => true
    cacert => "/etc/logstash/certs/ca.pem"

    # Index lifecycle management
    ilm_enabled => true
    ilm_rollover_alias => "est-client"
    ilm_pattern => "000001"
    ilm_policy => "est-client-policy"
  }

  # Debug output (optional)
  # stdout { codec => rubydebug }
}
```

### 5.4 Elasticsearch Index Template

**est-client-template.json:**
```json
{
  "index_patterns": ["est-client-*"],
  "template": {
    "settings": {
      "number_of_shards": 3,
      "number_of_replicas": 1,
      "index.lifecycle.name": "est-client-policy",
      "index.lifecycle.rollover_alias": "est-client"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "event_id": { "type": "keyword" },
        "event_name": { "type": "text", "fields": {"keyword": {"type": "keyword"}} },
        "severity": { "type": "keyword" },
        "category": { "type": "keyword" },
        "outcome": { "type": "keyword" },
        "stig_id": { "type": "keyword" },
        "message": { "type": "text" },

        "host": {
          "properties": {
            "hostname": { "type": "keyword" },
            "ip": { "type": "ip" }
          }
        },

        "destination": {
          "properties": {
            "domain": { "type": "keyword" },
            "port": { "type": "integer" }
          }
        },

        "certificate": {
          "properties": {
            "subject": { "type": "keyword" },
            "serial": { "type": "keyword" },
            "issuer": { "type": "keyword" },
            "not_before": { "type": "date" },
            "not_after": { "type": "date" },
            "key_algorithm": { "type": "keyword" },
            "key_size": { "type": "integer" }
          }
        },

        "details": {
          "type": "object",
          "enabled": true
        }
      }
    }
  },
  "priority": 200,
  "version": 1,
  "_meta": {
    "description": "Template for EST Client audit logs"
  }
}
```

**Load template:**
```bash
curl -X PUT "https://es.example.mil:9200/_index_template/est-client" \
  -H "Content-Type: application/json" \
  -u elastic:$ES_PASSWORD \
  --cacert /path/to/ca.pem \
  -d @est-client-template.json
```

### 5.5 Index Lifecycle Management (ILM) Policy

**est-client-policy.json:**
```json
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_age": "7d",
            "max_size": "50gb"
          },
          "set_priority": {
            "priority": 100
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          },
          "forcemerge": {
            "max_num_segments": 1
          },
          "set_priority": {
            "priority": 50
          }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "freeze": {},
          "set_priority": {
            "priority": 0
          }
        }
      },
      "delete": {
        "min_age": "365d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

**Load policy:**
```bash
curl -X PUT "https://es.example.mil:9200/_ilm/policy/est-client-policy" \
  -H "Content-Type: application/json" \
  -u elastic:$ES_PASSWORD \
  --cacert /path/to/ca.pem \
  -d @est-client-policy.json
```

### 5.6 Kibana Queries (KQL)

**Certificate Enrollment Failures:**
```
event_id: "CERT-2003" and outcome: "failure"
```

**Authentication Events (Last Hour):**
```
category: "authentication" and @timestamp >= now-1h
```

**Certificates Expiring Soon:**
```
event_id: "CERT-2020" or event_id: "CERT-2021"
```

**Security Violations:**
```
category: "security_violations" and severity: "CRITICAL"
```

**Host-Specific Events:**
```
host.hostname: "WORKSTATION01.example.mil"
```

**STIG Compliance Check:**
```
tags: "stig_compliance" and stig_id: "APSC-DV-*"
```

### 5.7 Kibana Visualization Examples

**1. Certificate Operations Timeline**
- **Type:** Area chart
- **X-axis:** @timestamp (Date Histogram)
- **Y-axis:** Count
- **Split series:** event_name.keyword
- **Filter:** category: "certificate_lifecycle"

**2. Authentication Success Rate**
- **Type:** Pie chart
- **Slice by:** outcome.keyword
- **Filter:** category: "authentication"

**3. Top Hosts by Activity**
- **Type:** Horizontal bar chart
- **Y-axis:** host.hostname.keyword (Top 10)
- **X-axis:** Count

**4. Security Violations Heatmap**
- **Type:** Heat map
- **X-axis:** @timestamp (Date Histogram, hourly)
- **Y-axis:** event_id.keyword
- **Cell value:** Count
- **Filter:** category: "security_violations"

---

## 6. Syslog Forwarding

### 6.1 Configuration

**EST Client Configuration (dod-hardened.toml):**
```toml
[logging.syslog]
enabled = true
server = "syslog.example.mil"
port = 514
protocol = "TCP"  # or "TLS" for RFC 5425
facility = "local0"
format = "rfc5424"
```

### 6.2 rsyslog Configuration (Linux SIEM)

**/etc/rsyslog.d/50-est-client.conf:**
```
# Receive from EST Client hosts
module(load="imtcp")
input(type="imtcp" port="514")

# Optional: TLS receiver
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1")
input(
  type="imtcp"
  port="6514"
  StreamDriver.Name="gtls"
  StreamDriver.Mode="1"
  StreamDriver.AuthMode="x509/name"
  PermittedPeer=["*.example.mil"]
)

# EST Client template
template(name="EstClientFormat" type="string"
  string="/var/log/est-client/%HOSTNAME%/%$YEAR%-%$MONTH%-%$DAY%.log"
)

# Routing rule
if $programname == 'est-client' then {
  action(type="omfile" DynaFile="EstClientFormat")
  stop
}
```

### 6.3 Syslog-ng Configuration (Alternative)

**/etc/syslog-ng/conf.d/est-client.conf:**
```
source s_est_client_tcp {
  tcp(
    ip(0.0.0.0)
    port(514)
    max-connections(100)
  );
};

source s_est_client_tls {
  tcp(
    ip(0.0.0.0)
    port(6514)
    tls(
      key-file("/etc/syslog-ng/cert.d/serverkey.pem")
      cert-file("/etc/syslog-ng/cert.d/servercert.pem")
      ca-dir("/etc/syslog-ng/ca.d")
      peer-verify(required-trusted)
    )
  );
};

filter f_est_client {
  program("est-client");
};

destination d_est_client {
  file(
    "/var/log/est-client/${HOST}/${YEAR}-${MONTH}-${DAY}.log"
    create-dirs(yes)
    owner("root")
    group("adm")
    perm(0640)
  );
};

log {
  source(s_est_client_tcp);
  source(s_est_client_tls);
  filter(f_est_client);
  destination(d_est_client);
};
```

---

## 7. Integration Checklist

### 7.1 Pre-Deployment

- [ ] **SIEM Platform Selection**: Choose SIEM platform (Splunk, ELK, ArcSight, etc.)
- [ ] **Network Connectivity**: Verify EST Client can reach SIEM collectors
- [ ] **Firewall Rules**: Open required ports (TCP 514, 6514, 5044, etc.)
- [ ] **Certificate Configuration**: Install TLS certificates for encrypted log forwarding
- [ ] **User Accounts**: Create service accounts for SIEM collectors
- [ ] **Storage Planning**: Calculate log volume and retention requirements

### 7.2 Configuration

- [ ] **EST Client**: Enable audit logging and configure format
- [ ] **Log Forwarder**: Install and configure (Universal Forwarder, Filebeat, etc.)
- [ ] **SIEM Ingest**: Configure log ingestion pipeline
- [ ] **Index/Store**: Create indexes and apply lifecycle policies
- [ ] **Parsing**: Validate log parsing and field extraction

### 7.3 Validation

- [ ] **Log Flow**: Verify logs are reaching SIEM
- [ ] **Field Extraction**: Confirm all fields are correctly parsed
- [ ] **Time Sync**: Verify timestamps are correct
- [ ] **Volume**: Monitor log volume and ingest rates
- [ ] **Test Queries**: Run sample queries to verify data is searchable

### 7.4 Post-Deployment

- [ ] **Dashboards**: Deploy security monitoring dashboards
- [ ] **Alerts**: Configure alerts for critical events
- [ ] **Reports**: Schedule regular compliance reports
- [ ] **Documentation**: Document integration for operations team
- [ ] **Training**: Train SOC analysts on EST Client event taxonomy

---

## 8. Compliance Mapping

### 8.1 NIST SP 800-53 Audit Requirements

| Control | Requirement | Implementation | Evidence |
|---------|-------------|----------------|----------|
| AU-2 | Audit Events | All security events logged | Event taxonomy (Section 2) |
| AU-3 | Content of Audit Records | Structured logs with context | JSON format (Section 3.1) |
| AU-6 | Audit Review | SIEM integration for analysis | Splunk/ELK integration |
| AU-8 | Time Stamps | UTC timestamps on all events | ISO 8601 format |
| AU-9 | Protection of Audit Info | File ACLs, SIEM access control | Windows ACLs + SIEM RBAC |
| AU-12 | Audit Generation | Comprehensive audit logging | All event categories |

### 8.2 STIG Audit Requirements

| STIG ID | Finding | Implementation | Validation |
|---------|---------|----------------|------------|
| APSC-DV-000050 | Generate audit records | All categories logged | Section 2 taxonomy |
| APSC-DV-000230 | Write audit records to log | File + SIEM output | Section 3-6 |
| APSC-DV-000200 | Protect audit information | ACLs + encryption | Windows ACLs, TLS forwarding |
| APSC-DV-000220 | Backup audit records | SIEM retention | ILM policies |

---

## 9. Troubleshooting

### 9.1 Common Issues

**Issue: Logs not reaching SIEM**
- **Cause**: Network connectivity, firewall, or authentication
- **Solution**:
  1. Test network connectivity: `Test-NetConnection siem.example.mil -Port 514`
  2. Check firewall rules
  3. Verify TLS certificates (if using encrypted forwarding)
  4. Check forwarder logs for errors

**Issue: Incorrect timestamp parsing**
- **Cause**: Time zone mismatch or format mismatch
- **Solution**:
  1. Verify EST Client outputs UTC timestamps (ISO 8601)
  2. Check SIEM time parser configuration
  3. Ensure NTP sync on all systems

**Issue: Missing fields in SIEM**
- **Cause**: Incomplete field extraction or mapping
- **Solution**:
  1. Validate JSON format in logs
  2. Review SIEM parser configuration
  3. Check field mappings (Section 4.2, 5.4)

**Issue: High log volume causing performance issues**
- **Cause**: Too many DEBUG events or inefficient indexing
- **Solution**:
  1. Increase log level to INFO or WARNING
  2. Implement log filtering at forwarder
  3. Optimize SIEM index settings
  4. Review ILM policies

### 9.2 Diagnostic Commands

**Check EST Client Logs:**
```powershell
Get-Content "C:\ProgramData\Department of War\EST\logs\est-client.log" -Tail 50
```

**Validate JSON Format:**
```powershell
Get-Content "C:\ProgramData\Department of War\EST\logs\est-client.log" -Tail 10 | ConvertFrom-Json
```

**Test Syslog Connectivity:**
```powershell
Test-NetConnection syslog.example.mil -Port 514
```

**Monitor Log Volume:**
```powershell
Get-ChildItem "C:\ProgramData\Department of War\EST\logs\*.log" | Measure-Object -Property Length -Sum
```

---

## 10. Appendices

### Appendix A: Event ID Reference

See Section 2 for complete event taxonomy.

### Appendix B: Sample Log Messages

Available in `examples/logs/` directory.

### Appendix C: SIEM Vendor Support Matrix

| SIEM Platform | Log Format | Transport | Status |
|---------------|-----------|-----------|--------|
| Splunk Enterprise | JSON, Syslog | TCP, TLS, Universal Forwarder | ✅ Supported |
| Elastic Stack | JSON | Filebeat, Logstash | ✅ Supported |
| ArcSight ESM | CEF, Syslog | Syslog, SmartConnector | ✅ Supported |
| QRadar | LEEF, Syslog | Syslog, Log Source | ✅ Supported |
| Sentinel (Azure) | JSON, CEF | Log Analytics Agent | 🔄 Planned (Phase 13) |
| Chronicle | JSON | Forwarder | 🔄 Planned (Phase 13) |

### Appendix D: Additional Resources

- NIST SP 800-92: Guide to Computer Security Log Management
- NIST SP 800-53 Rev 5: AU Family (Audit and Accountability)
- DoD SIEM Implementation Guide
- CIS Logging Benchmarks

---

**Document Classification:** UNCLASSIFIED
**Page Count:** 35
**End of Document**
