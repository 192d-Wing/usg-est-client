# Plan of Action & Milestones (POA&M)

## EST Client Library for Windows

**Version:** 1.0
**POA&M Date:** 2026-01-13
**Classification:** UNCLASSIFIED
**Distribution:** Authorized to U.S. Government agencies and their contractors

---

## 1. Executive Summary

This Plan of Action & Milestones (POA&M) documents security control weaknesses identified during the security assessment of the EST Client Library and establishes remediation timelines. All identified weaknesses are low-to-medium risk and represent planned enhancements rather than security deficiencies.

**System Name:** EST Client Library
**System Abbreviation:** EST-CLIENT
**POA&M Status:** OPEN
**Total Items:** 7
**Items by Risk Level:**
- HIGH: 0
- MEDIUM: 2
- LOW: 5

**Overall Assessment:** System is suitable for production deployment with planned enhancements tracked in this POA&M.

---

## 2. POA&M Items

### POA&M Item AU-001: Windows Event Log Integration

**Control:** AU-2 (Audit Events)

**Weakness Description:**
EST Client currently logs audit events to application log files only. Integration with Windows Event Log is not yet implemented, preventing centralized viewing in Windows Event Viewer and limiting integration with Windows-based SIEM agents.

**Current Implementation:**
- File-based logging using `tracing` crate
- JSON format logs to: `C:\ProgramData\EST\logs\audit.log`
- Log rotation and retention configured

**Risk Assessment:**
- **Likelihood:** Low (compensating control exists via file logging)
- **Impact:** Low (audit trail exists, just not in Windows Event Log)
- **Risk Level:** LOW
- **Risk Score:** 3 (on scale of 1-10)

**Affected Assets:**
- EST Auto-Enrollment Service
- Audit logging subsystem

**Mitigation Strategy:**
Implement Windows Event Log integration using Windows Event Logging API.

**Milestones:**

| Milestone ID | Task | Owner | Start Date | Target Date | Status |
|--------------|------|-------|------------|-------------|--------|
| AU-001-M1 | Design event source registration | Dev Team | 2026-02-01 | 2026-02-07 | Planned |
| AU-001-M2 | Implement Windows Event Log writer | Dev Team | 2026-02-08 | 2026-02-21 | Planned |
| AU-001-M3 | Create event manifest (MC file) | Dev Team | 2026-02-22 | 2026-02-28 | Planned |
| AU-001-M4 | Test event logging and Event Viewer display | QA Team | 2026-03-01 | 2026-03-14 | Planned |
| AU-001-M5 | Update documentation | Tech Writer | 2026-03-15 | 2026-03-21 | Planned |
| AU-001-M6 | Release with Event Log support | Release Mgr | 2026-03-22 | 2026-03-31 | Planned |

**Resources Required:**
- 2 developers (40 hours)
- 1 QA engineer (16 hours)
- Windows Event Log expertise

**Cost Estimate:** $8,000 (labor)

**Completion Criteria:**
- [ ] Event source registered during installation
- [ ] All security events written to Windows Event Log
- [ ] Events visible in Event Viewer with proper formatting
- [ ] Event IDs documented for SIEM correlation
- [ ] Backward compatibility maintained (file logging still works)

**Point of Contact:**
- Name: [Development Lead]
- Email: [email]
- Phone: [phone]

**Current Status:** Planned (Phase 12.5)

**Closure Date:** Target: 2026-03-31

**Comments/Updates:**
- 2026-01-13: POA&M item opened based on SAR findings

---

### POA&M Item AU-002: SIEM Integration

**Control:** AU-6 (Audit Review, Analysis, and Reporting)

**Weakness Description:**
EST Client does not currently forward audit logs to SIEM systems. Manual log review is required, limiting automated threat detection and compliance reporting capabilities.

**Current Implementation:**
- Logs written to local files
- Basic log rotation
- No centralized log aggregation

**Risk Assessment:**
- **Likelihood:** Low (logs are comprehensive and accessible)
- **Impact:** Low (organizational SIEM integration is optional enhancement)
- **Risk Level:** LOW
- **Risk Score:** 3 (on scale of 1-10)

**Affected Assets:**
- Audit logging subsystem
- SIEM integration

**Mitigation Strategy:**
Implement syslog forwarding and create pre-built SIEM content (dashboards, alerts).

**Milestones:**

| Milestone ID | Task | Owner | Start Date | Target Date | Status |
|--------------|------|-------|------------|-------------|--------|
| AU-002-M1 | Implement syslog client (RFC 5424) | Dev Team | 2026-04-01 | 2026-04-14 | Planned |
| AU-002-M2 | Add structured logging formats (CEF, LEEF) | Dev Team | 2026-04-15 | 2026-04-28 | Planned |
| AU-002-M3 | Create Splunk app and dashboards | SIEM Team | 2026-05-01 | 2026-05-15 | Planned |
| AU-002-M4 | Create ELK Stack dashboards | SIEM Team | 2026-05-16 | 2026-05-31 | Planned |
| AU-002-M5 | Create ArcSight SmartConnector config | SIEM Team | 2026-06-01 | 2026-06-15 | Planned |
| AU-002-M6 | Document SIEM integration procedures | Tech Writer | 2026-06-16 | 2026-06-30 | Planned |

**Resources Required:**
- 2 developers (60 hours)
- 1 SIEM specialist (80 hours)
- Test SIEM environments

**Cost Estimate:** $15,000 (labor + infrastructure)

**Completion Criteria:**
- [ ] Syslog forwarding implemented (TCP/TLS)
- [ ] CEF and LEEF format support
- [ ] Splunk app published to Splunkbase
- [ ] ELK dashboards available on GitHub
- [ ] ArcSight integration guide published
- [ ] Pre-built alert rules provided

**Point of Contact:**
- Name: [Development Lead]
- Email: [email]
- Phone: [phone]

**Current Status:** Planned (Phase 12.5)

**Closure Date:** Target: 2026-06-30

**Comments/Updates:**
- 2026-01-13: POA&M item opened based on SAR findings

---

### POA&M Item SC-001: Windows CNG Key Container Integration

**Control:** SC-12 (Cryptographic Key Establishment and Management)

**Weakness Description:**
Private keys are currently stored in PEM files with ACL protection instead of Windows CNG (Cryptography Next Generation) key containers. This prevents use of hardware-backed key protection (TPM) and DPAPI encryption.

**Current Implementation:**
- Private keys stored in: `C:\ProgramData\EST\keys\`
- File permissions: SYSTEM read-only
- Keys generated with CSPRNG (secure)

**Risk Assessment:**
- **Likelihood:** Medium (keys on disk more vulnerable than CNG/TPM)
- **Impact:** Medium (key compromise enables impersonation)
- **Risk Level:** MEDIUM
- **Risk Score:** 6 (on scale of 1-10)

**Affected Assets:**
- Private key storage
- Certificate enrollment module
- Key generation module

**Mitigation Strategy:**
Implement Windows CNG key container creation and management, eliminating file-based key storage.

**Milestones:**

| Milestone ID | Task | Owner | Start Date | Target Date | Status |
|--------------|------|-------|------------|-------------|--------|
| SC-001-M1 | Research CNG API requirements | Dev Team | 2026-02-01 | 2026-02-07 | Planned |
| SC-001-M2 | Implement CNG key generation | Dev Team | 2026-02-08 | 2026-02-21 | Planned |
| SC-001-M3 | Implement CNG key storage and retrieval | Dev Team | 2026-02-22 | 2026-03-14 | Planned |
| SC-001-M4 | Associate keys with certificates | Dev Team | 2026-03-15 | 2026-03-28 | Planned |
| SC-001-M5 | Implement TPM protection (optional) | Dev Team | 2026-03-29 | 2026-04-11 | Planned |
| SC-001-M6 | Migrate existing file-based keys to CNG | Dev Team | 2026-04-12 | 2026-04-18 | Planned |
| SC-001-M7 | Test key operations and TLS | QA Team | 2026-04-19 | 2026-04-30 | Planned |
| SC-001-M8 | Update documentation | Tech Writer | 2026-05-01 | 2026-05-15 | Planned |

**Resources Required:**
- 2 developers (120 hours)
- 1 QA engineer (32 hours)
- Windows CNG expertise
- TPM test hardware

**Cost Estimate:** $18,000 (labor + hardware)

**Completion Criteria:**
- [ ] Keys generated in CNG containers (non-exportable)
- [ ] DPAPI protection enabled by default
- [ ] TPM protection available when hardware present
- [ ] Keys associated with certificates in Windows store
- [ ] File-based storage removed from production code
- [ ] Migration tool for existing deployments
- [ ] All tests pass with CNG keys

**Point of Contact:**
- Name: [Development Lead]
- Email: [email]
- Phone: [phone]

**Current Status:** Planned (Phase 11.2)

**Closure Date:** Target: 2026-05-15

**Comments/Updates:**
- 2026-01-13: POA&M item opened based on SAR findings
- This addresses the highest-priority security enhancement

---

### POA&M Item SC-002: Protection of Keys at Rest

**Control:** SC-28 (Protection of Information at Rest)

**Weakness Description:**
Related to SC-001. Private keys stored in files lack DPAPI/TPM encryption that CNG provides. Audit logs not encrypted.

**Current Implementation:**
- Private keys in PEM files (ACL-protected)
- Audit logs in plaintext JSON files (ACL-protected)

**Risk Assessment:**
- **Likelihood:** Medium (offline access to disk could expose keys)
- **Impact:** Medium (key compromise enables impersonation)
- **Risk Level:** MEDIUM
- **Risk Score:** 6 (on scale of 1-10)

**Affected Assets:**
- Private key files
- Audit log files

**Mitigation Strategy:**
Implement CNG key storage (addresses primary risk) and optional audit log encryption.

**Milestones:**

| Milestone ID | Task | Owner | Start Date | Target Date | Status |
|--------------|------|-------|------------|-------------|--------|
| SC-002-M1 | Complete SC-001 (CNG integration) | Dev Team | 2026-02-01 | 2026-05-15 | Planned |
| SC-002-M2 | Design audit log encryption scheme | Security Team | 2026-05-16 | 2026-05-23 | Planned |
| SC-002-M3 | Implement optional log encryption | Dev Team | 2026-05-24 | 2026-06-06 | Planned |
| SC-002-M4 | Implement log integrity signatures | Dev Team | 2026-06-07 | 2026-06-20 | Planned |
| SC-002-M5 | Test encryption and key management | QA Team | 2026-06-21 | 2026-06-30 | Planned |

**Resources Required:**
- Dependent on SC-001 completion
- 1 developer (40 hours) for log encryption
- 1 security architect (16 hours)

**Cost Estimate:** $7,000 (labor)

**Completion Criteria:**
- [ ] SC-001 completed (CNG key storage)
- [ ] Optional audit log encryption implemented
- [ ] Log integrity signing available
- [ ] Key management for log encryption documented
- [ ] Performance impact acceptable (<5% overhead)

**Point of Contact:**
- Name: [Development Lead]
- Email: [email]
- Phone: [phone]

**Current Status:** Planned (Phase 12.5)

**Closure Date:** Target: 2026-06-30

**Dependencies:** Blocked by SC-001

**Comments/Updates:**
- 2026-01-13: POA&M item opened based on SAR findings

---

### POA&M Item SI-001: Security Update SLA Documentation

**Control:** SI-2 (Flaw Remediation)

**Weakness Description:**
No formal Service Level Agreement (SLA) documented for security patch releases. Security advisory process not fully defined.

**Current Implementation:**
- Dependency vulnerability scanning automated
- Security updates released on ad-hoc basis
- No published SLA or notification process

**Risk Assessment:**
- **Likelihood:** Low (vulnerabilities addressed but without formal SLA)
- **Impact:** Low (process exists, documentation needed)
- **Risk Level:** LOW
- **Risk Score:** 2 (on scale of 1-10)

**Affected Assets:**
- Security incident response
- Vulnerability disclosure process

**Mitigation Strategy:**
Document security update SLA and vulnerability disclosure policy.

**Milestones:**

| Milestone ID | Task | Owner | Start Date | Target Date | Status |
|--------------|------|-------|------------|-------------|--------|
| SI-001-M1 | Draft security update SLA | Security Team | 2026-02-01 | 2026-02-14 | Planned |
| SI-001-M2 | Create vulnerability disclosure policy | Legal + Security | 2026-02-15 | 2026-02-28 | Planned |
| SI-001-M3 | Publish security policy to repository | Dev Team | 2026-03-01 | 2026-03-07 | Planned |
| SI-001-M4 | Configure GitHub Security Advisories | Dev Team | 2026-03-08 | 2026-03-14 | Planned |
| SI-001-M5 | Create security advisory template | Tech Writer | 2026-03-15 | 2026-03-21 | Planned |
| SI-001-M6 | Document user notification channels | Comms Team | 2026-03-22 | 2026-03-31 | Planned |

**Resources Required:**
- 1 security manager (24 hours)
- Legal review (8 hours)
- Technical writer (16 hours)

**Cost Estimate:** $5,000 (labor)

**Completion Criteria:**
- [ ] Security update SLA published (30 days for High/Critical)
- [ ] Vulnerability disclosure policy published
- [ ] SECURITY.md file in repository
- [ ] GitHub Security Advisories configured
- [ ] User notification process documented
- [ ] Security contact email configured

**Point of Contact:**
- Name: [Security Manager]
- Email: [email]
- Phone: [phone]

**Current Status:** Planned (Phase 12.6)

**Closure Date:** Target: 2026-03-31

**Comments/Updates:**
- 2026-01-13: POA&M item opened based on SAR findings

---

### POA&M Item SI-002: Code Signing Implementation

**Control:** SI-7 (Software, Firmware, and Information Integrity)

**Weakness Description:**
Windows executables not yet signed with Authenticode certificates. Release checksums not GPG-signed. No build provenance attestation (SLSA).

**Current Implementation:**
- SHA-256 checksums provided for releases
- No Authenticode signature
- No GPG signature on checksums

**Risk Assessment:**
- **Likelihood:** Low (checksums provide integrity verification)
- **Impact:** Low (signing enhances trust but checksums sufficient)
- **Risk Level:** LOW
- **Risk Score:** 3 (on scale of 1-10)

**Affected Assets:**
- Release binaries
- Software distribution

**Mitigation Strategy:**
Acquire code signing certificate, implement Authenticode signing, add GPG signatures.

**Milestones:**

| Milestone ID | Task | Owner | Start Date | Target Date | Status |
|--------------|------|-------|------------|-------------|--------|
| SI-002-M1 | Procure Authenticode certificate | Procurement | 2026-03-01 | 2026-03-15 | Planned |
| SI-002-M2 | Set up secure code signing infrastructure | DevOps | 2026-03-16 | 2026-03-31 | Planned |
| SI-002-M3 | Implement Authenticode signing in build | Dev Team | 2026-04-01 | 2026-04-14 | Planned |
| SI-002-M4 | Generate GPG key for release signing | Security Team | 2026-04-15 | 2026-04-21 | Planned |
| SI-002-M5 | Implement GPG signing of checksums | Dev Team | 2026-04-22 | 2026-04-28 | Planned |
| SI-002-M6 | Implement SLSA build provenance | DevOps | 2026-05-01 | 2026-05-31 | Planned |
| SI-002-M7 | Document signature verification | Tech Writer | 2026-06-01 | 2026-06-15 | Planned |

**Resources Required:**
- Code signing certificate ($300/year)
- 1 developer (32 hours)
- 1 DevOps engineer (40 hours)
- Secure key storage (Azure Key Vault or HSM)

**Cost Estimate:** $10,000 (labor + certificate + infrastructure)

**Completion Criteria:**
- [ ] Authenticode certificate acquired
- [ ] All release binaries Authenticode-signed
- [ ] GPG key generated and published
- [ ] Release checksums GPG-signed
- [ ] SLSA provenance attestation included
- [ ] Signature verification documented

**Point of Contact:**
- Name: [Release Manager]
- Email: [email]
- Phone: [phone]

**Current Status:** Planned (Phase 12.6)

**Closure Date:** Target: 2026-06-15

**Comments/Updates:**
- 2026-01-13: POA&M item opened based on SAR findings

---

### POA&M Item RA-001: Penetration Testing Schedule

**Control:** RA-5 (Vulnerability Scanning)

**Weakness Description:**
Annual penetration testing not yet scheduled. No formal vulnerability disclosure program established.

**Current Implementation:**
- Automated static analysis and dependency scanning
- Fuzzing for input validation
- No external penetration testing

**Risk Assessment:**
- **Likelihood:** Low (comprehensive automated testing in place)
- **Impact:** Low (development-phase testing is thorough)
- **Risk Level:** LOW
- **Risk Score:** 2 (on scale of 1-10)

**Affected Assets:**
- Security testing program
- Vulnerability management

**Mitigation Strategy:**
Schedule annual penetration test with qualified team, establish testing cadence.

**Milestones:**

| Milestone ID | Task | Owner | Start Date | Target Date | Status |
|--------------|------|-------|------------|-------------|--------|
| RA-001-M1 | Define penetration testing requirements | Security Team | 2026-07-01 | 2026-07-15 | Planned |
| RA-001-M2 | Issue RFP for penetration testing services | Procurement | 2026-07-16 | 2026-08-15 | Planned |
| RA-001-M3 | Award contract to testing vendor | Procurement | 2026-08-16 | 2026-09-01 | Planned |
| RA-001-M4 | Conduct penetration test | Vendor | 2026-09-02 | 2026-09-30 | Planned |
| RA-001-M5 | Review findings and create POA&M items | Security Team | 2026-10-01 | 2026-10-15 | Planned |
| RA-001-M6 | Remediate High/Critical findings | Dev Team | 2026-10-16 | 2026-11-15 | Planned |
| RA-001-M7 | Schedule annual recurring tests | Security Team | 2026-11-16 | 2026-11-30 | Planned |

**Resources Required:**
- Penetration testing service ($25,000/year)
- Internal coordination (32 hours)
- Remediation effort (TBD based on findings)

**Cost Estimate:** $28,000 (testing + coordination)

**Completion Criteria:**
- [ ] Penetration test conducted by qualified vendor
- [ ] Test report reviewed and findings prioritized
- [ ] High/Critical findings remediated
- [ ] Annual testing schedule established
- [ ] Findings tracked in POA&M
- [ ] Retest confirms remediation

**Point of Contact:**
- Name: [Security Manager]
- Email: [email]
- Phone: [phone]

**Current Status:** Planned (Q4 2026)

**Closure Date:** Target: 2026-11-30

**Comments/Updates:**
- 2026-01-13: POA&M item opened based on SAR findings

---

## 3. POA&M Summary Dashboard

### 3.1 Items by Status

| Status | Count |
|--------|-------|
| Open | 7 |
| In Progress | 0 |
| Completed | 0 |
| **Total** | **7** |

### 3.2 Items by Risk Level

| Risk Level | Count | Percentage |
|------------|-------|------------|
| HIGH | 0 | 0% |
| MEDIUM | 2 | 29% |
| LOW | 5 | 71% |
| **Total** | **7** | **100%** |

### 3.3 Items by Control Family

| Family | Count |
|--------|-------|
| AU (Audit and Accountability) | 2 |
| SC (System and Communications Protection) | 2 |
| SI (System and Information Integrity) | 2 |
| RA (Risk Assessment) | 1 |
| **Total** | **7** |

### 3.4 Remediation Timeline

```
2026 Q1 (Jan-Mar):
  - AU-001: Windows Event Log Integration (Target: Mar 31)
  - SI-001: Security Update SLA (Target: Mar 31)

2026 Q2 (Apr-Jun):
  - SC-001: CNG Key Container Integration (Target: May 15)
  - SC-002: Protection of Keys at Rest (Target: Jun 30)
  - AU-002: SIEM Integration (Target: Jun 30)
  - SI-002: Code Signing (Target: Jun 15)

2026 Q3 (Jul-Sep):
  - [No POA&M items, focus on stability]

2026 Q4 (Oct-Dec):
  - RA-001: Penetration Testing (Target: Nov 30)
```

### 3.5 Cost Summary

| POA&M Item | Estimated Cost | Status |
|------------|---------------|--------|
| AU-001 | $8,000 | Not Started |
| AU-002 | $15,000 | Not Started |
| SC-001 | $18,000 | Not Started |
| SC-002 | $7,000 | Not Started |
| SI-001 | $5,000 | Not Started |
| SI-002 | $10,000 | Not Started |
| RA-001 | $28,000 | Not Started |
| **Total** | **$91,000** | **Planned** |

---

## 4. POA&M Management

### 4.1 Review Cycle

**Frequency:** Monthly

**Review Date:** First Monday of each month

**Participants:**
- System Owner
- ISSO
- Development Lead
- Security Manager

**Review Agenda:**
1. Status update on all open items
2. Milestone completion verification
3. Risk reassessment if needed
4. Resource allocation review
5. Timeline adjustments (if needed)
6. New items from vulnerability scans

### 4.2 Escalation Process

**Missed Milestones:**
- 1 week overdue: Email notification to POC
- 2 weeks overdue: Escalation to System Owner
- 1 month overdue: Escalation to Authorizing Official

**Risk Level Changes:**
- Any item escalating to HIGH risk: Immediate notification to AO
- Impact assessment required within 48 hours
- Expedited remediation plan required within 1 week

### 4.3 Closure Criteria

POA&M items are closed when:
1. All milestones completed
2. Completion criteria met
3. Testing confirms remediation
4. Security assessment validates fix
5. Documentation updated
6. ISSO approves closure

### 4.4 Reporting

**Monthly POA&M Status Report:**
- Submitted to Authorizing Official
- Includes: Status updates, timeline changes, risk changes
- Format: PDF with summary dashboard

**Annual ATO Review:**
- All POA&M items reviewed
- Risk posture reassessed
- ATO renewal decision

---

## 5. Approval

**Information System Owner:**
- Signature: _________________________ Date: __________
- Name:

**Information System Security Officer:**
- Signature: _________________________ Date: __________
- Name:

**Authorizing Official (Acknowledged):**
- Signature: _________________________ Date: __________
- Name:

---

## 6. Revision History

| Version | Date | Description | Author |
|---------|------|-------------|--------|
| 1.0 | 2026-01-13 | Initial POA&M created from SAR findings | Security Team |

---

**Document Classification:** UNCLASSIFIED
**Page Count:** 18
**End of Document**
