# Penetration Testing Requirements for EST Client

**Document Version**: 1.0
**Last Updated**: 2026-01-14
**Related POA&M**: RA-001
**Security Control**: RA-5 (Vulnerability Monitoring and Scanning)

---

## 1. Executive Summary

This document defines the penetration testing requirements for the U.S. Government EST (Enrollment over Secure Transport) Client. Annual penetration testing is required to:

- Validate security controls are functioning as intended
- Identify vulnerabilities not detected by automated scanning
- Meet FedRAMP and DoD ATO requirements
- Provide independent security assessment

**Testing Frequency**: Annually (Q4 each fiscal year)
**Budget**: $25,000/year for testing services
**Expected Duration**: 4 weeks (testing + reporting)

---

## 2. Scope

### 2.1 In-Scope Components

**Applications**:
- EST Client executable (`est-client.exe` / `est-client`)
- EST Auto-Enrollment Service (Windows service)
- EST Client REST API (if exposed)
- Configuration file parsing (`config.toml`)

**Network Services**:
- EST protocol implementation (HTTPS on port 443)
- TLS/SSL configuration
- Certificate validation logic

**Windows Integration** (Windows-only testing):
- Windows Certificate Store integration
- CNG (Cryptography Next Generation) key storage
- DPAPI (Data Protection API) usage
- TPM 2.0 integration
- Windows Event Log integration
- Service installation and permissions

**Authentication Mechanisms**:
- TLS client certificate authentication
- HTTP Basic authentication
- Digest authentication
- Certificate-based authentication

**Key Management**:
- Key generation (RSA, ECDSA)
- Key storage (CNG containers, file-based)
- Key protection (DPAPI, TPM)
- Key rotation

**Data Protection**:
- Certificate storage
- Audit log encryption (optional)
- Configuration file protection
- Memory handling of sensitive data

### 2.2 Out-of-Scope

**Infrastructure** (separate assessment):
- EST server implementation
- Network infrastructure
- Active Directory integration
- DNS, DHCP, routing

**Third-Party Components** (assessed separately):
- OpenSSL/rustls libraries
- Operating system vulnerabilities
- Hardware vulnerabilities

**Excluded Attack Vectors**:
- Physical attacks (tampering, theft)
- Social engineering
- Insider threats
- Supply chain attacks (unless specified)

---

## 3. Testing Methodology

### 3.1 Approach

**Testing Type**: Gray-box penetration testing
- Source code available for review
- Architecture documentation provided
- Configuration details shared
- Credentials for test environment provided

**Testing Standards**:
- NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment)
- OWASP Testing Guide v4.2
- PTES (Penetration Testing Execution Standard)
- FedRAMP Penetration Test Guidance

### 3.2 Test Phases

**Phase 1: Reconnaissance and Planning** (1 week)
- Review architecture documentation
- Review source code (static analysis)
- Identify attack surface
- Develop test plan

**Phase 2: Vulnerability Assessment** (1 week)
- Automated vulnerability scanning
- Manual code review
- Configuration review
- Dependency analysis

**Phase 3: Exploitation** (1 week)
- Attempt to exploit identified vulnerabilities
- Privilege escalation attempts
- Data exfiltration attempts
- Persistence mechanism testing

**Phase 4: Post-Exploitation** (3 days)
- Lateral movement assessment (if applicable)
- Data access verification
- Cleanup and documentation

**Phase 5: Reporting** (2 days)
- Findings documentation
- Risk scoring (CVSS v3.1)
- Remediation recommendations
- Executive summary

### 3.3 Testing Categories

**A. Network Penetration Testing**
- TLS/SSL configuration
- Certificate validation bypass attempts
- Man-in-the-middle attacks
- Protocol downgrade attacks
- Certificate pinning bypass

**B. Application Security Testing**
- Input validation
- Buffer overflow attempts
- Memory corruption
- Integer overflow/underflow
- Format string vulnerabilities

**C. Authentication Testing**
- Weak credential acceptance
- Certificate validation failures
- Session hijacking
- Replay attacks
- Authentication bypass

**D. Cryptography Testing**
- Weak algorithm usage
- Improper key generation
- Insecure random number generation
- Key storage vulnerabilities
- Side-channel attacks (timing, cache)

**E. Windows Platform Testing** (Windows-specific)
- Privilege escalation
- DLL hijacking
- Registry manipulation
- Service exploitation
- DPAPI bypass attempts
- CNG container access attempts

**F. Logic and Business Process Testing**
- Certificate enrollment bypass
- Renewal logic flaws
- Authorization bypass
- State machine attacks
- Race conditions

---

## 4. Threat Model

### 4.1 Threat Actors

**External Attackers** (Primary Focus):
- Motivation: Espionage, credential theft, man-in-the-middle
- Capabilities: Advanced persistent threat (APT)
- Access: Network-adjacent, compromised EST server

**Insider Threats** (Secondary Focus):
- Motivation: Data exfiltration, sabotage
- Capabilities: Authenticated access, code access
- Access: Legitimate user or service account

**Malicious Software** (Tertiary Focus):
- Motivation: Persistence, privilege escalation
- Capabilities: Code execution on endpoint
- Access: User-level process

### 4.2 Attack Vectors

**Priority 1 (Must Test)**:
1. TLS/SSL vulnerabilities
2. Certificate validation bypass
3. Key extraction from storage
4. Authentication bypass
5. Input validation failures
6. Memory corruption vulnerabilities

**Priority 2 (Should Test)**:
7. Configuration tampering
8. Log manipulation
9. Service account compromise
10. Privilege escalation
11. Side-channel attacks
12. Denial of service

**Priority 3 (Nice to Test)**:
13. Physical key extraction (if TPM present)
14. Timing attacks on crypto operations
15. Cache-based side channels
16. Spectre/Meltdown variants

---

## 5. Test Environment

### 5.1 Infrastructure Requirements

**Test Lab Configuration**:
- Isolated network (no production access)
- EST server (test instance)
- Windows test machines (various versions)
- Unix/Linux test machines (if applicable)
- Network monitoring tools (packet capture)

**Software Versions to Test**:
- Windows 10 (21H2, 22H2)
- Windows 11 (22H2, 23H2)
- Windows Server 2019
- Windows Server 2022
- Ubuntu 22.04 LTS (if Unix support)

**Hardware Variants**:
- With TPM 2.0
- Without TPM
- Virtual machines
- Physical hardware

### 5.2 Test Accounts

**Provided Credentials**:
- Administrator account (Windows)
- Standard user account (Windows)
- Service account (for auto-enrollment service)
- EST server admin credentials (test server only)

**Test Certificates**:
- Valid client certificates
- Expired client certificates
- Revoked client certificates
- Self-signed certificates
- Certificates from untrusted CAs

---

## 6. Acceptance Criteria

### 6.1 Deliverables

**Required Deliverables**:
1. **Penetration Test Report** (comprehensive)
   - Executive summary
   - Methodology
   - Findings (all severities)
   - Evidence (screenshots, logs, packet captures)
   - Risk ratings (CVSS v3.1)
   - Remediation recommendations

2. **Findings Database** (machine-readable)
   - JSON or CSV format
   - All vulnerabilities with CVSS scores
   - CWE identifiers
   - Affected components

3. **Retest Report** (after remediation)
   - Verification of fixes
   - Regression testing
   - Updated risk ratings

4. **Presentation** (executive briefing)
   - Key findings
   - Risk summary
   - Remediation roadmap

### 6.2 Finding Severity Definitions

**Critical** (CVSS 9.0-10.0):
- Remote code execution without authentication
- Complete system compromise
- Mass data exfiltration
- **Remediation SLA**: 7 days

**High** (CVSS 7.0-8.9):
- Privilege escalation to SYSTEM/root
- Authentication bypass
- Key extraction
- **Remediation SLA**: 30 days

**Medium** (CVSS 4.0-6.9):
- Information disclosure
- Denial of service
- Weak cryptography
- **Remediation SLA**: 90 days

**Low** (CVSS 0.1-3.9):
- Configuration weaknesses
- Minor information leaks
- Enhancement recommendations
- **Remediation SLA**: 180 days

**Informational** (CVSS 0.0):
- Best practice violations
- Hardening recommendations
- No security impact
- **Remediation**: Next release cycle

---

## 7. Vendor Qualifications

### 7.1 Required Qualifications

**Company Requirements**:
- Minimum 5 years penetration testing experience
- Experience with DoD or federal systems
- FedRAMP authorized service provider (preferred)
- ISO 27001 certified (preferred)
- Professional liability insurance ($2M minimum)

**Team Requirements**:
- At least one GPEN (GIAC Penetration Tester) certified tester
- At least one OSCP (Offensive Security Certified Professional) certified tester
- Windows security expertise
- Cryptography expertise (for key management testing)
- Experience with code review (Rust preferred)

**References**:
- Minimum 3 references from federal or DoD clients
- References from similar projects (PKI, certificate management)

### 7.2 Confidentiality Requirements

**Non-Disclosure Agreement (NDA)**:
- All testing personnel must sign NDA
- Source code access restricted
- Findings confidential (no public disclosure)
- Data destruction after contract completion

**Security Clearance** (if required):
- Secret clearance preferred for DoD deployments
- Suitability determination for civilian agencies
- Background checks required

---

## 8. Annual Testing Schedule

### 8.1 Recurring Schedule

**Fiscal Year Cadence**:
```
Q1 (Oct-Dec):
  - Planning and procurement
  - RFP issuance
  - Vendor selection

Q2 (Jan-Mar):
  - Kickoff meeting
  - Environment setup
  - Testing execution

Q3 (Apr-Jun):
  - Report delivery
  - Remediation planning
  - Fix development

Q4 (Jul-Sep):
  - Remediation completion
  - Retest
  - POA&M updates
```

**Milestone Dates** (Example FY2027):
- **Oct 1, 2026**: Initiate procurement
- **Nov 15, 2026**: Award contract
- **Jan 15, 2027**: Testing kickoff
- **Feb 15, 2027**: Testing complete
- **Mar 1, 2027**: Report delivery
- **Jun 30, 2027**: Remediation complete
- **Jul 31, 2027**: Retest complete
- **Sep 30, 2027**: Annual cycle complete

### 8.2 Trigger Events for Ad-Hoc Testing

**Major Changes** (test within 90 days):
- New authentication mechanism
- Major cryptographic changes
- New protocol implementation
- Privilege escalation fixes

**Security Incidents** (test within 30 days):
- Actual exploitation
- Zero-day vulnerability in dependencies
- Critical CVE affecting EST Client

---

## 9. Finding Management

### 9.1 Tracking Process

**Workflow**:
1. Finding identified by tester
2. Vendor documents in report
3. Security team validates finding
4. POA&M item created (if not duplicate)
5. Development team assigned
6. Fix implemented and tested
7. Vendor performs retest
8. POA&M item closed

**Tools**:
- GitHub Issues (development tracking)
- POA&M spreadsheet (compliance tracking)
- Jira/ServiceNow (if organizational standard)

### 9.2 Remediation Prioritization

**Priority 1** (Critical + High):
- Immediate resource allocation
- Dedicated sprint
- Weekly status updates
- Executive notification

**Priority 2** (Medium):
- Normal sprint prioritization
- Monthly status updates
- Included in next release

**Priority 3** (Low + Informational):
- Backlog placement
- Quarterly review
- Future release consideration

---

## 10. Compliance Mapping

### 10.1 NIST 800-53 Rev 5

**RA-5: Vulnerability Monitoring and Scanning**:
- (1) Update Tool Capability - ✅ Annual testing
- (2) Update Vulnerabilities to be Scanned - ✅ CVSS + CWE
- (3) Breadth and Depth of Coverage - ✅ Comprehensive scope
- (5) Privileged Access - ✅ Admin credentials provided
- (8) Review Historic Audit Logs - ✅ Log analysis included

**CA-2: Security Assessments**:
- (1) Independent Assessors - ✅ Third-party vendor
- (2) Specialized Assessments - ✅ Cryptography focus
- (3) Leveraging Results from External Organizations - ✅ FedRAMP process

**CA-8: Penetration Testing**:
- (1) Independent Penetration Testing Agent or Team - ✅ External vendor
- (2) Red Team Exercises - Considered for Phase 2 (after ATO)

### 10.2 FedRAMP Requirements

**Penetration Test Frequency**:
- Annual testing - ✅ Planned
- After significant changes - ✅ Trigger events defined

**Test Coverage**:
- Application layer - ✅ In scope
- Network layer - ✅ TLS/SSL testing
- Infrastructure layer - Separate assessment

**Reporting**:
- CVSS v3.1 scoring - ✅ Required
- Risk-based prioritization - ✅ Defined
- POA&M integration - ✅ Workflow defined

---

## 11. Budget and Resources

### 11.1 Annual Budget

| Line Item | Cost | Notes |
|-----------|------|-------|
| Penetration Testing Service | $25,000 | Annual contract |
| Retest (after remediation) | $5,000 | Included in contract |
| Internal Coordination | $3,000 | 32 hours @ $94/hr |
| **Total Annual Cost** | **$33,000** | FY budget allocation |

### 11.2 Internal Resources

**Security Team** (32 hours):
- Test planning: 8 hours
- Vendor coordination: 8 hours
- Report review: 8 hours
- Remediation planning: 8 hours

**Development Team** (TBD):
- Varies based on findings
- Estimate: 40-200 hours
- Reserved as "unplanned work" budget

---

## 12. References

### 12.1 Standards and Guidelines

- NIST SP 800-115: Technical Guide to Information Security Testing and Assessment
- NIST SP 800-53 Rev 5: Security and Privacy Controls
- FedRAMP Penetration Test Guidance (v4.0)
- OWASP Testing Guide v4.2
- PTES (Penetration Testing Execution Standard)
- CWE Top 25 Most Dangerous Software Weaknesses

### 12.2 Related Documents

- [POA&M](poam.md) - Plan of Action and Milestones
- [Security Update SLA](security-update-sla.md) - SI-001
- [SC-001 Completion Report](sc-001-completion.md) - Key storage
- [SC-002 Completion Report](sc-002-completion.md) - Log encryption

---

## 13. Appendices

### Appendix A: Sample RFP Template

See: [penetration-testing-rfp-template.md](penetration-testing-rfp-template.md)

### Appendix B: Finding Template

See: [penetration-test-finding-template.md](penetration-test-finding-template.md)

### Appendix C: Test Cases

See: [penetration-test-cases.md](penetration-test-cases.md)

---

**Document Owner**: Security Team
**Next Review**: 2026-07-01 (before FY2027 procurement)
**Approval**: [Security Manager Signature]
**Date**: _______________

---

**Version History**:
- v1.0 (2026-01-14): Initial creation for RA-001 POA&M item
