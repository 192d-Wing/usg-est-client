# Request for Proposal (RFP) - Penetration Testing Services
## U.S. Government EST Client Security Assessment

**RFP Number**: [TO BE ASSIGNED]
**Issue Date**: [ISSUE DATE]
**Proposal Due Date**: [DUE DATE - 30 days from issue]
**Questions Due Date**: [QUESTIONS DATE - 15 days from issue]
**Contract Period**: [START DATE] to [END DATE]
**Contract Type**: Firm Fixed Price (FFP)

---

## 1. Introduction

### 1.1 Purpose

The [AGENCY NAME] is seeking qualified vendors to provide comprehensive penetration testing services for the U.S. Government Enrollment over Secure Transport (EST) Client application. This annual security assessment is required to meet Federal Risk and Authorization Management Program (FedRAMP) and Department of Defense (DoD) Authorization to Operate (ATO) requirements.

### 1.2 Background

The EST Client is a certificate enrollment and management application used by federal agencies to automate PKI certificate lifecycle operations. The application:

- Implements RFC 7030 (Enrollment over Secure Transport)
- Operates on Windows and Unix/Linux platforms
- Integrates with Windows Certificate Store and CNG cryptography
- Supports TPM 2.0 for key protection
- Handles sensitive cryptographic material and certificates
- Processes classified and sensitive government data

### 1.3 Authority

This procurement is conducted under the authority of [APPLICABLE REGULATION/STATUTE].

### 1.4 Contract Vehicle

[SPECIFY: GSA Schedule, IDIQ, Open Market, etc.]

---

## 2. Scope of Work

### 2.1 Overview

The contractor shall perform a comprehensive gray-box penetration test of the EST Client application, including:

- Application security assessment (source code review + dynamic testing)
- Network protocol testing (EST/HTTPS/TLS)
- Authentication mechanism testing
- Cryptographic implementation review
- Windows platform integration testing
- Key management security assessment

**Testing Approach**: Gray-box (source code, documentation, and test credentials provided)

### 2.2 In-Scope Components

**Applications**:
- EST Client executable (`est-client.exe` / `est-client`)
- EST Auto-Enrollment Service (Windows service)
- EST Client REST API (if exposed)
- Configuration file parsing (`config.toml`)

**Network Services**:
- EST protocol implementation (RFC 7030)
- TLS/SSL configuration and certificate validation
- HTTPS communications

**Windows Integration** (Windows-specific testing):
- Windows Certificate Store integration
- Cryptography Next Generation (CNG) key storage
- Data Protection API (DPAPI) usage
- Trusted Platform Module (TPM) 2.0 integration
- Windows Event Log integration
- Service installation and privilege handling

**Authentication Mechanisms**:
- TLS client certificate authentication
- HTTP Basic authentication
- Digest authentication
- Certificate-based authentication

**Key Management**:
- Key generation (RSA 2048/4096, ECDSA P-256/P-384)
- Key storage (CNG containers, file-based)
- Key protection (DPAPI, TPM)
- Key rotation mechanisms

**Data Protection**:
- Certificate storage security
- Audit log encryption (AES-256-GCM)
- Configuration file protection
- Memory handling of sensitive data

### 2.3 Out-of-Scope

The following are explicitly **excluded** from this assessment:

- EST server implementation (separate system)
- Network infrastructure (routers, switches, firewalls)
- Active Directory infrastructure
- Third-party library vulnerabilities (OpenSSL, rustls) unless exploitation demonstrates EST Client vulnerability
- Operating system vulnerabilities
- Physical security attacks
- Social engineering attacks
- Supply chain attacks (unless specifically requested)

### 2.4 Testing Standards

The contractor shall conduct testing in accordance with:

- **NIST SP 800-115**: Technical Guide to Information Security Testing and Assessment
- **OWASP Testing Guide v4.2**: Application security testing methodology
- **PTES**: Penetration Testing Execution Standard
- **FedRAMP Penetration Test Guidance** (v4.0 or latest)
- **NIST SP 800-53 Rev 5**: Security controls RA-5, CA-2, CA-8

### 2.5 Test Categories

The contractor shall perform testing in the following categories:

**A. Network Penetration Testing**:
- TLS/SSL configuration weaknesses
- Certificate validation bypass attempts
- Man-in-the-middle (MITM) attacks
- Protocol downgrade attacks
- Certificate pinning bypass attempts

**B. Application Security Testing**:
- Input validation vulnerabilities
- Buffer overflow attempts
- Memory corruption vulnerabilities
- Integer overflow/underflow
- Format string vulnerabilities
- Logic flaws in certificate enrollment

**C. Authentication Testing**:
- Weak credential acceptance
- Certificate validation failures
- Session hijacking attempts
- Replay attacks
- Authentication bypass attempts

**D. Cryptography Testing**:
- Weak algorithm usage detection
- Improper key generation
- Insecure random number generation
- Key storage vulnerabilities
- Side-channel attacks (timing, cache-based)

**E. Windows Platform Testing**:
- Privilege escalation attempts
- DLL hijacking vulnerabilities
- Registry manipulation
- Service exploitation
- DPAPI bypass attempts
- CNG container unauthorized access

**F. Business Logic Testing**:
- Certificate enrollment bypass
- Renewal logic flaws
- Authorization bypass
- State machine vulnerabilities
- Race conditions

---

## 3. Deliverables

### 3.1 Required Deliverables

**Deliverable 1: Penetration Test Plan** (Due: 5 business days after kickoff)
- Detailed test plan with timelines
- Test environment requirements
- Tools to be used
- Testing schedule
- Points of contact

**Deliverable 2: Penetration Test Report** (Due: 10 business days after testing completion)

The comprehensive report shall include:

1. **Executive Summary** (2-3 pages)
   - High-level findings
   - Risk summary
   - Key recommendations
   - Business impact assessment

2. **Methodology** (3-5 pages)
   - Testing approach
   - Tools and techniques used
   - Test coverage
   - Limitations and constraints

3. **Detailed Findings** (Main section)
   - Each finding shall include:
     - Title and description
     - Severity rating (CVSS v3.1 score)
     - CWE identifier
     - Affected component(s)
     - Steps to reproduce
     - Evidence (screenshots, logs, packet captures)
     - Proof of concept (if applicable)
     - Business impact
     - Remediation recommendations (detailed)
     - References

4. **Attack Narrative** (2-5 pages)
   - Attack scenarios attempted
   - Attack chain progression
   - Successful exploitation paths
   - Defense evasion techniques

5. **Risk Assessment** (1-2 pages)
   - Overall security posture
   - Risk heat map
   - Trend analysis (if annual retest)

6. **Appendices**:
   - Testing scope
   - Test environment details
   - Tools and versions used
   - Raw scan outputs (summarized)

**Deliverable 3: Findings Database** (Due: With final report)
- Machine-readable format (JSON or CSV)
- All vulnerabilities with CVSS scores
- CWE identifiers
- Affected components
- Remediation status tracking fields

**Deliverable 4: Executive Presentation** (Due: 5 business days after report)
- PowerPoint or similar format
- 30-minute presentation to stakeholders
- Key findings and recommendations
- Risk summary
- Remediation roadmap

**Deliverable 5: Retest Report** (Due: 10 business days after remediation)
- Verification of remediation for all High and Critical findings
- Regression testing results
- Updated CVSS scores
- Residual risk assessment
- Final security posture rating

### 3.2 Delivery Format

- All reports in PDF format (unclassified)
- Findings database in JSON and CSV formats
- Presentation in PowerPoint (.pptx) format
- All deliverables delivered via secure file transfer (SFTP/HTTPS)

### 3.3 Report Marking

All deliverables shall be marked:
- **Classification**: UNCLASSIFIED
- **Distribution**: FOR OFFICIAL USE ONLY (FOUO)
- **Handling**: Controlled Unclassified Information (CUI) if containing sensitive findings

---

## 4. Period of Performance

### 4.1 Timeline

**Total Duration**: 16 weeks from contract award

| Phase | Duration | Milestone |
|-------|----------|-----------|
| Planning & Kickoff | Week 1 | Test plan delivered |
| Environment Setup | Week 1-2 | Test environment ready |
| Reconnaissance | Week 2-3 | Attack surface identified |
| Vulnerability Assessment | Week 3-4 | Vulnerabilities documented |
| Exploitation | Week 5-6 | Exploitation attempts complete |
| Post-Exploitation | Week 7 | Data access verified |
| Report Writing | Week 8-9 | Draft report delivered |
| Report Review | Week 10 | Final report delivered |
| Remediation Period | Week 11-14 | Government remediates findings |
| Retesting | Week 15 | Retesting complete |
| Final Reporting | Week 16 | Retest report delivered |

### 4.2 Key Meetings

**Kickoff Meeting** (Week 1):
- Test plan review
- Scope confirmation
- Credential handoff
- Schedule finalization

**Status Meetings** (Weekly):
- Progress updates
- Issue resolution
- Timeline adjustments

**Findings Briefing** (Week 7):
- Preliminary findings presentation
- Critical/High finding immediate notification
- Remediation discussion

**Final Presentation** (Week 10):
- Executive presentation delivery
- Stakeholder Q&A
- Remediation planning

**Retest Closeout** (Week 16):
- Retest results review
- Residual risk acceptance
- Lessons learned

---

## 5. Contractor Qualifications

### 5.1 Corporate Qualifications

**Minimum Requirements**:
- Minimum 5 years of penetration testing experience
- Experience with federal or DoD systems (3+ engagements)
- Active FedRAMP authorized service provider status (**highly preferred**)
- ISO 27001 certification (**preferred**)
- Professional liability insurance (minimum $2 million coverage)
- SOC 2 Type II attestation (**preferred**)

**Mandatory Submissions**:
- Company background and history
- ISO 27001 certificate (if applicable)
- FedRAMP authorization status
- Professional liability insurance certificate
- Past performance references (minimum 3)

### 5.2 Personnel Qualifications

**Lead Penetration Tester** (1 required):
- **Certifications** (minimum one):
  - OSCP (Offensive Security Certified Professional)
  - GPEN (GIAC Penetration Tester)
  - GXPN (GIAC Exploit Researcher and Advanced Penetration Tester)
  - CREST Registered Tester (CRT) or equivalent
- **Experience**:
  - Minimum 7 years penetration testing experience
  - Experience with federal/DoD systems
  - Windows security expertise
  - PKI/certificate management testing experience
- **Clearance**: Secret clearance (**preferred** for DoD deployments)

**Penetration Testers** (2-3 required):
- **Certifications** (minimum one per tester):
  - CEH (Certified Ethical Hacker)
  - OSCP
  - GPEN
  - CompTIA PenTest+
- **Experience**:
  - Minimum 3 years penetration testing experience
  - Windows and/or Linux security expertise
  - Network protocol analysis experience
  - Code review experience (Rust **highly preferred**)

**Cryptography Subject Matter Expert** (1 required, can be dual-role):
- **Qualifications**:
  - Cryptography expertise (FIPS 140-2/140-3 knowledge)
  - Experience testing cryptographic implementations
  - Understanding of side-channel attacks
  - Knowledge of NIST cryptographic standards

**Technical Writer** (1 required, can be dual-role):
- **Qualifications**:
  - Technical writing experience
  - Security report writing experience
  - CVSS scoring expertise
  - Federal reporting format familiarity

### 5.3 Security Requirements

**Personnel Security**:
- All personnel must pass government background check (minimum Public Trust)
- Secret clearance **preferred** for classified environments
- U.S. citizenship required for all testing personnel
- Non-Disclosure Agreement (NDA) required

**Data Handling**:
- Secure laptop/workstation for testing
- Encrypted storage for all test data
- Secure file transfer capabilities (SFTP/HTTPS)
- Data destruction certification after contract completion

---

## 6. Test Environment

### 6.1 Government-Provided Resources

The Government will provide:

**Test Infrastructure**:
- Isolated test network (no production access)
- Test EST server instance
- Windows test machines (various versions)
- Unix/Linux test machines (if applicable)
- Network monitoring/packet capture capability

**Software and Access**:
- EST Client source code repository access (read-only)
- Architecture and design documentation
- Test credentials (admin, standard user, service account)
- Test certificates (valid, expired, revoked, self-signed)
- VPN access to test environment (if remote testing)

**Points of Contact**:
- Technical POC (architecture questions)
- Security POC (findings escalation)
- Operations POC (environment issues)

### 6.2 Contractor-Provided Resources

The Contractor shall provide:

**Testing Tools**:
- Penetration testing software (Burp Suite, Metasploit, etc.)
- Network analysis tools (Wireshark, tcpdump, etc.)
- Code analysis tools (static and dynamic)
- Vulnerability scanners
- Cryptographic analysis tools

**Hardware**:
- Testing laptops/workstations
- Secure storage devices
- Network testing equipment (if needed)

**Software Licenses**:
- All necessary tool licenses
- Operating system licenses (if additional VMs needed)

---

## 7. Severity and Risk Scoring

### 7.1 CVSS v3.1 Scoring

All findings shall be scored using **CVSS v3.1** (Common Vulnerability Scoring System).

**Required Elements**:
- Base score (0.0 - 10.0)
- Vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- Exploitability metrics
- Impact metrics
- Scope

### 7.2 Severity Ratings

| Severity | CVSS Score | Remediation SLA | Examples |
|----------|------------|-----------------|----------|
| **Critical** | 9.0 - 10.0 | 7 days | Remote code execution (unauthenticated), complete system compromise |
| **High** | 7.0 - 8.9 | 30 days | Privilege escalation to SYSTEM, authentication bypass, key extraction |
| **Medium** | 4.0 - 6.9 | 90 days | Information disclosure, denial of service, weak cryptography |
| **Low** | 0.1 - 3.9 | 180 days | Configuration weaknesses, minor information leaks |
| **Informational** | 0.0 | Next release | Best practices, hardening recommendations |

### 7.3 CWE Mapping

All findings shall include **CWE** (Common Weakness Enumeration) identifiers:
- Primary CWE (most applicable)
- Secondary CWEs (if multiple weaknesses)
- CWE category (e.g., CWE-287: Improper Authentication)

---

## 8. Rules of Engagement

### 8.1 Authorized Activities

The contractor **IS AUTHORIZED** to:

- Perform vulnerability scanning of in-scope systems
- Attempt exploitation of identified vulnerabilities
- Perform man-in-the-middle attacks in test environment
- Analyze network traffic (packet capture)
- Review source code for vulnerabilities
- Attempt privilege escalation on test systems
- Test authentication bypass techniques
- Perform denial-of-service testing (coordinated)
- Extract keys from test systems
- Modify test system configurations

### 8.2 Prohibited Activities

The contractor **SHALL NOT**:

- Access production systems or data
- Test out-of-scope systems
- Perform social engineering (unless explicitly authorized)
- Perform physical attacks (unless explicitly authorized)
- Share findings with unauthorized parties
- Retain data after contract completion (without authorization)
- Perform destructive testing without approval
- Use zero-day exploits without prior approval
- Test during business hours (if production-adjacent) without coordination

### 8.3 Emergency Procedures

**Critical Finding Notification**:
- **Critical vulnerabilities** (CVSS 9.0+) must be reported within **4 hours** of discovery
- **High vulnerabilities** (CVSS 7.0-8.9) must be reported within **24 hours** of discovery
- Notification via secure email or phone to Government Security POC

**Stop Work Conditions**:
- Unintended production system access
- Unintended data exposure or exfiltration
- System instability or crashes
- Network outages affecting operations
- Any activity outside approved scope

**Reporting**: Contact Government Technical POC immediately and cease testing until authorized to continue.

---

## 9. Proposal Requirements

### 9.1 Proposal Format

Proposals shall be submitted in **three volumes**:

**Volume I: Technical Proposal** (40 pages maximum, excluding resumes)
- Section 1: Understanding of Requirements
- Section 2: Technical Approach and Methodology
- Section 3: Project Management Plan
- Section 4: Risk Management
- Section 5: Quality Assurance
- Section 6: Deliverables Plan

**Volume II: Management Proposal** (20 pages maximum)
- Section 1: Corporate Qualifications
- Section 2: Personnel Qualifications (include resumes)
- Section 3: Past Performance (minimum 3 references)
- Section 4: Security and Data Handling
- Section 5: Certifications and Licenses

**Volume III: Cost Proposal** (separate, sealed)
- Section 1: Pricing Summary
- Section 2: Labor Breakdown
- Section 3: Other Direct Costs (ODCs)
- Section 4: Assumptions

### 9.2 Technical Proposal Content

**Section 1: Understanding of Requirements** (3-5 pages)
- Demonstrate understanding of EST Client architecture
- Identify key security challenges
- Discuss threat landscape for PKI systems
- Describe testing priorities

**Section 2: Technical Approach** (10-15 pages)
- Detailed testing methodology
- Test phases and timeline
- Tools and techniques
- Coverage approach for each test category
- Handling of Windows-specific components
- Cryptographic testing approach
- Code review methodology

**Section 3: Project Management Plan** (5-8 pages)
- Project organization chart
- Key personnel roles
- Communication plan
- Schedule with milestones
- Status reporting approach

**Section 4: Risk Management** (3-5 pages)
- Identified project risks
- Mitigation strategies
- Contingency plans

**Section 5: Quality Assurance** (2-3 pages)
- QA processes for testing accuracy
- Report review process
- False positive management
- Peer review procedures

**Section 6: Deliverables Plan** (2-3 pages)
- Deliverable templates and examples
- Review and approval process
- Delivery methods and security

### 9.3 Management Proposal Content

**Section 1: Corporate Qualifications** (3-5 pages)
- Company background
- Relevant experience (federal/DoD)
- Certifications (ISO 27001, FedRAMP, SOC 2)
- Quality management systems

**Section 2: Personnel Qualifications** (10-15 pages)
- Personnel matrix (roles, certifications, experience)
- Resumes for key personnel (not counted in page limit)
- Clearance status
- Availability and commitment

**Section 3: Past Performance** (5-8 pages)
- Minimum 3 references (federal/DoD **preferred**)
- Contract details (customer, scope, value, dates)
- Similar projects (PKI, cryptography, Windows security)
- Performance ratings
- Lessons learned

**Section 4: Security and Data Handling** (2-3 pages)
- Data protection measures
- Secure communication procedures
- Data destruction process
- Incident response procedures

**Section 5: Certifications and Licenses** (Appendix)
- ISO 27001 certificate
- FedRAMP authorization (if applicable)
- SOC 2 report
- Insurance certificates
- Tool licenses

### 9.4 Cost Proposal Content

**Pricing Summary**:
```
Total Contract Value: $___________

Breakdown:
  - Initial Penetration Test:     $___________ (FFP)
  - Retest (after remediation):   $___________ (FFP)
  - Optional: Ad-hoc Testing:     $___________ (per engagement)
```

**Labor Breakdown**:
- Labor categories and rates
- Estimated hours per category
- Labor subtotal

**Other Direct Costs (ODCs)**:
- Travel (if required)
- Tools and licenses
- Subcontractor costs (if applicable)
- Other costs

**Assumptions**:
- Clear statement of assumptions
- Exclusions
- Government-provided items dependency

---

## 10. Evaluation Criteria

### 10.1 Evaluation Methodology

Proposals will be evaluated using a **Best Value Trade-off** approach considering technical merit, past performance, and cost.

**Evaluation Factors** (in order of importance):

1. **Technical Approach** (40 points)
2. **Personnel Qualifications** (30 points)
3. **Past Performance** (20 points)
4. **Cost** (10 points)

**Total**: 100 points

The Government reserves the right to award to other than the lowest-priced offeror if the higher technical rating provides best value.

### 10.2 Technical Approach Evaluation (40 points)

**Criteria**:
- Understanding of EST Client security challenges (10 points)
- Testing methodology comprehensiveness (15 points)
- Windows and cryptographic testing approach (10 points)
- Risk management and quality assurance (5 points)

**Rating Scale**:
- **Outstanding** (90-100% of points): Exceptional approach, no weaknesses
- **Good** (75-89%): Strong approach, minor weaknesses
- **Acceptable** (60-74%): Adequate approach, some weaknesses
- **Marginal** (40-59%): Weak approach, significant weaknesses
- **Unacceptable** (0-39%): Does not meet requirements

### 10.3 Personnel Qualifications Evaluation (30 points)

**Criteria**:
- Lead tester qualifications and experience (10 points)
- Team composition and certifications (10 points)
- Cryptography expertise (5 points)
- Clearance status and availability (5 points)

**Rating Scale**: Same as Technical Approach

### 10.4 Past Performance Evaluation (20 points)

**Criteria**:
- Relevance of past projects (8 points)
- Customer satisfaction ratings (6 points)
- Quality of deliverables (4 points)
- Adherence to schedule and budget (2 points)

**Rating Scale**:
- **Exceptional** (90-100%): All references highly satisfied
- **Satisfactory** (70-89%): Most references satisfied
- **Neutral** (50-69%): Limited relevant experience
- **Unsatisfactory** (0-49%): Poor performance or no relevant experience

### 10.5 Cost Evaluation (10 points)

**Methodology**:
- Lowest priced proposal receives 10 points
- Other proposals scored proportionally: (Lowest Price / Proposal Price) × 10

**Cost Realism**:
- Unrealistically low prices may be rated as higher risk
- Cost proposals evaluated for completeness and reasonableness

### 10.6 Award Decision

The Government will award to the offeror whose proposal represents the **best value** considering:
- Technical superiority
- Personnel qualifications
- Past performance confidence
- Cost reasonableness

---

## 11. Submission Instructions

### 11.1 Proposal Due Date

**Proposals Due**: [DATE] by [TIME] [TIMEZONE]

**Delivery Method**: Electronic submission via [PORTAL/EMAIL]

**Late Submissions**: Will not be accepted

### 11.2 Questions and Amendments

**Questions Deadline**: [DATE - 15 days before proposal due]

**Submit Questions To**: [EMAIL ADDRESS]

**Answers Posted**: All questions and answers will be posted as amendments to [PORTAL/WEBSITE]

### 11.3 Submission Format

- **File Format**: PDF (separate files for each volume)
- **File Naming**: `[VOLUME]_[COMPANY-NAME]_[RFP-NUMBER].pdf`
- **Size Limit**: 50 MB per file
- **Encryption**: Encrypt Cost Proposal with password (password provided separately)

### 11.4 Point of Contact

**Contracting Officer**:
[NAME]
[TITLE]
[AGENCY]
[ADDRESS]
[EMAIL]
[PHONE]

**Technical Point of Contact**:
[NAME]
[TITLE]
[EMAIL]
[PHONE]

---

## 12. Terms and Conditions

### 12.1 Contract Type

**Firm Fixed Price (FFP)** contract for all deliverables.

### 12.2 Payment Terms

**Payment Schedule**:
- 20% upon test plan approval
- 40% upon final report delivery
- 20% upon executive presentation
- 20% upon retest report delivery

**Invoicing**: Net 30 days from invoice receipt

### 12.3 Data Rights

**Government Rights**:
- Unlimited rights to all deliverables (reports, findings, presentations)
- Source code remains Government property (provided for testing only)

**Contractor Rights**:
- May use anonymized findings for internal training (with Government approval)
- May reference contract in past performance (no specific findings disclosed)

### 12.4 Confidentiality

- All findings and data are **Controlled Unclassified Information (CUI)**
- Non-Disclosure Agreement (NDA) required before contract award
- Contractor shall not disclose findings publicly
- Data destruction certification required within 30 days of contract completion

### 12.5 Compliance

Contractor shall comply with:
- Federal Acquisition Regulation (FAR)
- Defense Federal Acquisition Regulation Supplement (DFARS) (if DoD)
- NIST SP 800-171 (if handling CUI)
- Applicable federal and state laws

---

## 13. Appendices

### Appendix A: Acronyms and Definitions

| Acronym | Definition |
|---------|------------|
| ATO | Authorization to Operate |
| CNG | Cryptography Next Generation |
| CUI | Controlled Unclassified Information |
| CVSS | Common Vulnerability Scoring System |
| CWE | Common Weakness Enumeration |
| DPAPI | Data Protection API |
| EST | Enrollment over Secure Transport |
| FedRAMP | Federal Risk and Authorization Management Program |
| FFP | Firm Fixed Price |
| FOUO | For Official Use Only |
| GPEN | GIAC Penetration Tester |
| MITM | Man-in-the-Middle |
| NIST | National Institute of Standards and Technology |
| OSCP | Offensive Security Certified Professional |
| OWASP | Open Web Application Security Project |
| PKI | Public Key Infrastructure |
| PTES | Penetration Testing Execution Standard |
| RFP | Request for Proposal |
| TPM | Trusted Platform Module |

### Appendix B: Reference Documents

The following documents are provided for offeror reference:

1. **Penetration Testing Requirements** - [penetration-testing-requirements.md](penetration-testing-requirements.md)
2. **EST Client Architecture Overview** - [TO BE PROVIDED]
3. **Security Controls Matrix** - [poam.md](poam.md)
4. **NIST SP 800-115** - Technical Guide to Information Security Testing
5. **FedRAMP Penetration Test Guidance** - Available at fedramp.gov

### Appendix C: Sample Finding Template

See: [penetration-test-finding-template.md](penetration-test-finding-template.md)

### Appendix D: Proposal Checklist

**Volume I - Technical Proposal**:
- [ ] Section 1: Understanding of Requirements
- [ ] Section 2: Technical Approach and Methodology
- [ ] Section 3: Project Management Plan
- [ ] Section 4: Risk Management
- [ ] Section 5: Quality Assurance
- [ ] Section 6: Deliverables Plan
- [ ] Page limit met (40 pages maximum, excluding resumes)

**Volume II - Management Proposal**:
- [ ] Section 1: Corporate Qualifications
- [ ] Section 2: Personnel Qualifications with resumes
- [ ] Section 3: Past Performance (minimum 3 references)
- [ ] Section 4: Security and Data Handling
- [ ] Section 5: Certifications and Licenses (appendix)
- [ ] Page limit met (20 pages maximum, excluding resumes and appendices)

**Volume III - Cost Proposal**:
- [ ] Pricing summary
- [ ] Labor breakdown with rates
- [ ] Other Direct Costs (ODCs)
- [ ] Assumptions clearly stated
- [ ] File encrypted with password

**General**:
- [ ] All volumes in PDF format
- [ ] File naming convention followed
- [ ] Submitted by deadline
- [ ] Questions submitted (if any) by questions deadline

---

**END OF REQUEST FOR PROPOSAL**

**Issue Date**: [DATE]
**Issuing Office**: [AGENCY NAME]
**Contracting Officer**: [NAME]
**Signature**: _______________________
**Date**: _______________________
