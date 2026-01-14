# Security Update Service Level Agreement (SLA)

## EST Client Library for Windows

**Version:** 1.0
**Effective Date:** 2026-01-13
**Classification:** UNCLASSIFIED
**Review Cycle:** Quarterly

---

## 1. Executive Summary

This document defines the Service Level Agreement (SLA) for security updates and vulnerability remediation for the EST Client Library. It establishes response times, notification procedures, and support commitments for security issues affecting production deployments.

**Key Commitments:**
- **CRITICAL vulnerabilities**: Patch within 24 hours
- **HIGH vulnerabilities**: Patch within 7 days
- **MEDIUM vulnerabilities**: Patch within 30 days
- **LOW vulnerabilities**: Patch within 90 days

---

## 2. Scope

### 2.1 Covered Software

This SLA applies to:
- **EST Client Library** (usg-est-client crate)
- **Windows Service** (est-autoenroll-service binary)
- **CLI Tools** (est-enroll, est-service-install binaries)
- **Direct Dependencies** (security vulnerabilities in dependencies)

### 2.2 Supported Versions

Security updates are provided for:

| Version | Support Status | Security Updates | End of Support |
|---------|----------------|------------------|----------------|
| **1.x (current)** | ✅ Full Support | Yes | Until 2.0 release + 1 year |
| **0.x (legacy)** | ⚠️ Best Effort | Critical only | 2026-12-31 |

**Support Policy:**
- **Current major version (1.x)**: Full security support
- **Previous major version (N-1)**: Critical vulnerabilities only for 1 year after new major release
- **Older versions**: No security support (upgrade required)

### 2.3 Deployment Models

This SLA covers:
- ✅ **Production deployments** (DoD, federal, enterprise)
- ✅ **Development/testing** (best effort)
- ⚠️ **Modified/forked versions** (support on case-by-case basis)

---

## 3. Vulnerability Severity Definitions

### 3.1 Severity Levels

Severity is determined using CVSS v3.1 scoring with DoD-specific adjustments:

#### CRITICAL (CVSS 9.0-10.0)

**Definition:** Vulnerabilities that can be exploited remotely with no authentication, leading to:
- Complete system compromise
- Arbitrary code execution as SYSTEM/Administrator
- Root CA or PKI infrastructure compromise
- Mass certificate issuance or theft

**Examples:**
- Remote code execution without authentication
- EST server impersonation allowing arbitrary certificate issuance
- Private key extraction via network attack
- DoD PKI root certificate replacement

**Impact:** Immediate risk to all deployments, potential ATO revocation

#### HIGH (CVSS 7.0-8.9)

**Definition:** Vulnerabilities that can be exploited with limited complexity, leading to:
- Unauthorized certificate enrollment
- Certificate validation bypass
- Authentication bypass
- Privilege escalation to Administrator
- Sensitive data exposure (private keys, credentials)

**Examples:**
- Certificate validation bypass allowing rogue certificates
- Authentication bypass for EST server access
- Local privilege escalation to SYSTEM
- Private key exposure via local attack
- FIPS module bypass

**Impact:** Significant risk, requires immediate attention

#### MEDIUM (CVSS 4.0-6.9)

**Definition:** Vulnerabilities requiring specific conditions or user interaction:
- Information disclosure (non-critical)
- Denial of service (local)
- Configuration tampering
- Audit log manipulation

**Examples:**
- EST server URL disclosure
- Local denial of service via malformed config
- Certificate store enumeration by unprivileged users
- Audit log deletion by authenticated users
- Weak default configuration

**Impact:** Moderate risk, plan remediation

#### LOW (CVSS 0.1-3.9)

**Definition:** Minimal impact vulnerabilities:
- Information disclosure (minimal value)
- Denial of service (easily recoverable)
- Minor security hardening opportunities

**Examples:**
- Service version disclosure
- Non-sensitive log information disclosure
- Temporary denial of service (service restart recovers)
- Race conditions with minimal impact

**Impact:** Low risk, address in regular updates

### 3.2 Severity Modifiers

**Increase Severity By One Level If:**
- Affects FIPS 140-2 validated cryptography
- Affects DoD PKI certificate validation
- Affects Windows SYSTEM service
- Exploitable in default configuration
- No authentication required
- Affects production DoD deployments

**Decrease Severity By One Level If:**
- Requires Administrator privileges
- Requires physical access
- Affects deprecated features only
- Requires complex preconditions
- Affects non-default configuration only

### 3.3 Severity Assessment Process

**Step 1: CVSS Base Score**
- Calculate using CVSS v3.1 calculator
- Use attack vector, complexity, privileges, user interaction

**Step 2: Apply Modifiers**
- Evaluate DoD-specific impacts
- Consider deployment context
- Assess exploitability

**Step 3: Peer Review**
- Security team reviews assessment
- Stakeholder input for production impact
- Final severity determination

**Step 4: Publication**
- Severity published in security advisory
- CVSS vector string included
- Justification documented

---

## 4. Response Timelines

### 4.1 Response SLA by Severity

| Severity | Acknowledgment | Initial Assessment | Patch Release | Notification |
|----------|----------------|-------------------|---------------|--------------|
| **CRITICAL** | 2 hours | 4 hours | 24 hours | Immediate |
| **HIGH** | 8 hours | 24 hours | 7 days | Within 24 hours |
| **MEDIUM** | 24 hours | 5 days | 30 days | With patch release |
| **LOW** | 72 hours | 14 days | 90 days | With patch release |

**Timeline Notes:**
- Timelines start from vulnerability disclosure (internal discovery or external report)
- Business days for MEDIUM and LOW severity
- Calendar days (24/7) for CRITICAL and HIGH severity
- Timelines may be extended with justification and notification

### 4.2 Response Actions

#### Acknowledgment
- Confirm receipt of vulnerability report
- Assign tracking ID (format: `USG-EST-YYYY-NNNN`)
- Provide expected timeline
- Identify point of contact

#### Initial Assessment
- Verify vulnerability reproduction
- Determine severity (CVSS scoring)
- Identify affected versions
- Assess exploitability
- Determine remediation approach

#### Patch Development
- Develop and test fix
- Create regression tests
- Validate fix effectiveness
- Prepare security advisory
- Code review and approval

#### Patch Release
- Release patched version
- Publish security advisory
- Update documentation
- Notify stakeholders

### 4.3 Emergency Response (CRITICAL)

For CRITICAL vulnerabilities, activate emergency response:

**Hour 0-2:**
- Acknowledge vulnerability
- Convene emergency response team
- Begin impact assessment
- Activate notification tree

**Hour 2-4:**
- Complete severity assessment
- Identify affected systems
- Develop mitigation guidance
- Prepare initial advisory

**Hour 4-12:**
- Develop patch
- Test fix in lab environment
- Peer review code changes
- Prepare release

**Hour 12-24:**
- Final testing
- Release patch
- Publish security advisory
- Notify all stakeholders
- Monitor deployment

**Hour 24-48:**
- Verify patch deployment
- Monitor for exploitation attempts
- Provide deployment support
- Conduct post-incident review

---

## 5. Vulnerability Disclosure Process

### 5.1 Reporting Channels

**Preferred Method:** GitHub Security Advisories (Private)
- Navigate to: https://github.com/johnwillman/usg-est-client/security/advisories
- Click "Report a vulnerability"
- Provide detailed information

**Alternative Methods:**
- **Email:** security@[organization].mil (for DoD deployments)
- **Encrypted Email:** PGP key available at [URL]
- **Phone:** [DoD Security Hotline] (CRITICAL issues only)

**DO NOT:**
- ❌ Create public GitHub issues
- ❌ Discuss on public forums/social media
- ❌ Disclose details before patch release

### 5.2 Required Information

When reporting vulnerabilities, please provide:

**Essential:**
- Vulnerability description
- Affected version(s)
- Steps to reproduce
- Potential impact

**Helpful:**
- Proof of concept (code or commands)
- Screenshots or logs
- Suggested fix (if any)
- CVSS score (if calculated)

**Optional:**
- Your contact information
- Disclosure timeline preferences
- CVE assignment request

### 5.3 Disclosure Timeline

**Standard Timeline:**
- **Day 0**: Vulnerability reported
- **Day 1**: Acknowledgment sent
- **Day 7** (HIGH/CRITICAL): Patch released
- **Day 7**: Security advisory published
- **Day 90**: Full technical details published (if appropriate)

**Coordinated Disclosure:**
- We work with reporters to coordinate disclosure
- 90-day disclosure deadline (from report date)
- Earlier disclosure if actively exploited
- Extensions granted for complex vulnerabilities

**Public Disclosure:**
- After patch release and reasonable deployment time
- With reporter's consent (if they wish credit)
- Include CVE ID, CVSS score, remediation steps

### 5.4 Researcher Recognition

We believe in recognizing security researchers:

**Hall of Fame:**
- Security researchers credited in SECURITY.md
- Listed in security advisory (with permission)
- Recognition in release notes

**No Bug Bounty Program:**
- We do not currently offer monetary rewards
- Research is appreciated and recognized
- Consider contributing fixes via pull requests

---

## 6. Patch Distribution

### 6.1 Distribution Channels

**Primary Channel:** GitHub Releases
- **URL:** https://github.com/johnwillman/usg-est-client/releases
- Tagged releases with semantic versioning
- Release notes include security advisories
- Binaries available for download

**Secondary Channels:**
- **crates.io:** https://crates.io/crates/usg-est-client
- **DoD DevSecOps Platform:** [Internal mirror for DoD deployments]
- **Organization Package Repositories:** [As configured]

### 6.2 Patch Versioning

Security patches follow semantic versioning:

**Patch Version (1.0.X):**
- Security fixes only
- No breaking changes
- No new features
- Examples: 1.0.1, 1.0.2

**Minor Version (1.X.0):**
- Security fixes plus enhancements
- Backward compatible
- May include new features
- Examples: 1.1.0, 1.2.0

**Major Version (X.0.0):**
- Security fixes plus breaking changes
- May require configuration updates
- Migration guide provided
- Examples: 2.0.0, 3.0.0

**Example Security Release:**
```
Version: 1.0.3
Type: Security Patch
Release Date: 2026-01-15
CVEs: USG-EST-2026-0001 (HIGH)
Description: Fixes certificate validation bypass
```

### 6.3 Release Process

**Security Release Steps:**

1. **Prepare Release:**
   - Create release branch (e.g., `security/1.0.3`)
   - Apply security fix
   - Update version numbers
   - Update CHANGELOG.md

2. **Testing:**
   - Run full test suite
   - Execute security-specific tests
   - Verify fix effectiveness
   - Test on supported platforms

3. **Review:**
   - Security team review
   - Code review (if appropriate)
   - ISSO review (for DoD deployments)
   - Authorizing Official notification (CRITICAL)

4. **Release:**
   - Tag release (e.g., `v1.0.3`)
   - Build release binaries
   - Sign binaries (Authenticode)
   - Publish to GitHub Releases
   - Publish to crates.io
   - Update documentation

5. **Notification:**
   - Publish security advisory
   - Email notification list
   - Update SECURITY.md
   - Post to forums/mailing lists

---

## 7. Security Advisories

### 7.1 Advisory Format

Security advisories follow this structure:

```
Title: [Severity] Vulnerability Description (USG-EST-YYYY-NNNN)

Summary:
[One-paragraph summary of the vulnerability and impact]

Severity: [CRITICAL/HIGH/MEDIUM/LOW]
CVSS Score: X.X (CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X)
CVE ID: CVE-YYYY-NNNNN (if assigned)

Affected Versions:
- usg-est-client: X.X.X - X.X.X

Fixed Versions:
- usg-est-client: X.X.X+

Description:
[Detailed vulnerability description]

Impact:
[What an attacker could achieve]

Affected Components:
- [Component 1]
- [Component 2]

Reproduction:
[Steps to reproduce, if appropriate to disclose]

Mitigation:
[Workarounds if patch not immediately applicable]

Remediation:
[How to fix - upgrade instructions]

Timeline:
- YYYY-MM-DD: Vulnerability reported
- YYYY-MM-DD: Vulnerability confirmed
- YYYY-MM-DD: Patch released
- YYYY-MM-DD: Advisory published

Credits:
- Discovered by: [Researcher Name] (with permission)

References:
- GitHub Security Advisory: [URL]
- CVE Details: [URL]
- Patch Commit: [URL]
```

### 7.2 Advisory Distribution

**Publication Channels:**
- **GitHub Security Advisories:** Primary source of truth
- **SECURITY.md:** List of all advisories
- **Release Notes:** Security fixes listed
- **Mailing List:** security-announce@[organization]
- **RSS Feed:** GitHub releases feed
- **DoD Cyber Exchange:** For DoD-specific issues

**Notification List:**
- Known production deployments
- DoD ISSO contacts
- Security researchers (opted-in)
- Integration partners
- Enterprise customers

### 7.3 CVE Assignment

**Process:**
- Request CVE from MITRE or GitHub CVE Numbering Authority (CNA)
- Provide CVE in security advisory
- Update National Vulnerability Database (NVD) entry
- Reference CVE in all documentation

**CVE Naming:**
- Format: `CVE-YYYY-NNNNN`
- Year: Discovery year
- Number: Sequential

---

## 8. Dependency Management

### 8.1 Dependency Scanning

**Automated Scanning:**
- **Daily:** `cargo audit` via GitHub Actions
- **Daily:** `cargo deny` license and advisory checks
- **Weekly:** Dependabot pull requests
- **Monthly:** Manual dependency review

**Scan Scope:**
- Direct dependencies
- Transitive dependencies
- Dev dependencies (for supply chain risk)

### 8.2 Dependency Update Policy

**CRITICAL/HIGH Dependency Vulnerabilities:**
- Update within 24-48 hours
- Release patch version
- Notify users immediately

**MEDIUM Dependency Vulnerabilities:**
- Update within 7 days
- Include in next scheduled release
- Notify via release notes

**LOW Dependency Vulnerabilities:**
- Update within 30 days
- Include in regular maintenance release

**Unmaintained Dependencies:**
- Replace within 60 days
- Evaluate alternatives
- Consider forking if critical

### 8.3 Supply Chain Security

**Measures:**
- ✅ All dependencies from crates.io (trusted registry)
- ✅ Cargo.lock committed to repository
- ✅ Dependency license verification (cargo-deny)
- ✅ SBOM generation (SPDX, CycloneDX)
- ✅ Checksum verification
- 🔄 Code signing (planned SI-002)
- 🔄 SLSA provenance (planned SI-002)

---

## 9. Compliance and Governance

### 9.1 NIST SP 800-53 Rev 5 Compliance

This SLA satisfies the following controls:

**SI-2: Flaw Remediation**
- ✅ SI-2(a): Identify, report, and correct flaws
- ✅ SI-2(b): Test patches before installation
- ✅ SI-2(c): Install security-relevant patches within established timeframes
- ✅ SI-2(2): Automated flaw remediation status (via GitHub Actions)

**SI-5: Security Alerts, Advisories, and Directives**
- ✅ SI-5(a): Receive security alerts and advisories
- ✅ SI-5(b): Generate internal security alerts as needed
- ✅ SI-5(c): Implement security directives

**RA-5: Vulnerability Monitoring and Scanning**
- ✅ RA-5(a): Monitor for vulnerabilities
- ✅ RA-5(b): Employ vulnerability monitoring tools
- ✅ RA-5(5): Privileged access for scanning

### 9.2 DoD STIG Compliance

**APSC-DV-002570 (CAT II):**
- Application must provide near real-time alerts for security-related events
- ✅ SATISFIED: GitHub Security Advisories, email notifications

**APSC-DV-003270 (CAT II):**
- Application must protect audit information from unauthorized modification
- ✅ SATISFIED: GitHub commit history, signed releases (planned)

### 9.3 FedRAMP Compliance

**SI-2: Flaw Remediation**
- High impact systems: 30 days for High/Critical
- ✅ EXCEEDS: 24 hours (Critical), 7 days (High)

**RA-5: Vulnerability Scanning**
- Continuous monitoring required
- ✅ SATISFIED: Daily automated scanning

### 9.4 SLA Review and Updates

**Review Cycle:** Quarterly

**Review Triggers:**
- Major vulnerability incident
- Significant process improvement
- Compliance requirement changes
- Stakeholder feedback

**Review Process:**
1. Collect metrics on SLA performance
2. Gather stakeholder feedback
3. Assess adequacy of response times
4. Identify improvement opportunities
5. Update SLA as needed
6. Publish updated version

---

## 10. Metrics and Reporting

### 10.1 SLA Performance Metrics

**Tracked Metrics:**
- Time to acknowledgment (by severity)
- Time to patch release (by severity)
- SLA adherence rate (% met within timeline)
- Number of vulnerabilities (by severity, by quarter)
- Mean time to remediation (MTTR)
- Patch deployment rate (% of users upgraded within 30 days)

**Reporting:**
- Quarterly security report
- Annual ATO review
- Metrics included in POA&M reviews

### 10.2 Incident Tracking

**Tracking System:** GitHub Security Advisories + Internal tracker

**Tracked Information:**
- Vulnerability ID (USG-EST-YYYY-NNNN)
- Discovery date
- Reporter information
- Severity assessment
- Affected versions
- Timeline milestones
- Patch version
- Deployment status

### 10.3 Transparency

**Public Reporting:**
- Security advisories published after patch release
- Quarterly vulnerability summary in release notes
- Annual security report

**Confidential Reporting:**
- Details of unremediated vulnerabilities (pre-patch)
- Exploitation attempts
- Specific deployment information

---

## 11. Support and Assistance

### 11.1 Deployment Support

**Patch Deployment Assistance:**
- Migration guides for breaking changes
- Rollback procedures if issues occur
- Hotline for CRITICAL patches (DoD deployments)

**Hours of Support:**
- **CRITICAL vulnerabilities:** 24/7 support
- **HIGH vulnerabilities:** Business hours + on-call
- **MEDIUM/LOW vulnerabilities:** Business hours

### 11.2 Communication Channels

**For Security Issues:**
- GitHub Security Advisories (preferred)
- Email: security@[organization]
- Phone: [Security Hotline] (CRITICAL only)

**For Patch Deployment Questions:**
- GitHub Discussions: https://github.com/johnwillman/usg-est-client/discussions
- Email: support@[organization]
- DoD users: [DoD support channel]

### 11.3 Escalation

**Escalation Path:**
1. **Security Team** → Initial response and assessment
2. **Development Lead** → Patch development and testing
3. **System Owner** → Major incident coordination
4. **ISSO** → DoD deployment impact assessment
5. **Authorizing Official** → ATO impact (CRITICAL issues)

---

## 12. Limitations and Disclaimers

### 12.1 Best Effort Basis

This SLA represents best-effort commitments. Response times may be extended due to:
- Complexity of vulnerability
- Unavailability of patches from upstream dependencies
- Resource constraints
- Holidays and weekends (for MEDIUM/LOW)

Extensions will be communicated promptly with justification.

### 12.2 Exclusions

This SLA does NOT cover:
- Vulnerabilities in third-party software (except direct dependencies)
- Misconfigurations by administrators
- Intentional misuse of the software
- Modified or forked versions (without coordination)
- Unsupported versions (beyond EOL)
- Zero-day exploits before discovery/disclosure

### 12.3 Warranty Disclaimer

This software is provided "AS IS" under the Apache 2.0 license without warranty. This SLA represents operational commitments but does not constitute a legal warranty or guarantee.

---

## 13. Appendices

### Appendix A: Contact Information

**Security Team:**
- Email: security@[organization].mil
- PGP Key: [Fingerprint]
- Phone: [DoD Security Hotline]

**Project Maintainers:**
- GitHub: @[maintainer-username]
- Email: [maintainer]@[organization]

**DoD Contacts:**
- ISSO: [Name, Email, Phone]
- System Owner: [Name, Email, Phone]

### Appendix B: Security Advisory Template

See Section 7.1 for detailed advisory format.

### Appendix C: Related Documents

- [Vulnerability Management & SBOM Guide](./vulnerability-management.md)
- [Incident Response Plan](./incident-response.md)
- [POA&M](./poam.md) - SI-001
- [SECURITY.md](../../SECURITY.md) - Main security documentation

### Appendix D: Revision History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-01-13 | Initial release (POA&M SI-001) | Security Team |

---

## Document Approval

**Prepared By:** Security Team
**Date:** 2026-01-13

**Reviewed By:** System Owner
**Date:** 2026-01-13

**Approved By:** ISSO
**Date:** 2026-01-13

**Next Review Date:** 2026-04-13

---

**Document Classification:** UNCLASSIFIED
**Page Count:** 18
**Document ID:** USG-EST-SLA-v1.0

**END OF SECURITY UPDATE SLA**
