# Incident Response and Recovery Plan

## EST Client Library for Windows

**Version:** 1.0
**Date:** 2026-01-13
**Classification:** UNCLASSIFIED

---

## 1. Overview

This document defines incident response procedures, disaster recovery plans, and business continuity strategies for security events affecting the EST Client Library.

### 1.1 Incident Types and Severity

| Severity | Incident Type | Response Time | Escalation |
|----------|--------------|---------------|------------|
| **CRITICAL** | Root CA compromise, crypto module breach | 15 minutes | CISO, System Owner |
| **HIGH** | Private key exposure, authentication bypass | 1 hour | ISSO, Security Team |
| **MEDIUM** | Certificate misuse, config tampering | 4 hours | ISSO |
| **LOW** | Failed enrollments, policy violations | 24 hours | System Admin |

### 1.2 Incident Response Team

**Core Team:**
- **Incident Commander**: ISSO
- **Technical Lead**: System Owner
- **Security Analyst**: Security Team
- **Communications**: IT Management
- **Legal**: General Counsel (if needed)

---

## 2. Incident Response Phases

### 2.1 Detection and Analysis

**Detection Sources:**
- SIEM alerts (certificate events, auth failures)
- Security monitoring (IDS/IPS)
- User reports
- Audit log analysis
- Vulnerability scanner alerts

**Initial Assessment:**
1. Confirm incident validity
2. Determine incident type and severity
3. Identify affected systems
4. Preserve evidence
5. Activate response team

### 2.2 Containment

**Short-term Containment:**
- Isolate affected systems from network
- Revoke compromised certificates
- Block compromised accounts
- Disable auto-enrollment temporarily

**Long-term Containment:**
- Replace compromised certificates
- Update credentials
- Patch vulnerabilities
- Implement additional controls

### 2.3 Eradication

**Actions:**
- Remove malware/unauthorized access
- Close vulnerabilities
- Update systems to patched versions
- Verify clean state

### 2.4 Recovery

**Recovery Steps:**
1. Restore from clean backups
2. Re-enroll certificates
3. Verify functionality
4. Monitor for recurrence
5. Gradual service restoration

### 2.5 Post-Incident Activity

**Activities:**
- Document lessons learned
- Update incident response procedures
- Implement preventive measures
- Brief management
- Update security controls

---

## 3. Incident Response Playbooks

### 3.1 Private Key Exposure

**Detection Indicators:**
- Unauthorized key file access
- Key file copied to removable media
- Memory dump containing key material

**Response Actions:**
1. **Immediate** (0-15 min):
   - Identify compromised key
   - Revoke associated certificate
   - Block affected machine from EST server
2. **Short-term** (15 min - 4 hours):
   - Generate new key pair
   - Re-enroll certificate
   - Update certificate in applications
3. **Long-term** (4-24 hours):
   - Investigate how key was exposed
   - Implement additional key protection (CNG)
   - Review file system ACLs
   - Audit all systems for similar exposure

**Notification:**
- ISSO (immediate)
- System Owner (within 1 hour)
- Affected users (within 4 hours)
- CISO (if widespread)

### 3.2 Certificate Compromise

**Detection Indicators:**
- Certificate used from unauthorized location
- Certificate detected in threat intelligence
- Suspicious certificate enrollment patterns

**Response Actions:**
1. **Immediate** (0-30 min):
   - Revoke compromised certificate
   - Add to CRL
   - Publish emergency CRL update
2. **Short-term** (30 min - 2 hours):
   - Investigate compromise source
   - Review other certificates from same system
   - Re-enroll affected systems
3. **Long-term** (2-48 hours):
   - Root cause analysis
   - Implement preventive controls
   - Update security monitoring

### 3.3 EST Server Compromise

**Detection Indicators:**
- Unauthorized EST server configuration changes
- Malicious certificates issued
- EST server compromise notification

**Response Actions:**
1. **Immediate** (0-1 hour):
   - Disable EST client auto-enrollment
   - Block EST server access at firewall
   - Preserve EST client logs
2. **Short-term** (1-4 hours):
   - Coordinate with EST server team
   - Identify malicious certificates
   - Revoke suspicious certificates
3. **Long-term** (4-48 hours):
   - Verify EST server integrity
   - Re-establish trust
   - Resume auto-enrollment
   - Enhanced monitoring

### 3.4 Insider Threat

**Detection Indicators:**
- Unauthorized certificate operations
- Suspicious configuration changes
- Abnormal enrollment patterns
- Access outside normal hours

**Response Actions:**
1. **Immediate** (0-30 min):
   - Disable user/machine account
   - Revoke issued certificates
   - Preserve audit logs
2. **Short-term** (30 min - 4 hours):
   - Investigate scope of access
   - Identify compromised systems
   - Engage HR/Legal if employee
3. **Long-term** (4-72 hours):
   - Complete investigation
   - Implement access restrictions
   - Enhanced monitoring
   - Personnel actions

---

## 4. Disaster Recovery

### 4.1 Recovery Point Objective (RPO)

**Data Loss Tolerance:**
- **Configuration**: 24 hours (daily backup)
- **Certificates**: 0 hours (can be re-enrolled)
- **Audit Logs**: 1 hour (SIEM backup)
- **Private Keys**: 0 hours (ephemeral, regenerate)

### 4.2 Recovery Time Objective (RTO)

**Service Restoration Time:**
- **Critical Systems**: 4 hours
- **Standard Systems**: 24 hours
- **Low-Priority Systems**: 72 hours

### 4.3 Backup Procedures

**Configuration Backup:**
```powershell
# Daily backup script
$BackupPath = "\\backup-server\EST\Backups\$(Get-Date -Format 'yyyy-MM-dd')"
Copy-Item "C:\ProgramData\EST\config.toml" -Destination $BackupPath
Copy-Item "C:\ProgramData\EST\logs" -Destination $BackupPath -Recurse
```

**Backup Verification:**
- Weekly restore test
- Quarterly full recovery drill

### 4.4 Recovery Procedures

**Full System Recovery:**
1. Rebuild Windows system from baseline
2. Install EST Client from verified source
3. Restore configuration from backup
4. Re-enroll certificates
5. Verify functionality
6. Resume monitoring

**Configuration-Only Recovery:**
1. Stop EST service
2. Restore config.toml from backup
3. Validate configuration
4. Restart EST service
5. Verify enrollment

---

## 5. Business Continuity

### 5.1 Alternative EST Servers

**Failover Configuration:**
```toml
[server]
url = "https://est-primary.example.mil/.well-known/est"

# Failover servers (manual failover)
# [server]
# url = "https://est-backup.example.mil/.well-known/est"
```

### 5.2 Manual Enrollment Fallback

**When Auto-Enrollment Fails:**
1. Generate CSR manually using certreq
2. Submit to CA via alternate channel (email, portal)
3. Import issued certificate
4. Restore auto-enrollment when available

### 5.3 Certificate Validity Extension

**Emergency Procedures:**
- Request temporary certificate validity extension
- Coordinate with PKI team
- Document justification
- Implement before expiry

---

## 6. Communication Plan

### 6.1 Internal Communication

**Incident Notification Template:**
```
SUBJECT: [SEVERITY] EST Client Security Incident

Incident ID: INC-2026-0001
Severity: [CRITICAL/HIGH/MEDIUM/LOW]
Detected: [Timestamp]
Status: [Investigating/Contained/Resolved]

Description:
[Brief description of incident]

Impact:
[Systems affected, service disruption]

Actions Taken:
- [Action 1]
- [Action 2]

Next Steps:
- [Step 1]
- [Step 2]

Contact: ISSO [phone/email]
```

### 6.2 External Communication

**Notification Requirements:**
- US-CERT (within 1 hour for major incidents)
- DoD CERT (immediate for DoD systems)
- Affected partners (within 4 hours)

---

## 7. Testing and Exercises

### 7.1 Tabletop Exercises

**Frequency**: Quarterly

**Scenarios**:
- Private key exposure
- Certificate compromise
- EST server failure
- Insider threat

### 7.2 Full Recovery Drills

**Frequency**: Annually

**Scope**:
- Complete system rebuild
- Certificate re-enrollment
- Service restoration
- Stakeholder coordination

---

## 8. Appendices

### Appendix A: Contact Information

**Emergency Contacts:**
- ISSO: [Name] [Phone] [Email]
- System Owner: [Name] [Phone] [Email]
- Security Team: [Distribution List]
- US-CERT: 888-282-0870
- DoD CERT: cert@dc3.mil

### Appendix B: Evidence Collection

**Required Evidence:**
- System logs (Event Viewer, EST logs)
- Network captures (if available)
- Memory dumps (compromised systems)
- File system snapshots
- Configuration files
- Certificate details

### Appendix C: Legal Holds

**When to Implement:**
- Insider threat investigation
- Law enforcement involvement
- Litigation anticipated

**Preservation Scope:**
- All logs and audit trails
- System images
- Email communications
- Configuration history

---

**Document Classification:** UNCLASSIFIED
**Page Count:** 8
**End of Document**
