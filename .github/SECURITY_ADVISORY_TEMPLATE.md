# Security Advisory Template

Use this template when creating security advisories for the EST Client Library.

---

## Title Format

`[SEVERITY] Brief Vulnerability Description (USG-EST-YYYY-NNNN)`

**Example:** `[HIGH] Certificate Validation Bypass (USG-EST-2026-0001)`

---

## Advisory Content

### Summary

[One-paragraph summary of the vulnerability and its impact. Should be understandable by non-technical stakeholders.]

**Example:**
> A vulnerability in certificate validation allows an attacker to bypass certificate chain verification under certain conditions, potentially allowing unauthorized certificate acceptance. This affects EST client versions 1.0.0 through 1.0.2 when using custom trust anchors.

---

### Severity

**Severity Level:** [CRITICAL / HIGH / MEDIUM / LOW]

**CVSS Score:** X.X (CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X)

**CVE ID:** CVE-YYYY-NNNNN (if assigned)

**Tracking ID:** USG-EST-YYYY-NNNN

---

### Affected Versions

**EST Client Library:**
- Version X.X.X through X.X.X

**Windows Service:**
- Version X.X.X through X.X.X (if applicable)

**Affected Features:**
- [Feature 1]
- [Feature 2]

---

### Fixed Versions

**EST Client Library:**
- Version X.X.X and later

**Patched Releases:**
- [Link to release on GitHub]

---

### Description

[Detailed technical description of the vulnerability]

**Technical Details:**
- What component is affected
- What conditions trigger the vulnerability
- How the vulnerability manifests
- Root cause of the issue

**Example:**
> The `validate_certificate_chain()` function in `src/validation.rs` does not properly verify intermediate certificate signatures when the trust anchor list contains multiple CAs with the same subject DN. This allows an attacker to craft a certificate chain that appears valid but uses an untrusted intermediate certificate.

---

### Impact

[Describe what an attacker could achieve by exploiting this vulnerability]

**Potential Attack Scenarios:**
1. [Scenario 1]
2. [Scenario 2]

**Impact Assessment:**
- **Confidentiality:** [NONE / LOW / MEDIUM / HIGH]
- **Integrity:** [NONE / LOW / MEDIUM / HIGH]
- **Availability:** [NONE / LOW / MEDIUM / HIGH]

**Example:**
> An attacker with network position (man-in-the-middle) could present a rogue certificate that would be accepted by the EST client. This could allow:
> 1. Impersonation of EST server
> 2. Issuance of unauthorized certificates
> 3. Interception of enrollment requests
>
> Confidentiality: HIGH - Sensitive enrollment data could be captured
> Integrity: HIGH - Unauthorized certificates could be issued
> Availability: LOW - Service continues to operate

---

### Affected Components

- [Component / Module Name] - [File path or crate name]
- [Component / Module Name] - [File path or crate name]

**Example:**
- Certificate Validation - `src/validation.rs`
- TLS Configuration - `src/tls.rs`

---

### Reproduction

[Steps to reproduce the vulnerability - only include if appropriate for public disclosure]

**Prerequisites:**
- [Prerequisite 1]
- [Prerequisite 2]

**Steps:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Result:**
[What should happen in secure version]

**Actual Result:**
[What happens in vulnerable version]

**Note:** Detailed reproduction steps may be withheld for CRITICAL/HIGH vulnerabilities until sufficient time has passed for patch deployment.

---

### Mitigation

[Workarounds or temporary mitigations if patch cannot be immediately applied]

**If Immediate Upgrade Not Possible:**
1. [Mitigation step 1]
2. [Mitigation step 2]

**Configuration Changes:**
```toml
# Example mitigation configuration
[security]
option = "secure_value"
```

**Limitations:**
- [Limitation of mitigation 1]
- [Limitation of mitigation 2]

**Example:**
> If immediate upgrade is not possible:
> 1. Use explicit trust anchors with single CA only
> 2. Enable additional certificate validation logging
> 3. Implement network-level controls to verify EST server identity
>
> Note: These mitigations reduce but do not eliminate risk. Upgrade is strongly recommended.

---

### Remediation

[How to fix the vulnerability - upgrade instructions]

**Recommended Action:** Upgrade to patched version immediately.

**For Rust Library Users:**
```toml
# Update Cargo.toml
[dependencies]
usg-est-client = "X.X.X"  # Patched version
```

Then run:
```bash
cargo update
cargo build --release
```

**For Windows Service Users:**
1. Download patched version from [GitHub Releases](URL)
2. Stop EST service: `Stop-Service "EST Auto-Enrollment"`
3. Replace executable: `C:\Program Files\EST Client\`
4. Start EST service: `Start-Service "EST Auto-Enrollment"`
5. Verify version: `Get-Service "EST Auto-Enrollment" | Select-Object -ExpandProperty DisplayName`

**For DoD Deployments:**
- Coordinate with ISSO before deployment
- Follow change management procedures
- Verify STIG compliance after update
- Update security documentation

**Verification:**
```bash
# Verify patched version
cargo tree | grep usg-est-client
# Should show version X.X.X or later
```

---

### Timeline

| Date | Event |
|------|-------|
| YYYY-MM-DD | Vulnerability reported [by researcher name if public] |
| YYYY-MM-DD | Vulnerability confirmed |
| YYYY-MM-DD | Fix developed and tested |
| YYYY-MM-DD | Security advisory published (private) |
| YYYY-MM-DD | Patch released |
| YYYY-MM-DD | Security advisory published (public) |
| YYYY-MM-DD | CVE assigned (if applicable) |

---

### Credits

**Discovered By:**
- [Researcher Name] (with permission to credit)
- [Organization] (if applicable)
- [Link to researcher profile/website]

**Coordinated Disclosure:**
- Thank you to [Researcher Name] for responsible disclosure
- This vulnerability was reported through our [GitHub Security Advisories](https://github.com/johnwillman/usg-est-client/security/advisories)

**Security Team:**
- [Team member names involved in response]

---

### References

**Related Resources:**
- [Security Update SLA](../docs/ato/security-update-sla.md)
- [Vulnerability Management Guide](../docs/ato/vulnerability-management.md)

**External References:**
- [CVE-YYYY-NNNNN](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-YYYY-NNNNN)
- [GitHub Security Advisory](https://github.com/johnwillman/usg-est-client/security/advisories/GHSA-xxxx-xxxx-xxxx)
- [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN)

**Patch Details:**
- [Pull Request fixing the issue](https://github.com/johnwillman/usg-est-client/pull/XXX)
- [Commit hash](https://github.com/johnwillmanv/usg-est-client/commit/XXXXXXX)
- [Release Notes](https://github.com/johnwillman/usg-est-client/releases/tag/vX.X.X)

**Related Advisories:**
- [USG-EST-YYYY-NNNN](link) - If there are related advisories

---

### FAQ

**Q: Am I affected by this vulnerability?**
A: You are affected if you are running EST Client version X.X.X through X.X.X. Check your version with `cargo tree | grep usg-est-client`.

**Q: What should I do if I'm affected?**
A: Upgrade to version X.X.X or later immediately. Follow the remediation steps above.

**Q: Is there a workaround if I can't upgrade right away?**
A: See the Mitigation section above for temporary workarounds. However, upgrading is strongly recommended.

**Q: Has this been exploited in the wild?**
A: [We are not aware of any exploitation / We have evidence of exploitation - provide details]

**Q: Do I need to rotate certificates after patching?**
A: [Yes/No and explanation]

**Q: Will this affect my ATO?**
A: For DoD deployments, coordinate with your ISSO. [HIGH/CRITICAL] vulnerabilities may require POA&M updates and risk reassessment.

---

### Contact

**For Questions About This Advisory:**
- GitHub Discussions: https://github.com/johnwillman/usg-est-client/discussions
- Email: security@[organization].mil

**For Reporting New Vulnerabilities:**
- Use [GitHub Security Advisories](https://github.com/johnwillman/usg-est-client/security/advisories)
- See [SECURITY.md](../SECURITY.md) for full reporting process

---

**Document Classification:** UNCLASSIFIED (unless vulnerability details are sensitive)
**Advisory ID:** USG-EST-YYYY-NNNN
**Publication Date:** YYYY-MM-DD
**Last Updated:** YYYY-MM-DD

**END OF SECURITY ADVISORY**
