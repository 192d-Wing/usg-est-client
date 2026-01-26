# Software Bill of Materials (SBOM)

**Generated:** 2026-01-18
**Version:** 1.0.3
**Classification:** UNCLASSIFIED

---

## Overview

This directory contains Software Bills of Materials (SBOMs) for the EST Client Library, providing complete supply chain transparency in compliance with Executive Order 14028 (Improving the Nation's Cybersecurity).

---

## SBOM Formats

### 1. SPDX 2.3 (Recommended for DoD)

**File:** `usg-est-client-spdx-2.3.json`
**Format:** SPDX JSON 2.3
**Size:** 363KB
**Packages:** 346 components
**Standard:** ISO/IEC 5962:2021

**Use Cases:**
- DoD software factories
- NIST compliance validation
- License compliance auditing
- Vulnerability correlation

### 2. CycloneDX 1.5

**File:** `usg-est-client-cyclonedx-1.5.json`
**Format:** CycloneDX JSON 1.5
**Size:** 289KB
**Components:** 345 components
**Standard:** OWASP standard

**Use Cases:**
- Continuous monitoring
- Dependency-Track integration
- Vulnerability intelligence
- Security operations

---

## Generation

### Command

```bash
# SPDX 2.3
cargo sbom --output-format spdx_json_2_3 > sbom/usg-est-client-spdx-2.3.json

# CycloneDX 1.5
cargo sbom --output-format cyclone_dx_json_1_5 > sbom/usg-est-client-cyclonedx-1.5.json
```

### Tool

- **Tool:** cargo-sbom v0.10.0
- **Source:** https://crates.io/crates/cargo-sbom
- **Installation:** `cargo install cargo-sbom`

---

## SBOM Contents

### Package Information

Each SBOM includes:
- Package name and version
- Package URL (PURL) identifier
- License information (SPDX identifiers)
- Checksum (SHA-256)
- Supplier information
- Dependency relationships

### Dependency Tree

The SBOMs capture:
- **Direct dependencies:** 150+ crates
- **Transitive dependencies:** 346 total components
- **Dependency relationships:** Complete graph

### Example Dependencies

**Cryptographic Libraries:**
- `openssl` 0.10 (FIPS 140-2 module)
- `rustls` 0.23 (TLS implementation)
- `ring` 0.17 (Cryptographic operations)
- `rsa` 0.9 (RSA operations)

**DoD PKI:**
- `x509-cert` 0.2 (Certificate parsing)
- `der` (DER encoding)
- `const-oid` (OID handling)

**Windows Integration:**
- `windows` 0.58 (Windows APIs)
- `windows-sys` 0.59 (System bindings)

---

## Compliance

### Executive Order 14028

**Section 4(e)(ix):** "providing a purchaser a Software Bill of Materials (SBOM) for each product directly or by publishing it on a public website"

✅ **COMPLIANT:** Both SPDX and CycloneDX SBOMs provided

### NIST SP 800-161 Rev 1

**Supply Chain Risk Management:**
- Complete component inventory
- License compliance verification
- Vulnerability tracking capability

✅ **COMPLIANT:** SBOMs enable continuous supply chain monitoring

### NTIA Minimum Elements

Required SBOM elements per NTIA:

- ✅ **Supplier Name:** Documented for each component
- ✅ **Component Name:** Complete package names
- ✅ **Version:** Precise version strings
- ✅ **Dependencies:** Full dependency graph
- ✅ **Timestamp:** Generation timestamp included
- ✅ **Unique Identifier:** PURL for each component
- ✅ **Data Format:** SPDX 2.3 and CycloneDX 1.5

---

## Usage

### Viewing SBOMs

**JSON Viewers:**
```bash
# Pretty print SPDX
jq '.' sbom/usg-est-client-spdx-2.3.json | less

# Pretty print CycloneDX
jq '.' sbom/usg-est-client-cyclonedx-1.5.json | less
```

**Extract Package List:**
```bash
# SPDX: List all packages
jq -r '.packages[].name' sbom/usg-est-client-spdx-2.3.json | sort

# CycloneDX: List all components
jq -r '.components[].name' sbom/usg-est-client-cyclonedx-1.5.json | sort
```

### Vulnerability Analysis

**Using SPDX with Grype:**
```bash
grype sbom:sbom/usg-est-client-spdx-2.3.json
```

**Using CycloneDX with Dependency-Track:**
1. Upload `usg-est-client-cyclonedx-1.5.json` to Dependency-Track
2. Continuous vulnerability monitoring
3. License policy enforcement
4. Component risk scoring

### License Compliance

**Extract all licenses:**
```bash
# SPDX
jq -r '.packages[].licenseConcluded // "NOASSERTION"' \
  sbom/usg-est-client-spdx-2.3.json | sort -u

# CycloneDX
jq -r '.components[].licenses[]?.license.id // .components[].licenses[]?.expression // "NONE"' \
  sbom/usg-est-client-cyclonedx-1.5.json | sort -u
```

---

## Known Vulnerabilities

### From cargo audit (2026-01-18)

**RUSTSEC-2023-0071: RSA Marvin Attack**
- Component: `rsa` 0.9.10
- Severity: Medium (5.9)
- Status: No fixed upgrade available
- Mitigation: Tracked in POA&M

**RUSTSEC-2024-0436: paste unmaintained**
- Component: `paste` 1.0.15 (transitive)
- Severity: Warning (unmaintained)
- Status: Alternative being evaluated
- Mitigation: Macro-only dependency, minimal risk

See `docs/ato/vulnerability-management.md` for complete vulnerability tracking.

---

## Maintenance

### When to Regenerate

Generate new SBOMs when:
1. **Dependency changes:** After `cargo update`
2. **Version releases:** For each release tag
3. **Security updates:** After applying security patches
4. **Quarterly reviews:** As part of continuous monitoring
5. **Annual audits:** For ATO renewal

### Automated Generation

**CI/CD Integration:**
```yaml
# .gitlab-ci.yml or .github/workflows/
sbom-generation:
  script:
    - cargo install cargo-sbom
    - mkdir -p sbom
    - cargo sbom --output-format spdx_json_2_3 > sbom/usg-est-client-spdx-2.3.json
    - cargo sbom --output-format cyclone_dx_json_1_5 > sbom/usg-est-client-cyclonedx-1.5.json
  artifacts:
    paths:
      - sbom/
```

---

## Verification

### Checksum Verification

```bash
# Generate checksums
sha256sum sbom/*.json > sbom/checksums.txt

# Verify checksums
sha256sum -c sbom/checksums.txt
```

### SBOM Validation

**SPDX Validation:**
```bash
# Using spdx-tools (if available)
java -jar tools-java-1.1.0-jar-with-dependencies.jar Verify sbom/usg-est-client-spdx-2.3.json
```

**CycloneDX Validation:**
```bash
# Using cyclonedx-cli (if available)
cyclonedx-cli validate --input-file sbom/usg-est-client-cyclonedx-1.5.json
```

---

## Integration with ATO Package

### Document References

- **System Security Plan:** References SBOM for component inventory
- **Vulnerability Management Plan:** Uses SBOM for tracking
- **Control Traceability Matrix:** Maps SA-15(9) to SBOM
- **Risk Assessment:** SBOM supports supply chain risk analysis

### NIST SP 800-53 Rev 5 Controls

**SA-15(9): Developer Security and Privacy Architecture and Design | Use of Live or Operational Data**
- SBOM provides component transparency

**SR-3: Supply Chain Controls and Processes**
- SBOM enables supply chain visibility

**SR-4: Provenance**
- SBOM documents component provenance

**SR-6: Supplier Assessments and Reviews**
- SBOM facilitates supplier risk assessment

---

## Distribution

### Public Availability

Per EO 14028, SBOMs should be:
- ✅ Included with releases
- ✅ Published on public repository
- ✅ Provided to customers
- ✅ Available for download

### Access Control

**Classification:** UNCLASSIFIED
**Distribution:** UNLIMITED
**Export Control:** No restrictions (supply chain transparency)

---

## Statistics

### SBOM Metrics

| Metric | SPDX | CycloneDX |
|--------|------|-----------|
| **File Size** | 363KB | 289KB |
| **Components** | 346 | 345 |
| **Format Version** | SPDX 2.3 | CycloneDX 1.5 |
| **License Info** | Yes | Yes |
| **Checksums** | SHA-256 | SHA-256 |
| **Relationships** | Yes | Yes |

### Dependency Statistics

- **Direct Dependencies:** 150+
- **Total Components:** 346
- **Unique Licenses:** 15+
- **Vulnerability Scan Coverage:** 100%

---

## References

### Standards

- **SPDX:** https://spdx.dev/
- **CycloneDX:** https://cyclonedx.org/
- **NTIA SBOM:** https://www.ntia.gov/sbom

### Guidance

- **EO 14028:** https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
- **NIST SP 800-161 Rev 1:** https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final
- **DoD SBOM Guidance:** https://dodcio.defense.gov/

### Tools

- **cargo-sbom:** https://crates.io/crates/cargo-sbom
- **Dependency-Track:** https://dependencytrack.org/
- **Grype:** https://github.com/anchore/grype

---

**Document Classification:** UNCLASSIFIED
**Next Review:** Quarterly or with each release
**Maintained By:** Security Team

**End of SBOM Documentation**
