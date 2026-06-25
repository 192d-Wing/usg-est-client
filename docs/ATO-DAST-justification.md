# DAST Applicability Justification — `usg-est-client`

**Classification:** UNCLASSIFIED
**Component:** `usg-est-client` (RFC 7030 EST enrollment client library + `est-enroll` CLI)
**Owner:** 192d Wing
**Applies to controls:** SA-11 (Developer Testing and Evaluation), SA-11(8) (Dynamic
Code Analysis), RA-5 (Vulnerability Monitoring and Scanning), CA-8 (Penetration Testing)

---

## 1. Summary

Dynamic Application Security Testing (DAST) in its conventional form — an automated
scanner (e.g., OWASP ZAP, Burp, Nikto) probing a **running network-exposed
application** over HTTP(S) — **does not apply** to this component. `usg-est-client`
is a **client library** and a command-line tool. It **initiates** outbound TLS
connections to an EST server; it does **not** listen on a socket, bind a port, or
expose any network-reachable attack surface of its own.

This is not a gap to be remediated; it is a property of the software's architecture.
The dynamic-analysis obligation under SA-11(8) is instead satisfied by **coverage-guided
fuzzing** of the component's untrusted-input boundaries, which is the appropriate
dynamic technique for a library that parses attacker-influenced data.

## 2. Why traditional DAST is Not Applicable

| DAST precondition | Status for `usg-est-client` |
|---|---|
| A running, network-listening service | **Absent** — no `TcpListener`/`bind`/server; verified by source inspection (`grep -rE 'TcpListener\|bind\(\|axum\|hyper::Server' src/` returns nothing). |
| HTTP request/response surface to scan | **Absent** — the crate is the HTTP **client**, not the server. |
| Authenticated session / forms / endpoints | **Absent** — no endpoints are served. |

Pointing a DAST scanner at this component would have nothing to crawl. The
network-facing attack surface that DAST is designed to assess belongs to the **EST
server** that this client enrolls against — a separate system with its own ATO
boundary and its own DAST obligation.

## 3. The real dynamic attack surface, and how it is tested

The component's genuine dynamic risk is in **parsing untrusted bytes** returned by
(or supplied to) the EST exchange: PEM, PKCS#7/CMS, CSR, and private-key material.
These are exercised dynamically by the libFuzzer harnesses in [`fuzz/`](../fuzz):

| Fuzz target | Boundary exercised |
|---|---|
| `fuzz_parse_pem_certificates` | PEM certificate parsing |
| `fuzz_parse_pem_private_key` | PEM private-key parsing |
| `fuzz_parse_pkcs7` | PKCS#7 / CMS structure parsing (EST `simpleenroll` response) |
| `fuzz_validate_csr` | CSR construction/validation |

These run automatically in CI (`.github/workflows/security.yml`, job **`fuzz`**) as a
bounded regression sweep on every push/PR, and can be run for extended campaigns
locally with `cargo +nightly fuzz run <target>`. A crash fails the job and the
reproducer is uploaded as a build artifact. This is the SA-11(8) dynamic-analysis
control of record for this component.

## 4. Complementary dynamic / integration coverage

- **Integration tests** (`tests/`) drive real EST flows against fixtures, including
  the FIPS (`aws-lc-rs`) crypto provider, exercising the TLS and PKI code paths at
  runtime.
- **`cargo audit` / `cargo deny` / Grype** provide continuous runtime-dependency
  vulnerability monitoring (RA-5).

## 5. If a network-level DAST/pentest is still required (CA-8)

Should the assessor require active scanning of the *enrollment transaction*, the
correct scope is an **integration environment** containing a live EST **server**,
with the scanner positioned against that server (and, if desired, a TLS-intercepting
proxy observing the client's outbound requests). That activity belongs to the
server's ATO package, not this client's. This component would participate only as a
traffic generator.

## 6. Conclusion

Traditional DAST is **Not Applicable** to `usg-est-client` because it exposes no
network service. The SA-11(8) dynamic-analysis requirement is met by coverage-guided
fuzzing of the untrusted-input parsers, enforced in CI. This memo documents that
determination for the system security plan (SSP).

---

*Maintained alongside the CI security tooling; update if the component ever gains a
network-listening mode.*
