#![no_main]

use libfuzzer_sys::fuzz_target;
use usg_est_client::types::parse_certs_only;

fuzz_target!(|data: &[u8]| {
    // Fuzz the PKCS#7 certs-only parser (EST simpleenroll/cacerts response body).
    // This should not panic or cause undefined behavior on arbitrary input.
    let _ = parse_certs_only(data);
});
