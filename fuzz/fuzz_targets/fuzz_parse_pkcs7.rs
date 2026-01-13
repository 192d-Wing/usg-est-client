#![no_main]

use libfuzzer_sys::fuzz_target;
use usg_est_client::types::Pkcs7CertificateChain;

fuzz_target!(|data: &[u8]| {
    // Fuzz the PKCS#7 parser
    // This should not panic or cause undefined behavior
    let _ = Pkcs7CertificateChain::from_der(data);
});
