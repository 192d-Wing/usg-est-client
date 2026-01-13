#![no_main]

use libfuzzer_sys::fuzz_target;
use usg_est_client::tls::parse_pem_private_key;

fuzz_target!(|data: &[u8]| {
    // Fuzz the PEM private key parser
    // This should not panic or cause undefined behavior
    let _ = parse_pem_private_key(data);
});
