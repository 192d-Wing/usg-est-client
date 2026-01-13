#![no_main]

use libfuzzer_sys::fuzz_target;
use usg_est_client::operations::enroll::validate_csr;

fuzz_target!(|data: &[u8]| {
    // Fuzz the CSR validator
    // This should not panic or cause undefined behavior
    let _ = validate_csr(data);
});
