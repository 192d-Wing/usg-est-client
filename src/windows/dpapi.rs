// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Windows Data Protection API (DPAPI) wrapper.
//!
//! Provides simple interface to Windows DPAPI for protecting sensitive data
//! like encryption keys, passwords, and tokens.

use crate::error::{EstError, Result};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

/// Protect data with DPAPI (user-scoped)
///
/// The data is encrypted with a key derived from the user's login credentials.
/// Only the same user on the same machine can unprotect the data.
pub fn protect(data: &[u8], description: &str) -> Result<Vec<u8>> {
    let description_wide: Vec<u16> = description
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut data_in = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let result = unsafe {
        CryptProtectData(
            &mut data_in as *mut _,
            windows::core::PCWSTR(description_wide.as_ptr()),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out as *mut _,
        )
    };

    if result.is_err() {
        return Err(EstError::platform("Failed to protect data with DPAPI"));
    }

    // Copy protected data
    let protected =
        unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec() };

    // Free DPAPI memory
    unsafe {
        windows::Win32::System::Memory::LocalFree(data_out.pbData as isize);
    }

    Ok(protected)
}

/// Unprotect DPAPI-protected data
///
/// Returns the original plaintext data.
pub fn unprotect(protected: &[u8]) -> Result<Vec<u8>> {
    let mut data_in = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let result = unsafe {
        CryptUnprotectData(
            &mut data_in as *mut _,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out as *mut _,
        )
    };

    if result.is_err() {
        return Err(EstError::platform("Failed to unprotect data with DPAPI"));
    }

    // Copy unprotected data
    let unprotected =
        unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec() };

    // Free DPAPI memory
    unsafe {
        windows::Win32::System::Memory::LocalFree(data_out.pbData as isize);
    }

    Ok(unprotected)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_protect_unprotect() {
        let plaintext = b"sensitive data that needs protection";
        let description = "Test Data";

        let protected = protect(plaintext, description).unwrap();
        assert_ne!(protected.as_slice(), plaintext);

        let unprotected = unprotect(&protected).unwrap();
        assert_eq!(unprotected.as_slice(), plaintext);
    }

    #[test]
    fn test_empty_data() {
        let plaintext = b"";
        let protected = protect(plaintext, "Empty").unwrap();
        let unprotected = unprotect(&protected).unwrap();
        assert_eq!(unprotected.as_slice(), plaintext);
    }

    #[test]
    fn test_large_data() {
        let plaintext = vec![0x42u8; 10000];
        let protected = protect(&plaintext, "Large Data").unwrap();
        let unprotected = unprotect(&protected).unwrap();
        assert_eq!(unprotected, plaintext);
    }
}
