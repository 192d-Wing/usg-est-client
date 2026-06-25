// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! FIPS-aware hashing helpers.
//!
//! These centralize the choice of cryptographic module for hashing. Under the
//! `fips` feature they run in the aws-lc-rs FIPS module; otherwise they use the
//! RustCrypto `sha2` implementation. Routing fingerprint/digest call sites
//! through here keeps a FIPS build from computing hashes outside the validated
//! module, without sprinkling `#[cfg(feature = "fips")]` across every caller.

/// Compute the SHA-256 digest of `data`.
///
/// Uses the aws-lc-rs FIPS module under the `fips` feature, otherwise `sha2`.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    #[cfg(feature = "fips")]
    {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
    #[cfg(not(feature = "fips"))]
    {
        use sha2::{Digest, Sha256};
        Sha256::digest(data).into()
    }
}

/// Compute the SHA-384 digest of `data`.
///
/// Uses the aws-lc-rs FIPS module under the `fips` feature, otherwise `sha2`.
/// Centralizing SHA-384 here (alongside [`sha256`]) keeps a FIPS build from
/// computing hashes outside the validated module — callers must route through
/// this layer rather than reaching for `sha2` or `aws_lc_rs` directly.
#[cfg(feature = "tamp")]
pub(crate) fn sha384(data: &[u8]) -> [u8; 48] {
    #[cfg(feature = "fips")]
    {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, data);
        let mut out = [0u8; 48];
        out.copy_from_slice(digest.as_ref());
        out
    }
    #[cfg(not(feature = "fips"))]
    {
        use sha2::{Digest, Sha384};
        Sha384::digest(data).into()
    }
}

/// Compute the SHA-512 digest of `data`.
///
/// Uses the aws-lc-rs FIPS module under the `fips` feature, otherwise `sha2`.
/// See [`sha384`] for why digest selection is centralized here.
#[cfg(feature = "tamp")]
pub(crate) fn sha512(data: &[u8]) -> [u8; 64] {
    #[cfg(feature = "fips")]
    {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, data);
        let mut out = [0u8; 64];
        out.copy_from_slice(digest.as_ref());
        out
    }
    #[cfg(not(feature = "fips"))]
    {
        use sha2::{Digest, Sha512};
        Sha512::digest(data).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let got = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let got = sha256(b"");
        assert_eq!(
            got[..4],
            [0xe3, 0xb0, 0xc4, 0x42],
            "unexpected SHA-256 of empty input"
        );
    }
}
