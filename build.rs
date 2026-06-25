// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let has_fips = std::env::var("CARGO_FEATURE_FIPS").is_ok();
    let has_fips_cng = std::env::var("CARGO_FEATURE_FIPS_CNG").is_ok();

    if has_fips && target_os == "windows" {
        panic!(
            "\n\
            The `fips` feature uses aws-lc-fips-sys, which does not build on Windows.\n\
            On Windows, use `--features fips-cng` instead. It routes TLS through\n\
            native-tls/SChannel and key operations through CNG, both of which honour\n\
            the OS FIPS algorithm policy.\n"
        );
    }

    if has_fips_cng && target_os != "windows" {
        panic!(
            "\n\
            The `fips-cng` feature requires a Windows target (it routes crypto through\n\
            Windows CNG and native-tls/SChannel). On Linux/macOS, use `--features fips`\n\
            instead, which uses the aws-lc-rs FIPS module.\n"
        );
    }
}
