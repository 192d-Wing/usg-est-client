// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

fn main() {
    // These guards depend only on the target OS and the two FIPS feature flags;
    // re-run the script when those change. (Cargo tracks CARGO_FEATURE_* inputs
    // automatically, but make the target-os dependency explicit so the guards
    // keep firing if a non-default rerun directive is ever added.)
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo:rerun-if-changed=build.rs");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let has_fips = std::env::var("CARGO_FEATURE_FIPS").is_ok();
    let has_fips_cng = std::env::var("CARGO_FEATURE_FIPS_CNG").is_ok();

    if has_fips && has_fips_cng {
        panic!(
            "\n\
            The `fips` and `fips-cng` features are mutually exclusive: `fips` links the\n\
            aws-lc-rs FIPS module (Linux), while `fips-cng` routes crypto through Windows\n\
            CNG/SChannel. Enable exactly one for the target platform.\n"
        );
    }

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
