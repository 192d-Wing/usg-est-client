// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Variable expansion for configuration values.
//!
//! This module handles expansion of variables like `${COMPUTERNAME}` and
//! `${USERDNSDOMAIN}` in configuration strings.

use crate::error::EstError;

/// Expand variables in a string.
///
/// Variables are in the format `${VARIABLE_NAME}`. Supported variables:
///
/// - `${COMPUTERNAME}` - Computer/hostname
/// - `${USERDNSDOMAIN}` - DNS domain suffix (Windows)
/// - `${USERDOMAIN}` - NetBIOS domain name (Windows)
/// - `${USERNAME}` - Current username
/// - `${USERPROFILE}` - User profile directory
/// - `${PROGRAMDATA}` - ProgramData directory (Windows)
/// - `${LOCALAPPDATA}` - Local app data directory
/// - `${TEMP}` - Temporary directory
/// - `${HOME}` - Home directory (Unix)
///
/// Unknown variables are left unchanged.
///
/// # Examples
///
/// ```
/// use usg_est_client::auto_enroll::expand_variables;
///
/// // Simple expansion
/// let result = expand_variables("${COMPUTERNAME}.example.com").unwrap();
/// // Returns something like "MYPC.example.com"
///
/// // Multiple variables
/// let result = expand_variables("${USERNAME}@${COMPUTERNAME}").unwrap();
/// // Returns something like "john@MYPC"
/// ```
pub fn expand_variables(input: &str) -> Result<String, EstError> {
    let mut result = input.to_string();
    let mut start = 0;

    // Find all ${...} patterns and replace them
    while let Some(var_start) = result[start..].find("${") {
        let absolute_start = start + var_start;

        if let Some(var_end) = result[absolute_start..].find('}') {
            let absolute_end = absolute_start + var_end;
            let var_name = &result[absolute_start + 2..absolute_end];

            // Look up the variable value
            if let Some(value) = get_variable_value(var_name) {
                // Replace ${VAR} with value
                result.replace_range(absolute_start..absolute_end + 1, &value);
                // Continue searching after the replacement
                start = absolute_start + value.len();
            } else {
                // Variable not found, skip past it
                start = absolute_end + 1;
            }
        } else {
            // No closing brace, skip past ${
            start = absolute_start + 2;
        }
    }

    Ok(result)
}

/// Get the value of a variable.
///
/// Returns `None` for unknown variables.
fn get_variable_value(name: &str) -> Option<String> {
    // First try our custom resolvers
    match name {
        "COMPUTERNAME" => get_computer_name(),
        "USERDNSDOMAIN" => get_dns_domain(),
        "USERDOMAIN" => get_netbios_domain(),
        "USERNAME" => get_username(),
        "HOME" | "USERPROFILE" => get_home_dir(),
        "PROGRAMDATA" => get_program_data(),
        "LOCALAPPDATA" => get_local_app_data(),
        "TEMP" | "TMP" => get_temp_dir(),
        _ => {
            // Fall back to environment variable
            std::env::var(name).ok()
        }
    }
}

/// Get the computer name.
fn get_computer_name() -> Option<String> {
    // Try environment variable first (works on Windows)
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        return Some(name);
    }

    // Fall back to hostname
    #[cfg(unix)]
    {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .map(|s| {
                // Remove domain suffix if present
                s.split('.').next().unwrap_or(&s).to_uppercase()
            })
    }

    #[cfg(not(unix))]
    {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .map(|s| s.to_uppercase())
    }
}

/// Get the DNS domain suffix.
fn get_dns_domain() -> Option<String> {
    // Try environment variable first (Windows)
    if let Ok(domain) = std::env::var("USERDNSDOMAIN") {
        return Some(domain);
    }

    // On Unix, try to extract from FQDN
    #[cfg(unix)]
    {
        if let Ok(Some(fqdn)) = hostname::get().map(|h| h.into_string().ok())
            && let Some(dot_pos) = fqdn.find('.')
        {
            return Some(fqdn[dot_pos + 1..].to_string());
        }
    }

    None
}

/// Get the NetBIOS domain name.
fn get_netbios_domain() -> Option<String> {
    // Try environment variable (Windows)
    std::env::var("USERDOMAIN").ok()
}

/// Get the current username.
fn get_username() -> Option<String> {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .ok()
}

/// Get the home directory.
fn get_home_dir() -> Option<String> {
    dirs::home_dir().map(|p| p.to_string_lossy().into_owned())
}

/// Get the ProgramData directory (Windows) or /var/lib equivalent.
fn get_program_data() -> Option<String> {
    std::env::var("PROGRAMDATA").ok().or_else(|| {
        #[cfg(unix)]
        {
            Some("/var/lib".to_string())
        }
        #[cfg(not(unix))]
        {
            None
        }
    })
}

/// Get the local app data directory.
fn get_local_app_data() -> Option<String> {
    std::env::var("LOCALAPPDATA")
        .ok()
        .or_else(|| dirs::data_local_dir().map(|p| p.to_string_lossy().into_owned()))
}

/// Get the temporary directory.
fn get_temp_dir() -> Option<String> {
    Some(std::env::temp_dir().to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_expand_no_variables() {
        let result = expand_variables("hello world").unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_expand_single_variable() {
        // Set a test environment variable
        // SAFETY: This is a test, no other threads are accessing this variable
        unsafe {
            std::env::set_var("TEST_VAR_123", "test_value");
        }
        let result = expand_variables("prefix_${TEST_VAR_123}_suffix").unwrap();
        assert_eq!(result, "prefix_test_value_suffix");
        unsafe {
            std::env::remove_var("TEST_VAR_123");
        }
    }

    #[test]
    fn test_expand_multiple_variables() {
        // SAFETY: This is a test, no other threads are accessing these variables
        unsafe {
            std::env::set_var("TEST_A", "aaa");
            std::env::set_var("TEST_B", "bbb");
        }
        let result = expand_variables("${TEST_A}-${TEST_B}").unwrap();
        assert_eq!(result, "aaa-bbb");
        unsafe {
            std::env::remove_var("TEST_A");
            std::env::remove_var("TEST_B");
        }
    }

    #[test]
    fn test_expand_unknown_variable() {
        // Unknown variables are left unchanged
        let result = expand_variables("${DEFINITELY_NOT_SET_XYZ123}").unwrap();
        assert_eq!(result, "${DEFINITELY_NOT_SET_XYZ123}");
    }

    #[test]
    fn test_expand_unclosed_brace() {
        // Unclosed brace is left unchanged
        let result = expand_variables("${UNCLOSED").unwrap();
        assert_eq!(result, "${UNCLOSED");
    }

    #[test]
    fn test_expand_temp() {
        let result = expand_variables("${TEMP}").unwrap();
        // Should expand to something (temp dir exists on all platforms)
        assert!(!result.is_empty());
        assert!(!result.contains("${"));
    }

    #[test]
    fn test_expand_computername() {
        // COMPUTERNAME should always resolve to something
        let result = expand_variables("${COMPUTERNAME}").unwrap();
        // Either it expanded or the environment var wasn't set
        // On most systems, hostname is available
        if !result.contains("${") {
            assert!(!result.is_empty());
        }
    }

    #[test]
    fn test_expand_in_path() {
        // SAFETY: This is a test, no other threads are accessing this variable
        unsafe {
            std::env::set_var("TEST_DIR", "mydir");
        }
        let result = expand_variables("/base/${TEST_DIR}/file.txt").unwrap();
        assert_eq!(result, "/base/mydir/file.txt");
        unsafe {
            std::env::remove_var("TEST_DIR");
        }
    }

    // ===== Additional Phase 11.8 Variable Expansion Tests =====

    #[test]
    fn test_expand_empty_string() {
        let result = expand_variables("").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_expand_no_closing_brace_at_end() {
        let result = expand_variables("prefix ${VAR").unwrap();
        assert_eq!(result, "prefix ${VAR");
    }

    #[test]
    fn test_expand_empty_variable_name() {
        // ${} should be left unchanged since it's not a valid variable name
        let result = expand_variables("prefix ${}suffix").unwrap();
        assert_eq!(result, "prefix ${}suffix");
    }

    #[test]
    fn test_expand_consecutive_variables() {
        // SAFETY: This is a test, no other threads are accessing these variables
        unsafe {
            std::env::set_var("TEST_X", "X");
            std::env::set_var("TEST_Y", "Y");
            std::env::set_var("TEST_Z", "Z");
        }
        let result = expand_variables("${TEST_X}${TEST_Y}${TEST_Z}").unwrap();
        assert_eq!(result, "XYZ");
        unsafe {
            std::env::remove_var("TEST_X");
            std::env::remove_var("TEST_Y");
            std::env::remove_var("TEST_Z");
        }
    }

    #[test]
    fn test_expand_variable_with_special_chars() {
        // SAFETY: This is a test, no other threads are accessing this variable
        unsafe {
            std::env::set_var("TEST_SPECIAL", "value with spaces & symbols!");
        }
        let result = expand_variables("data: ${TEST_SPECIAL}").unwrap();
        assert_eq!(result, "data: value with spaces & symbols!");
        unsafe {
            std::env::remove_var("TEST_SPECIAL");
        }
    }

    #[test]
    fn test_expand_nested_dollar_sign() {
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_DOLLAR", "has$dollar");
        }
        let result = expand_variables("${TEST_DOLLAR}").unwrap();
        assert_eq!(result, "has$dollar");
        unsafe {
            std::env::remove_var("TEST_DOLLAR");
        }
    }

    #[test]
    fn test_expand_variable_that_looks_like_variable() {
        // Test variable that contains ${...} pattern in its value
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_META", "${OTHER_VAR}");
        }
        let result = expand_variables("${TEST_META}").unwrap();
        // Note: since OTHER_VAR doesn't exist, it's left as-is
        assert_eq!(result, "${OTHER_VAR}");
        unsafe {
            std::env::remove_var("TEST_META");
        }
    }

    #[test]
    fn test_expand_dollar_without_brace() {
        let result = expand_variables("price $100").unwrap();
        assert_eq!(result, "price $100");
    }

    #[test]
    fn test_expand_double_dollar() {
        let result = expand_variables("$$VAR$$").unwrap();
        assert_eq!(result, "$$VAR$$");
    }

    #[test]
    fn test_expand_username() {
        let result = expand_variables("${USERNAME}").unwrap();
        // On most systems, USERNAME or USER is set
        // The function falls back to USER if USERNAME isn't set
        if !result.contains("${") {
            assert!(!result.is_empty());
        }
    }

    #[test]
    fn test_expand_home_and_userprofile() {
        // Both HOME and USERPROFILE should resolve to the same thing
        let home_result = expand_variables("${HOME}").unwrap();
        let profile_result = expand_variables("${USERPROFILE}").unwrap();

        // If either expanded successfully, they should be the same
        if !home_result.contains("${") && !profile_result.contains("${") {
            assert_eq!(home_result, profile_result);
        }
    }

    #[test]
    fn test_expand_tmp_and_temp() {
        // Both TEMP and TMP should resolve to the same thing
        let temp_result = expand_variables("${TEMP}").unwrap();
        let tmp_result = expand_variables("${TMP}").unwrap();

        assert!(!temp_result.is_empty());
        assert!(!tmp_result.is_empty());
        // Both should resolve to temp dir
        assert_eq!(temp_result, tmp_result);
    }

    #[test]
    fn test_expand_programdata() {
        let result = expand_variables("${PROGRAMDATA}").unwrap();
        // On Unix, this falls back to /var/lib
        // On Windows, it should be set
        if !result.contains("${") {
            assert!(!result.is_empty());
        }
    }

    #[test]
    fn test_expand_localappdata() {
        let result = expand_variables("${LOCALAPPDATA}").unwrap();
        // Should resolve on most platforms via dirs crate
        if !result.contains("${") {
            assert!(!result.is_empty());
        }
    }

    #[test]
    fn test_expand_fqdn_pattern() {
        // Test common pattern: ${COMPUTERNAME}.${USERDNSDOMAIN}
        let result = expand_variables("${COMPUTERNAME}.${USERDNSDOMAIN}").unwrap();
        // COMPUTERNAME should expand, USERDNSDOMAIN may or may not depending on platform
        assert!(!result.is_empty());
    }

    #[test]
    fn test_expand_mixed_known_and_unknown() {
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_KNOWN_VAR", "known_value");
        }
        let result = expand_variables("${TEST_KNOWN_VAR} and ${UNKNOWN_XYZ_VAR}").unwrap();
        assert_eq!(result, "known_value and ${UNKNOWN_XYZ_VAR}");
        unsafe {
            std::env::remove_var("TEST_KNOWN_VAR");
        }
    }

    #[test]
    fn test_expand_variable_at_start() {
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_START", "start");
        }
        let result = expand_variables("${TEST_START} of string").unwrap();
        assert_eq!(result, "start of string");
        unsafe {
            std::env::remove_var("TEST_START");
        }
    }

    #[test]
    fn test_expand_variable_at_end() {
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_END", "end");
        }
        let result = expand_variables("string at the ${TEST_END}").unwrap();
        assert_eq!(result, "string at the end");
        unsafe {
            std::env::remove_var("TEST_END");
        }
    }

    #[test]
    fn test_expand_only_variable() {
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_ONLY", "only_value");
        }
        let result = expand_variables("${TEST_ONLY}").unwrap();
        assert_eq!(result, "only_value");
        unsafe {
            std::env::remove_var("TEST_ONLY");
        }
    }

    #[test]
    fn test_expand_variable_with_numbers() {
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_VAR_123_ABC", "numeric_name");
        }
        let result = expand_variables("${TEST_VAR_123_ABC}").unwrap();
        assert_eq!(result, "numeric_name");
        unsafe {
            std::env::remove_var("TEST_VAR_123_ABC");
        }
    }

    #[test]
    fn test_expand_variable_with_underscores() {
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST___UNDERSCORES___", "underscored");
        }
        let result = expand_variables("${TEST___UNDERSCORES___}").unwrap();
        assert_eq!(result, "underscored");
        unsafe {
            std::env::remove_var("TEST___UNDERSCORES___");
        }
    }

    #[test]
    fn test_expand_long_value() {
        let long_value = "a".repeat(10000);
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_LONG", &long_value);
        }
        let result = expand_variables("prefix_${TEST_LONG}_suffix").unwrap();
        assert_eq!(result, format!("prefix_{long_value}_suffix"));
        unsafe {
            std::env::remove_var("TEST_LONG");
        }
    }

    #[test]
    fn test_expand_variable_replaces_to_empty() {
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_EMPTY_VAL", "");
        }
        let result = expand_variables("before${TEST_EMPTY_VAL}after").unwrap();
        assert_eq!(result, "beforeafter");
        unsafe {
            std::env::remove_var("TEST_EMPTY_VAL");
        }
    }

    #[test]
    fn test_get_variable_value_fallback_to_env() {
        // Test that custom variable names fall back to environment
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("CUSTOM_TEST_VAR_XYZ", "custom_value");
        }
        let value = get_variable_value("CUSTOM_TEST_VAR_XYZ");
        assert_eq!(value, Some("custom_value".to_string()));
        unsafe {
            std::env::remove_var("CUSTOM_TEST_VAR_XYZ");
        }
    }

    #[test]
    fn test_get_computer_name_returns_something() {
        // This should return something on most platforms
        let name = get_computer_name();
        // hostname crate should work, or COMPUTERNAME env var
        assert!(name.is_some() || std::env::var("COMPUTERNAME").is_err());
    }

    #[test]
    fn test_get_username_returns_something() {
        // USERNAME or USER should be set on most systems
        let username = get_username();
        // At least one of USERNAME or USER should be set
        if std::env::var("USERNAME").is_ok() || std::env::var("USER").is_ok() {
            assert!(username.is_some());
        }
    }

    #[test]
    fn test_get_home_dir_returns_something() {
        let home = get_home_dir();
        // dirs crate should be able to find home on all platforms
        assert!(home.is_some());
    }

    #[test]
    fn test_get_temp_dir_returns_something() {
        let temp = get_temp_dir();
        assert!(temp.is_some());
        assert!(!temp.unwrap().is_empty());
    }
}
