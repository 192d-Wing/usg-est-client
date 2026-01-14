// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Windows machine identity retrieval for EST enrollment.
//!
//! This module provides functionality to retrieve machine-specific identity
//! information on Windows systems. This information is used for:
//!
//! - Generating unique machine identifiers for enrollment
//! - Populating certificate subject fields
//! - Authenticating with EST servers using machine credentials
//!
//! # Machine Identity Components
//!
//! - **Computer Name**: The NetBIOS computer name (e.g., "WORKSTATION01")
//! - **DNS Hostname**: The fully qualified DNS name (e.g., "workstation01.example.com")
//! - **Domain**: The Active Directory domain name (if joined)
//! - **Machine SID**: The unique security identifier for the machine account
//! - **Workgroup**: The workgroup name (if not domain-joined)
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::identity::MachineIdentity;
//!
//! let identity = MachineIdentity::current()?;
//!
//! println!("Computer Name: {}", identity.computer_name);
//! println!("Domain: {:?}", identity.domain);
//! println!("Is Domain Joined: {}", identity.is_domain_joined());
//!
//! // Generate a machine-specific username for EST
//! let username = identity.machine_username();
//! println!("EST Username: {}", username);
//! ```

use crate::error::{EstError, Result};

#[cfg(windows)]
use windows::Win32::System::SystemInformation::{
    ComputerNameDnsDomain, ComputerNameDnsFullyQualified, ComputerNameDnsHostname,
    ComputerNameNetBIOS, GetComputerNameExW,
};

/// Machine identity information retrieved from Windows.
#[derive(Debug, Clone)]
pub struct MachineIdentity {
    /// The NetBIOS computer name (e.g., "WORKSTATION01").
    pub computer_name: String,
    /// The DNS hostname (e.g., "workstation01").
    pub dns_hostname: String,
    /// The fully qualified DNS name (e.g., "workstation01.example.com").
    pub fqdn: Option<String>,
    /// The Active Directory domain name (if domain-joined).
    pub domain: Option<String>,
    /// The workgroup name (if not domain-joined).
    pub workgroup: Option<String>,
    /// The machine SID as a string (e.g., "S-1-5-21-...").
    pub machine_sid: Option<String>,
    /// Whether the machine is domain-joined.
    domain_joined: bool,
}

impl MachineIdentity {
    /// Retrieve the current machine's identity.
    ///
    /// This queries Windows APIs to gather machine identity information
    /// including computer name, domain membership, and DNS names.
    pub fn current() -> Result<Self> {
        #[cfg(windows)]
        {
            Self::current_windows()
        }

        #[cfg(not(windows))]
        {
            Self::current_fallback()
        }
    }

    /// Windows implementation of identity retrieval.
    #[cfg(windows)]
    fn current_windows() -> Result<Self> {
        let computer_name = Self::get_computer_name_ex(ComputerNameNetBIOS)?;
        let dns_hostname = Self::get_computer_name_ex(ComputerNameDnsHostname)
            .unwrap_or_else(|_| computer_name.clone());
        let fqdn = Self::get_computer_name_ex(ComputerNameDnsFullyQualified).ok();
        let domain = Self::get_computer_name_ex(ComputerNameDnsDomain).ok();

        // Determine if domain-joined based on whether we have a domain name
        let domain_joined = domain.as_ref().map(|d| !d.is_empty()).unwrap_or(false);

        Ok(Self {
            computer_name,
            dns_hostname,
            fqdn,
            domain: if domain_joined { domain } else { None },
            workgroup: if domain_joined {
                None
            } else {
                Self::get_workgroup().ok()
            },
            machine_sid: Self::get_machine_sid().ok(),
            domain_joined,
        })
    }

    /// Fallback implementation for non-Windows platforms.
    #[cfg(not(windows))]
    fn current_fallback() -> Result<Self> {
        // Use hostname crate for cross-platform hostname
        let hostname = hostname::get()
            .map_err(|e| EstError::platform(format!("Failed to get hostname: {}", e)))?
            .to_string_lossy()
            .to_string();

        Ok(Self {
            computer_name: hostname.clone(),
            dns_hostname: hostname.clone(),
            fqdn: None,
            domain: None,
            workgroup: None,
            machine_sid: None,
            domain_joined: false,
        })
    }

    /// Get a computer name using GetComputerNameExW.
    #[cfg(windows)]
    fn get_computer_name_ex(
        name_type: windows::Win32::System::SystemInformation::COMPUTER_NAME_FORMAT,
    ) -> Result<String> {
        let mut size = 0u32;

        // First call to get required buffer size
        unsafe {
            let _ = GetComputerNameExW(name_type, windows::core::PWSTR::null(), &mut size);
        }

        if size == 0 {
            return Err(EstError::platform("Failed to get computer name size"));
        }

        // Allocate buffer and get the name
        let mut buffer = vec![0u16; size as usize];
        let result = unsafe {
            GetComputerNameExW(
                name_type,
                windows::core::PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
        };

        if result.is_err() {
            return Err(EstError::platform(format!(
                "Failed to get computer name: {:?}",
                result
            )));
        }

        // Convert to String, removing null terminator
        let name = String::from_utf16_lossy(&buffer[..size as usize]);
        Ok(name)
    }

    /// Get the workgroup name.
    #[cfg(windows)]
    fn get_workgroup() -> Result<String> {
        // In a full implementation, this would use NetGetJoinInformation
        // For now, return a placeholder
        Err(EstError::platform("Workgroup detection not implemented"))
    }

    /// Get the machine SID.
    #[cfg(windows)]
    fn get_machine_sid() -> Result<String> {
        // In a full implementation, this would query the machine SID from the registry
        // or use LsaQueryInformationPolicy
        // For now, return a placeholder
        Err(EstError::platform("Machine SID retrieval not implemented"))
    }

    /// Check if the machine is domain-joined.
    pub fn is_domain_joined(&self) -> bool {
        self.domain_joined
    }

    /// Get the machine username for EST enrollment.
    ///
    /// This returns a username suitable for HTTP Basic authentication
    /// with an EST server. The format depends on domain membership:
    ///
    /// - Domain-joined: `DOMAIN\COMPUTERNAME$`
    /// - Workgroup: `COMPUTERNAME`
    pub fn machine_username(&self) -> String {
        if let Some(ref domain) = self.domain {
            format!("{}\\{}$", domain, self.computer_name)
        } else {
            self.computer_name.clone()
        }
    }

    /// Get a suggested Common Name (CN) for certificate enrollment.
    ///
    /// Returns the FQDN if available, otherwise the DNS hostname.
    pub fn suggested_cn(&self) -> String {
        self.fqdn
            .clone()
            .or_else(|| Some(format!("{}.local", self.dns_hostname)))
            .unwrap_or_else(|| self.computer_name.clone())
    }

    /// Get suggested Subject Alternative Names (SANs) for certificate enrollment.
    ///
    /// Returns a list of DNS names that should be included in the certificate:
    /// - FQDN (if available)
    /// - DNS hostname
    /// - NetBIOS computer name
    pub fn suggested_sans(&self) -> Vec<String> {
        let mut sans = Vec::new();

        if let Some(ref fqdn) = self.fqdn {
            sans.push(fqdn.clone());
        }

        if !self.dns_hostname.is_empty() && !sans.contains(&self.dns_hostname) {
            sans.push(self.dns_hostname.clone());
        }

        if !self.computer_name.is_empty()
            && !sans.contains(&self.computer_name)
            && self.computer_name != self.dns_hostname
        {
            sans.push(self.computer_name.clone());
        }

        sans
    }

    /// Get the domain component for certificate subject.
    ///
    /// Returns the domain in a format suitable for DC= components:
    /// e.g., "example.com" -> ["example", "com"]
    pub fn domain_components(&self) -> Vec<String> {
        self.domain
            .as_ref()
            .map(|d| d.split('.').map(|s| s.to_string()).collect())
            .unwrap_or_default()
    }
}

/// Get the currently logged-in username.
///
/// This returns the username of the interactive user, which may be
/// different from the machine identity used for enrollment.
pub fn current_username() -> Result<String> {
    #[cfg(windows)]
    {
        use windows::Win32::System::WindowsProgramming::GetUserNameW;

        let mut size = 0u32;

        // First call to get required buffer size
        unsafe {
            let _ = GetUserNameW(windows::core::PWSTR::null(), &mut size);
        }

        if size == 0 {
            return Err(EstError::platform("Failed to get username size"));
        }

        let mut buffer = vec![0u16; size as usize];
        let result = unsafe { GetUserNameW(windows::core::PWSTR(buffer.as_mut_ptr()), &mut size) };

        if result.is_err() {
            return Err(EstError::platform("Failed to get username"));
        }

        let name = String::from_utf16_lossy(&buffer[..(size as usize).saturating_sub(1)]);
        Ok(name)
    }

    #[cfg(not(windows))]
    {
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .map_err(|_| EstError::platform("Failed to get username"))
    }
}

/// Check if the current process is running as the SYSTEM account.
///
/// This is relevant for Windows services that run as LocalSystem.
pub fn is_running_as_system() -> bool {
    #[cfg(windows)]
    {
        // In a full implementation, this would check the current token SID
        // against the well-known SYSTEM SID (S-1-5-18)
        false
    }

    #[cfg(not(windows))]
    {
        false
    }
}

/// Check if the current process is running as a service.
///
/// Services have different security contexts and may need special
/// handling for credential access.
pub fn is_running_as_service() -> bool {
    #[cfg(windows)]
    {
        // In a full implementation, this would check if stdin is a console
        // or use the service control manager to determine service context
        false
    }

    #[cfg(not(windows))]
    {
        false
    }
}

/// Domain join information.
#[derive(Debug, Clone)]
pub struct DomainInfo {
    /// The domain name.
    pub name: String,
    /// The domain controller hostname.
    pub domain_controller: Option<String>,
    /// The domain forest name.
    pub forest: Option<String>,
    /// Whether this is an Azure AD joined device.
    pub is_azure_ad_joined: bool,
}

/// Get detailed domain information.
///
/// This provides more detailed information about domain membership
/// than `MachineIdentity::domain`.
pub fn get_domain_info() -> Result<Option<DomainInfo>> {
    #[cfg(windows)]
    {
        // In a full implementation, this would use NetGetJoinInformation
        // and DsGetDcName to get detailed domain info
        let identity = MachineIdentity::current()?;
        if let Some(domain) = identity.domain {
            Ok(Some(DomainInfo {
                name: domain,
                domain_controller: None,
                forest: None,
                is_azure_ad_joined: false,
            }))
        } else {
            Ok(None)
        }
    }

    #[cfg(not(windows))]
    {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_machine_identity_suggested_cn() {
        let identity = MachineIdentity {
            computer_name: "WORKSTATION01".to_string(),
            dns_hostname: "workstation01".to_string(),
            fqdn: Some("workstation01.example.com".to_string()),
            domain: Some("example.com".to_string()),
            workgroup: None,
            machine_sid: None,
            domain_joined: true,
        };

        assert_eq!(identity.suggested_cn(), "workstation01.example.com");
    }

    #[test]
    fn test_machine_identity_suggested_cn_no_fqdn() {
        let identity = MachineIdentity {
            computer_name: "WORKSTATION01".to_string(),
            dns_hostname: "workstation01".to_string(),
            fqdn: None,
            domain: None,
            workgroup: Some("WORKGROUP".to_string()),
            machine_sid: None,
            domain_joined: false,
        };

        assert_eq!(identity.suggested_cn(), "workstation01.local");
    }

    #[test]
    fn test_machine_identity_machine_username_domain() {
        let identity = MachineIdentity {
            computer_name: "WORKSTATION01".to_string(),
            dns_hostname: "workstation01".to_string(),
            fqdn: Some("workstation01.example.com".to_string()),
            domain: Some("EXAMPLE".to_string()),
            workgroup: None,
            machine_sid: None,
            domain_joined: true,
        };

        assert_eq!(identity.machine_username(), "EXAMPLE\\WORKSTATION01$");
    }

    #[test]
    fn test_machine_identity_machine_username_workgroup() {
        let identity = MachineIdentity {
            computer_name: "WORKSTATION01".to_string(),
            dns_hostname: "workstation01".to_string(),
            fqdn: None,
            domain: None,
            workgroup: Some("WORKGROUP".to_string()),
            machine_sid: None,
            domain_joined: false,
        };

        assert_eq!(identity.machine_username(), "WORKSTATION01");
    }

    #[test]
    fn test_machine_identity_suggested_sans() {
        let identity = MachineIdentity {
            computer_name: "WORKSTATION01".to_string(),
            dns_hostname: "workstation01".to_string(),
            fqdn: Some("workstation01.example.com".to_string()),
            domain: Some("example.com".to_string()),
            workgroup: None,
            machine_sid: None,
            domain_joined: true,
        };

        let sans = identity.suggested_sans();
        assert!(sans.contains(&"workstation01.example.com".to_string()));
        assert!(sans.contains(&"workstation01".to_string()));
        assert!(sans.contains(&"WORKSTATION01".to_string()));
    }

    #[test]
    fn test_machine_identity_domain_components() {
        let identity = MachineIdentity {
            computer_name: "WORKSTATION01".to_string(),
            dns_hostname: "workstation01".to_string(),
            fqdn: None,
            domain: Some("corp.example.com".to_string()),
            workgroup: None,
            machine_sid: None,
            domain_joined: true,
        };

        let dcs = identity.domain_components();
        assert_eq!(dcs, vec!["corp", "example", "com"]);
    }

    #[test]
    fn test_is_domain_joined() {
        let domain_joined = MachineIdentity {
            computer_name: "PC".to_string(),
            dns_hostname: "pc".to_string(),
            fqdn: None,
            domain: Some("example.com".to_string()),
            workgroup: None,
            machine_sid: None,
            domain_joined: true,
        };
        assert!(domain_joined.is_domain_joined());

        let workgroup = MachineIdentity {
            computer_name: "PC".to_string(),
            dns_hostname: "pc".to_string(),
            fqdn: None,
            domain: None,
            workgroup: Some("WORKGROUP".to_string()),
            machine_sid: None,
            domain_joined: false,
        };
        assert!(!workgroup.is_domain_joined());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_current_identity_fallback() {
        // On non-Windows, we should get a fallback identity
        let identity = MachineIdentity::current().unwrap();
        assert!(!identity.computer_name.is_empty());
        assert!(!identity.dns_hostname.is_empty());
        assert!(!identity.is_domain_joined());
    }

    #[test]
    fn test_is_running_as_system() {
        // Should not crash
        let _ = is_running_as_system();
    }

    #[test]
    fn test_is_running_as_service() {
        // Should not crash
        let _ = is_running_as_service();
    }
}
