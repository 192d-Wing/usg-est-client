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

//! Windows Service framework for EST auto-enrollment.
//!
//! This module provides the infrastructure for running EST auto-enrollment
//! as a Windows Service. It handles:
//!
//! - Service control events (start, stop, pause, continue)
//! - Service state management
//! - Graceful shutdown with state preservation
//! - Service recovery configuration
//!
//! # Architecture
//!
//! The service is structured as follows:
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │           Windows Service Control Manager        │
//! │                    (SCM)                        │
//! └─────────────────────┬───────────────────────────┘
//!                       │ Control Events
//!                       ▼
//! ┌─────────────────────────────────────────────────┐
//! │              ServiceEventHandler                 │
//! │  - Handles STOP, PAUSE, CONTINUE, etc.          │
//! └─────────────────────┬───────────────────────────┘
//!                       │
//!                       ▼
//! ┌─────────────────────────────────────────────────┐
//! │              EnrollmentService                   │
//! │  - Manages certificate lifecycle                │
//! │  - Runs renewal scheduler                       │
//! │  - Handles enrollment workflows                 │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Service States
//!
//! The service follows the standard Windows service state machine:
//!
//! - `Stopped` - Service is not running
//! - `StartPending` - Service is starting up
//! - `Running` - Service is operational
//! - `PausePending` - Service is pausing
//! - `Paused` - Service is paused (not checking renewals)
//! - `ContinuePending` - Service is resuming
//! - `StopPending` - Service is shutting down
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::service::{EnrollmentService, ServiceConfig};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Run as a Windows service
//!     EnrollmentService::run()?;
//!     Ok(())
//! }
//! ```

use crate::error::{EstError, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

/// Service name as registered with Windows SCM.
pub const SERVICE_NAME: &str = "ESTAutoEnroll";

/// Service display name shown in services.msc.
pub const SERVICE_DISPLAY_NAME: &str = "EST Certificate Auto-Enrollment";

/// Service description.
pub const SERVICE_DESCRIPTION: &str =
    "Automatically enrolls and renews X.509 certificates using EST (RFC 7030)";

/// Service type - we're a standalone service.
#[cfg(windows)]
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Current service state for cross-thread communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStateValue {
    /// Service is not running.
    Stopped = 1,
    /// Service is starting up.
    StartPending = 2,
    /// Service is stopping.
    StopPending = 3,
    /// Service is running.
    Running = 4,
    /// Service is resuming from paused state.
    ContinuePending = 5,
    /// Service is pausing.
    PausePending = 6,
    /// Service is paused.
    Paused = 7,
}

impl ServiceStateValue {
    /// Convert to Windows ServiceState.
    #[cfg(windows)]
    pub fn to_service_state(self) -> ServiceState {
        match self {
            Self::Stopped => ServiceState::Stopped,
            Self::StartPending => ServiceState::StartPending,
            Self::StopPending => ServiceState::StopPending,
            Self::Running => ServiceState::Running,
            Self::ContinuePending => ServiceState::ContinuePending,
            Self::PausePending => ServiceState::PausePending,
            Self::Paused => ServiceState::Paused,
        }
    }

    /// Convert from atomic u32.
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Stopped,
            2 => Self::StartPending,
            3 => Self::StopPending,
            4 => Self::Running,
            5 => Self::ContinuePending,
            6 => Self::PausePending,
            7 => Self::Paused,
            _ => Self::Stopped,
        }
    }
}

/// Shared state between the service event handler and the main loop.
#[derive(Debug)]
pub struct ServiceState {
    /// Whether a shutdown has been requested.
    pub shutdown_requested: AtomicBool,
    /// Whether the service is paused.
    pub paused: AtomicBool,
    /// Current service state.
    pub current_state: AtomicU32,
}

impl ServiceState {
    /// Create a new service state.
    pub fn new() -> Self {
        Self {
            shutdown_requested: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            current_state: AtomicU32::new(ServiceStateValue::Stopped as u32),
        }
    }

    /// Check if shutdown has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Request shutdown.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }

    /// Check if service is paused.
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Set paused state.
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
    }

    /// Get current state.
    pub fn get_state(&self) -> ServiceStateValue {
        ServiceStateValue::from_u32(self.current_state.load(Ordering::SeqCst))
    }

    /// Set current state.
    pub fn set_state(&self, state: ServiceStateValue) {
        self.current_state.store(state as u32, Ordering::SeqCst);
    }
}

impl Default for ServiceState {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for the enrollment service.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Path to the configuration file.
    pub config_path: Option<String>,
    /// Whether to run in verbose/debug mode.
    pub verbose: bool,
    /// Check interval for renewal (in seconds).
    pub check_interval: u64,
    /// Whether to support pause/continue operations.
    pub allow_pause: bool,
    /// Timeout for graceful shutdown (in seconds).
    pub shutdown_timeout: u64,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            config_path: None,
            verbose: false,
            check_interval: 3600, // 1 hour
            allow_pause: true,
            shutdown_timeout: 30,
        }
    }
}

/// Service control handler that processes SCM events.
#[cfg(windows)]
pub struct ServiceEventHandler {
    state: Arc<ServiceState>,
    status_handle: ServiceStatusHandle,
}

#[cfg(windows)]
impl ServiceEventHandler {
    /// Create a new event handler.
    pub fn new(state: Arc<ServiceState>, status_handle: ServiceStatusHandle) -> Self {
        Self {
            state,
            status_handle,
        }
    }

    /// Handle a service control event.
    pub fn handle_control_event(
        &self,
        control_event: ServiceControl,
    ) -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                tracing::info!("Received STOP control event");
                self.state.set_state(ServiceStateValue::StopPending);
                self.state.request_shutdown();
                self.report_status(ServiceStateValue::StopPending, None);
                ServiceControlHandlerResult::NoError
            }

            ServiceControl::Pause => {
                tracing::info!("Received PAUSE control event");
                self.state.set_state(ServiceStateValue::PausePending);
                self.state.set_paused(true);
                self.report_status(ServiceStateValue::Paused, None);
                self.state.set_state(ServiceStateValue::Paused);
                ServiceControlHandlerResult::NoError
            }

            ServiceControl::Continue => {
                tracing::info!("Received CONTINUE control event");
                self.state.set_state(ServiceStateValue::ContinuePending);
                self.state.set_paused(false);
                self.report_status(ServiceStateValue::Running, None);
                self.state.set_state(ServiceStateValue::Running);
                ServiceControlHandlerResult::NoError
            }

            ServiceControl::Interrogate => {
                // Report current status
                self.report_status(self.state.get_state(), None);
                ServiceControlHandlerResult::NoError
            }

            ServiceControl::Preshutdown => {
                tracing::info!("Received PRESHUTDOWN control event");
                // Save any state that needs to be preserved
                self.state.set_state(ServiceStateValue::StopPending);
                self.state.request_shutdown();
                self.report_status(ServiceStateValue::StopPending, None);
                ServiceControlHandlerResult::NoError
            }

            ServiceControl::Shutdown => {
                tracing::info!("Received SHUTDOWN control event");
                self.state.request_shutdown();
                ServiceControlHandlerResult::NoError
            }

            _ => ServiceControlHandlerResult::NotImplemented,
        }
    }

    /// Report service status to SCM.
    fn report_status(&self, state: ServiceStateValue, exit_code: Option<u32>) {
        let controls_accepted = if state == ServiceStateValue::Running {
            ServiceControlAccept::STOP
                | ServiceControlAccept::PAUSE_CONTINUE
                | ServiceControlAccept::PRESHUTDOWN
                | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        };

        let status = ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state.to_service_state(),
            controls_accepted,
            exit_code: match exit_code {
                Some(code) => ServiceExitCode::Win32(code),
                None => ServiceExitCode::Win32(0),
            },
            checkpoint: 0,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        };

        if let Err(e) = self.status_handle.set_service_status(status) {
            tracing::error!("Failed to set service status: {}", e);
        }
    }
}

/// Main enrollment service structure.
pub struct EnrollmentService {
    /// Shared state for cross-thread communication.
    state: Arc<ServiceState>,
    /// Service configuration.
    config: ServiceConfig,
}

impl EnrollmentService {
    /// Create a new enrollment service.
    pub fn new(config: ServiceConfig) -> Self {
        Self {
            state: Arc::new(ServiceState::new()),
            config,
        }
    }

    /// Get a reference to the shared state.
    pub fn state(&self) -> Arc<ServiceState> {
        Arc::clone(&self.state)
    }

    /// Run the service (entry point for Windows service dispatcher).
    #[cfg(windows)]
    pub fn run() -> Result<()> {
        // Register the service with the dispatcher
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|e| EstError::platform(format!("Failed to start service dispatcher: {}", e)))
    }

    /// Main service loop.
    pub async fn run_service_loop(&self) -> Result<()> {
        tracing::info!("EST Auto-Enrollment service starting");

        self.state.set_state(ServiceStateValue::Running);

        // Main service loop
        while !self.state.is_shutdown_requested() {
            if self.state.is_paused() {
                // When paused, just sleep and check for state changes
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }

            // Perform enrollment/renewal check
            if let Err(e) = self.check_certificates().await {
                tracing::error!("Certificate check failed: {}", e);
            }

            // Sleep until next check interval
            let check_interval = Duration::from_secs(self.config.check_interval);
            let sleep_increment = Duration::from_secs(1);
            let mut elapsed = Duration::ZERO;

            while elapsed < check_interval && !self.state.is_shutdown_requested() {
                tokio::time::sleep(sleep_increment).await;
                elapsed += sleep_increment;

                // Check if paused during sleep
                if self.state.is_paused() {
                    break;
                }
            }
        }

        tracing::info!("EST Auto-Enrollment service stopping");
        self.state.set_state(ServiceStateValue::Stopped);

        Ok(())
    }

    /// Check certificates and perform enrollment/renewal if needed.
    async fn check_certificates(&self) -> Result<()> {
        tracing::debug!("Checking certificates for enrollment/renewal");

        // Load configuration
        let config = self.load_config()?;
        tracing::info!("Loaded configuration from: {}", config.server.url);

        // Check if enrollment is needed
        if crate::auto_enroll::needs_enrollment(&config).await? {
            tracing::info!("Enrollment needed, starting enrollment process");
            crate::auto_enroll::perform_enrollment(&config).await?;
        } else if config.renewal.enabled {
            // Check if renewal is needed
            if crate::auto_enroll::check_renewal(&config).await? {
                tracing::info!("Renewal needed, starting renewal process");
                crate::auto_enroll::perform_renewal(&config).await?;
            }
        }

        Ok(())
    }

    /// Load the auto-enrollment configuration.
    fn load_config(&self) -> Result<crate::auto_enroll::AutoEnrollConfig> {
        use crate::auto_enroll::ConfigLoader;

        let mut loader = ConfigLoader::new();

        // If a config path was provided, use it
        if let Some(ref path) = self.config.config_path {
            loader = loader.with_path(path);
        }

        loader.load()
    }

    /// Perform graceful shutdown.
    pub async fn shutdown(&self) {
        tracing::info!("Performing graceful shutdown");

        // Save any state that needs to be preserved
        // Close connections, etc.

        self.state.set_state(ServiceStateValue::Stopped);
    }
}

/// FFI service main function required by windows-service crate.
#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

/// Service main function called by Windows SCM.
#[cfg(windows)]
fn service_main(arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service(arguments) {
        tracing::error!("Service failed: {}", e);
    }
}

/// Internal service runner.
#[cfg(windows)]
fn run_service(_arguments: Vec<std::ffi::OsString>) -> Result<()> {
    let service = EnrollmentService::new(ServiceConfig::default());
    let state = service.state();

    // Register the control handler
    let state_clone = Arc::clone(&state);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        // We need to create the handler inside the closure
        // This is a simplified version - in production, you'd want to
        // properly share the status handle
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                state_clone.request_shutdown();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Pause => {
                state_clone.set_paused(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Continue => {
                state_clone.set_paused(false);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| EstError::platform(format!("Failed to register control handler: {}", e)))?;

    // Report that we're starting
    let status = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    status_handle
        .set_service_status(status)
        .map_err(|e| EstError::platform(format!("Failed to set service status: {}", e)))?;

    // Create tokio runtime and run the service
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| EstError::platform(format!("Failed to create runtime: {}", e)))?;

    // Report that we're running
    let status = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP
            | ServiceControlAccept::PAUSE_CONTINUE
            | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    status_handle
        .set_service_status(status)
        .map_err(|e| EstError::platform(format!("Failed to set service status: {}", e)))?;

    // Run the main service loop
    rt.block_on(service.run_service_loop())?;

    // Report that we've stopped
    let status = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    if let Err(e) = status_handle.set_service_status(status) {
        tracing::error!("Failed to set service status to STOPPED: {}", e);
    }

    Ok(())
}

/// Service installation/management utilities.
pub mod installer {
    use super::*;

    /// Service account type.
    #[derive(Debug, Clone)]
    pub enum ServiceAccount {
        /// LocalSystem account (full access).
        LocalSystem,
        /// LocalService account (limited local access).
        LocalService,
        /// NetworkService account (network access).
        NetworkService,
        /// Custom account (domain\user or .\user).
        Custom {
            /// Account name.
            account: String,
            /// Account password.
            password: Option<String>,
        },
    }

    impl ServiceAccount {
        /// Get the account name for service configuration.
        pub fn account_name(&self) -> Option<&str> {
            match self {
                Self::LocalSystem => None, // Default
                Self::LocalService => Some("NT AUTHORITY\\LocalService"),
                Self::NetworkService => Some("NT AUTHORITY\\NetworkService"),
                Self::Custom { account, .. } => Some(account),
            }
        }
    }

    /// Service start type.
    #[derive(Debug, Clone, Copy)]
    pub enum StartType {
        /// Service starts automatically at boot.
        Automatic,
        /// Service starts automatically but with a delay.
        AutomaticDelayed,
        /// Service must be started manually.
        Manual,
        /// Service is disabled.
        Disabled,
    }

    /// Service recovery action.
    #[derive(Debug, Clone, Copy)]
    pub enum RecoveryAction {
        /// Take no action.
        None,
        /// Restart the service.
        Restart,
        /// Reboot the computer.
        Reboot,
        /// Run a command.
        RunCommand,
    }

    /// Service recovery configuration.
    #[derive(Debug, Clone)]
    pub struct RecoveryConfig {
        /// Action on first failure.
        pub first_failure: RecoveryAction,
        /// Action on second failure.
        pub second_failure: RecoveryAction,
        /// Action on subsequent failures.
        pub subsequent_failures: RecoveryAction,
        /// Reset failure count after this many seconds.
        pub reset_period: u32,
        /// Delay before restart (in milliseconds).
        pub restart_delay: u32,
    }

    impl Default for RecoveryConfig {
        fn default() -> Self {
            Self {
                first_failure: RecoveryAction::Restart,
                second_failure: RecoveryAction::Restart,
                subsequent_failures: RecoveryAction::Restart,
                reset_period: 86400,  // 24 hours
                restart_delay: 60000, // 1 minute
            }
        }
    }

    /// Service installation configuration.
    #[derive(Debug, Clone)]
    pub struct InstallConfig {
        /// Service name.
        pub name: String,
        /// Display name.
        pub display_name: String,
        /// Service description.
        pub description: String,
        /// Path to service executable.
        pub executable_path: String,
        /// Service account.
        pub account: ServiceAccount,
        /// Start type.
        pub start_type: StartType,
        /// Recovery configuration.
        pub recovery: RecoveryConfig,
        /// Service dependencies.
        pub dependencies: Vec<String>,
    }

    impl Default for InstallConfig {
        fn default() -> Self {
            Self {
                name: SERVICE_NAME.to_string(),
                display_name: SERVICE_DISPLAY_NAME.to_string(),
                description: SERVICE_DESCRIPTION.to_string(),
                executable_path: String::new(),
                account: ServiceAccount::LocalSystem,
                start_type: StartType::Automatic,
                recovery: RecoveryConfig::default(),
                dependencies: vec!["Tcpip".to_string(), "Dnscache".to_string()],
            }
        }
    }

    /// Install the service.
    #[cfg(windows)]
    pub fn install_service(config: &InstallConfig) -> Result<()> {
        use windows_service::{
            service::{ServiceAccess, ServiceInfo},
            service_manager::{ServiceManager, ServiceManagerAccess},
        };

        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
                .map_err(|e| {
                    EstError::platform(format!("Failed to open service manager: {}", e))
                })?;

        let start_type = match config.start_type {
            StartType::Automatic | StartType::AutomaticDelayed => {
                windows_service::service::ServiceStartType::AutoStart
            }
            StartType::Manual => windows_service::service::ServiceStartType::OnDemand,
            StartType::Disabled => windows_service::service::ServiceStartType::Disabled,
        };

        let service_info = ServiceInfo {
            name: config.name.clone().into(),
            display_name: config.display_name.clone().into(),
            service_type: SERVICE_TYPE,
            start_type,
            error_control: windows_service::service::ServiceErrorControl::Normal,
            executable_path: std::path::PathBuf::from(&config.executable_path),
            launch_arguments: vec![],
            dependencies: config
                .dependencies
                .iter()
                .map(|s| windows_service::service::ServiceDependency::Service(s.clone().into()))
                .collect(),
            account_name: config.account.account_name().map(|s| s.into()),
            account_password: match &config.account {
                ServiceAccount::Custom { password, .. } => password.clone(),
                _ => None,
            },
        };

        manager
            .create_service(&service_info, ServiceAccess::all())
            .map_err(|e| EstError::platform(format!("Failed to create service: {}", e)))?;

        tracing::info!("Service '{}' installed successfully", config.name);
        Ok(())
    }

    /// Uninstall the service.
    #[cfg(windows)]
    pub fn uninstall_service(name: &str) -> Result<()> {
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| {
            EstError::platform(format!("Failed to open service manager: {}", e))
        })?;

        let service = manager
            .open_service(name, ServiceAccess::DELETE)
            .map_err(|e| EstError::platform(format!("Failed to open service: {}", e)))?;

        service
            .delete()
            .map_err(|e| EstError::platform(format!("Failed to delete service: {}", e)))?;

        tracing::info!("Service '{}' uninstalled successfully", name);
        Ok(())
    }

    /// Start the service.
    #[cfg(windows)]
    pub fn start_service(name: &str) -> Result<()> {
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| {
            EstError::platform(format!("Failed to open service manager: {}", e))
        })?;

        let service = manager
            .open_service(name, ServiceAccess::START)
            .map_err(|e| EstError::platform(format!("Failed to open service: {}", e)))?;

        service
            .start(&[] as &[&str])
            .map_err(|e| EstError::platform(format!("Failed to start service: {}", e)))?;

        tracing::info!("Service '{}' started", name);
        Ok(())
    }

    /// Stop the service.
    #[cfg(windows)]
    pub fn stop_service(name: &str) -> Result<()> {
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| {
            EstError::platform(format!("Failed to open service manager: {}", e))
        })?;

        let service = manager
            .open_service(name, ServiceAccess::STOP)
            .map_err(|e| EstError::platform(format!("Failed to open service: {}", e)))?;

        service
            .stop()
            .map_err(|e| EstError::platform(format!("Failed to stop service: {}", e)))?;

        tracing::info!("Service '{}' stopped", name);
        Ok(())
    }

    /// Get service status.
    #[cfg(windows)]
    pub fn get_service_status(name: &str) -> Result<ServiceStateValue> {
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| {
            EstError::platform(format!("Failed to open service manager: {}", e))
        })?;

        let service = manager
            .open_service(name, ServiceAccess::QUERY_STATUS)
            .map_err(|e| EstError::platform(format!("Failed to open service: {}", e)))?;

        let status = service
            .query_status()
            .map_err(|e| EstError::platform(format!("Failed to query status: {}", e)))?;

        Ok(match status.current_state {
            ServiceState::Stopped => ServiceStateValue::Stopped,
            ServiceState::StartPending => ServiceStateValue::StartPending,
            ServiceState::StopPending => ServiceStateValue::StopPending,
            ServiceState::Running => ServiceStateValue::Running,
            ServiceState::ContinuePending => ServiceStateValue::ContinuePending,
            ServiceState::PausePending => ServiceStateValue::PausePending,
            ServiceState::Paused => ServiceStateValue::Paused,
        })
    }

    /// Non-Windows stubs.
    #[cfg(not(windows))]
    pub fn install_service(_config: &InstallConfig) -> Result<()> {
        Err(EstError::platform("Service installation requires Windows"))
    }

    #[cfg(not(windows))]
    pub fn uninstall_service(_name: &str) -> Result<()> {
        Err(EstError::platform(
            "Service uninstallation requires Windows",
        ))
    }

    #[cfg(not(windows))]
    pub fn start_service(_name: &str) -> Result<()> {
        Err(EstError::platform("Service start requires Windows"))
    }

    #[cfg(not(windows))]
    pub fn stop_service(_name: &str) -> Result<()> {
        Err(EstError::platform("Service stop requires Windows"))
    }

    #[cfg(not(windows))]
    pub fn get_service_status(_name: &str) -> Result<ServiceStateValue> {
        Err(EstError::platform("Service status requires Windows"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_state_value() {
        assert_eq!(ServiceStateValue::from_u32(1), ServiceStateValue::Stopped);
        assert_eq!(ServiceStateValue::from_u32(4), ServiceStateValue::Running);
        assert_eq!(ServiceStateValue::from_u32(7), ServiceStateValue::Paused);
        assert_eq!(ServiceStateValue::from_u32(99), ServiceStateValue::Stopped);
    }

    #[test]
    fn test_service_state() {
        let state = ServiceState::new();

        assert!(!state.is_shutdown_requested());
        assert!(!state.is_paused());
        assert_eq!(state.get_state(), ServiceStateValue::Stopped);

        state.request_shutdown();
        assert!(state.is_shutdown_requested());

        state.set_paused(true);
        assert!(state.is_paused());

        state.set_state(ServiceStateValue::Running);
        assert_eq!(state.get_state(), ServiceStateValue::Running);
    }

    #[test]
    fn test_service_config_default() {
        let config = ServiceConfig::default();
        assert!(config.config_path.is_none());
        assert!(!config.verbose);
        assert_eq!(config.check_interval, 3600);
        assert!(config.allow_pause);
        assert_eq!(config.shutdown_timeout, 30);
    }

    #[test]
    fn test_service_account() {
        assert!(
            installer::ServiceAccount::LocalSystem
                .account_name()
                .is_none()
        );
        assert_eq!(
            installer::ServiceAccount::LocalService.account_name(),
            Some("NT AUTHORITY\\LocalService")
        );
        assert_eq!(
            installer::ServiceAccount::NetworkService.account_name(),
            Some("NT AUTHORITY\\NetworkService")
        );

        let custom = installer::ServiceAccount::Custom {
            account: "DOMAIN\\User".to_string(),
            password: Some("password".to_string()),
        };
        assert_eq!(custom.account_name(), Some("DOMAIN\\User"));
    }

    #[test]
    fn test_install_config_default() {
        let config = installer::InstallConfig::default();
        assert_eq!(config.name, SERVICE_NAME);
        assert_eq!(config.display_name, SERVICE_DISPLAY_NAME);
        assert!(!config.dependencies.is_empty());
    }

    #[test]
    fn test_recovery_config_default() {
        let config = installer::RecoveryConfig::default();
        assert!(matches!(
            config.first_failure,
            installer::RecoveryAction::Restart
        ));
        assert_eq!(config.reset_period, 86400);
        assert_eq!(config.restart_delay, 60000);
    }

    // ===== Additional Phase 11.8 Service Tests =====

    #[test]
    fn test_all_service_state_values() {
        // Test all state value conversions
        for (val, expected) in [
            (1u32, ServiceStateValue::Stopped),
            (2, ServiceStateValue::StartPending),
            (3, ServiceStateValue::StopPending),
            (4, ServiceStateValue::Running),
            (5, ServiceStateValue::ContinuePending),
            (6, ServiceStateValue::PausePending),
            (7, ServiceStateValue::Paused),
        ] {
            assert_eq!(ServiceStateValue::from_u32(val), expected);
            // Round-trip test
            assert_eq!(ServiceStateValue::from_u32(expected as u32), expected);
        }
    }

    #[test]
    fn test_service_state_default() {
        let state = ServiceState::default();
        assert!(!state.is_shutdown_requested());
        assert!(!state.is_paused());
        assert_eq!(state.get_state(), ServiceStateValue::Stopped);
    }

    #[test]
    fn test_service_state_transitions() {
        let state = ServiceState::new();

        // Start transition
        state.set_state(ServiceStateValue::StartPending);
        assert_eq!(state.get_state(), ServiceStateValue::StartPending);

        state.set_state(ServiceStateValue::Running);
        assert_eq!(state.get_state(), ServiceStateValue::Running);

        // Pause transition
        state.set_state(ServiceStateValue::PausePending);
        state.set_paused(true);
        assert!(state.is_paused());
        state.set_state(ServiceStateValue::Paused);
        assert_eq!(state.get_state(), ServiceStateValue::Paused);

        // Resume transition
        state.set_state(ServiceStateValue::ContinuePending);
        state.set_paused(false);
        assert!(!state.is_paused());
        state.set_state(ServiceStateValue::Running);
        assert_eq!(state.get_state(), ServiceStateValue::Running);

        // Stop transition
        state.set_state(ServiceStateValue::StopPending);
        state.request_shutdown();
        assert!(state.is_shutdown_requested());
        state.set_state(ServiceStateValue::Stopped);
        assert_eq!(state.get_state(), ServiceStateValue::Stopped);
    }

    #[test]
    fn test_service_state_concurrent_access() {
        use std::thread;

        let state = Arc::new(ServiceState::new());

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if i % 2 == 0 {
                        state.set_state(ServiceStateValue::Running);
                    } else {
                        state.set_state(ServiceStateValue::Paused);
                    }
                    state.get_state()
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join().unwrap();
        }

        // State should be valid (either Running or Paused)
        let final_state = state.get_state();
        assert!(
            final_state == ServiceStateValue::Running || final_state == ServiceStateValue::Paused
        );
    }

    #[test]
    fn test_service_config_custom() {
        let config = ServiceConfig {
            config_path: Some("/etc/est/config.toml".to_string()),
            verbose: true,
            check_interval: 1800,
            allow_pause: false,
            shutdown_timeout: 60,
        };

        assert_eq!(config.config_path, Some("/etc/est/config.toml".to_string()));
        assert!(config.verbose);
        assert_eq!(config.check_interval, 1800);
        assert!(!config.allow_pause);
        assert_eq!(config.shutdown_timeout, 60);
    }

    #[test]
    fn test_enrollment_service_creation() {
        let config = ServiceConfig::default();
        let service = EnrollmentService::new(config);
        let state = service.state();

        assert_eq!(state.get_state(), ServiceStateValue::Stopped);
        assert!(!state.is_shutdown_requested());
        assert!(!state.is_paused());
    }

    #[test]
    fn test_enrollment_service_state_sharing() {
        let config = ServiceConfig::default();
        let service = EnrollmentService::new(config);

        let state1 = service.state();
        let state2 = service.state();

        // Both should point to the same state
        state1.set_state(ServiceStateValue::Running);
        assert_eq!(state2.get_state(), ServiceStateValue::Running);

        state2.request_shutdown();
        assert!(state1.is_shutdown_requested());
    }

    #[test]
    fn test_service_account_custom_no_password() {
        let account = installer::ServiceAccount::Custom {
            account: "WORKGROUP\\ServiceUser".to_string(),
            password: None,
        };
        assert_eq!(account.account_name(), Some("WORKGROUP\\ServiceUser"));
    }

    #[test]
    fn test_install_config_custom() {
        let config = installer::InstallConfig {
            name: "CustomService".to_string(),
            display_name: "Custom EST Service".to_string(),
            description: "Custom description".to_string(),
            executable_path: "C:\\Program Files\\EST\\est-enroll.exe".to_string(),
            account: installer::ServiceAccount::NetworkService,
            start_type: installer::StartType::AutomaticDelayed,
            recovery: installer::RecoveryConfig {
                first_failure: installer::RecoveryAction::Restart,
                second_failure: installer::RecoveryAction::Restart,
                subsequent_failures: installer::RecoveryAction::None,
                reset_period: 43200,
                restart_delay: 30000,
            },
            dependencies: vec!["Tcpip".to_string()],
        };

        assert_eq!(config.name, "CustomService");
        assert_eq!(config.display_name, "Custom EST Service");
        assert!(matches!(
            config.start_type,
            installer::StartType::AutomaticDelayed
        ));
        assert_eq!(config.dependencies.len(), 1);
    }

    #[test]
    fn test_all_start_types() {
        // Verify all start types are constructible
        let _auto = installer::StartType::Automatic;
        let _delayed = installer::StartType::AutomaticDelayed;
        let _manual = installer::StartType::Manual;
        let _disabled = installer::StartType::Disabled;
    }

    #[test]
    fn test_all_recovery_actions() {
        // Verify all recovery actions are constructible
        let _none = installer::RecoveryAction::None;
        let _restart = installer::RecoveryAction::Restart;
        let _reboot = installer::RecoveryAction::Reboot;
        let _run_cmd = installer::RecoveryAction::RunCommand;
    }

    #[test]
    fn test_recovery_config_custom() {
        let config = installer::RecoveryConfig {
            first_failure: installer::RecoveryAction::Restart,
            second_failure: installer::RecoveryAction::Reboot,
            subsequent_failures: installer::RecoveryAction::RunCommand,
            reset_period: 3600,
            restart_delay: 120000,
        };

        assert!(matches!(
            config.first_failure,
            installer::RecoveryAction::Restart
        ));
        assert!(matches!(
            config.second_failure,
            installer::RecoveryAction::Reboot
        ));
        assert!(matches!(
            config.subsequent_failures,
            installer::RecoveryAction::RunCommand
        ));
        assert_eq!(config.reset_period, 3600);
        assert_eq!(config.restart_delay, 120000);
    }

    #[test]
    fn test_service_constants() {
        assert_eq!(SERVICE_NAME, "ESTAutoEnroll");
        assert!(!SERVICE_DISPLAY_NAME.is_empty());
        assert!(!SERVICE_DESCRIPTION.is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_non_windows_stubs() {
        let config = installer::InstallConfig::default();

        // All operations should fail on non-Windows
        assert!(installer::install_service(&config).is_err());
        assert!(installer::uninstall_service("test").is_err());
        assert!(installer::start_service("test").is_err());
        assert!(installer::stop_service("test").is_err());
        assert!(installer::get_service_status("test").is_err());
    }
}
