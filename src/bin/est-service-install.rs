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

//! EST Auto-Enrollment Service Installer
//!
//! This binary provides commands for installing, uninstalling, and managing
//! the EST auto-enrollment Windows service.
//!
//! # Usage
//!
//! ```text
//! est-service-install install   - Install the service
//! est-service-install uninstall - Remove the service
//! est-service-install start     - Start the service
//! est-service-install stop      - Stop the service
//! est-service-install status    - Query service status
//! ```
//!
//! # Administrator Privileges
//!
//! Most operations require administrator privileges. Run from an elevated
//! command prompt or PowerShell session.

use std::env;
use std::process::ExitCode;

#[cfg(all(windows, feature = "windows-service"))]
use std::path::PathBuf;

#[cfg(all(windows, feature = "windows-service"))]
use usg_est_client::windows::service::{
    SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME,
    installer::{self, InstallConfig, ServiceAccount, StartType},
};

fn main() -> ExitCode {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        return ExitCode::FAILURE;
    }

    let command = args[1].to_lowercase();

    #[cfg(all(windows, feature = "windows-service"))]
    {
        let result = match command.as_str() {
            "install" => cmd_install(&args),
            "uninstall" | "remove" => cmd_uninstall(),
            "start" => cmd_start(),
            "stop" => cmd_stop(),
            "status" => cmd_status(),
            "help" | "--help" | "-h" => {
                print_usage(&args[0]);
                Ok(())
            }
            _ => {
                eprintln!("Unknown command: {}", command);
                print_usage(&args[0]);
                Err("Unknown command".to_string())
            }
        };

        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: {}", e);
                ExitCode::FAILURE
            }
        }
    }

    #[cfg(not(all(windows, feature = "windows-service")))]
    {
        let _ = command;
        eprintln!("This tool requires Windows and the 'windows-service' feature.");
        ExitCode::FAILURE
    }
}

fn print_usage(program: &str) {
    println!("EST Auto-Enrollment Service Installer");
    println!();
    println!("Usage: {} <command> [options]", program);
    println!();
    println!("Commands:");
    println!("  install     Install the service");
    println!("  uninstall   Remove the service");
    println!("  start       Start the service");
    println!("  stop        Stop the service");
    println!("  status      Query service status");
    println!("  help        Show this help message");
    println!();
    println!("Install Options:");
    println!("  --account <type>    Service account: system, localservice, networkservice");
    println!("  --start-type <type> Start type: auto, delayed, manual, disabled");
    println!("  --config <path>     Path to configuration file");
    println!();
    println!("Examples:");
    println!("  {} install", program);
    println!(
        "  {} install --account networkservice --start-type delayed",
        program
    );
    println!("  {} uninstall", program);
    println!("  {} status", program);
    println!();
    println!("Note: Most operations require administrator privileges.");
}

#[cfg(all(windows, feature = "windows-service"))]
fn cmd_install(args: &[String]) -> Result<(), String> {
    use usg_est_client::windows::is_elevated;

    // Check for admin privileges
    if !is_elevated() {
        return Err(
            "Administrator privileges required. Please run from an elevated command prompt."
                .to_string(),
        );
    }

    // Get the path to the service executable
    let exe_path = get_service_executable_path()?;

    // Parse options
    let mut account = ServiceAccount::LocalSystem;
    let mut start_type = StartType::Automatic;
    let mut _config_path: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--account" => {
                i += 1;
                if i >= args.len() {
                    return Err("--account requires a value".to_string());
                }
                account = parse_account(&args[i])?;
            }
            "--start-type" => {
                i += 1;
                if i >= args.len() {
                    return Err("--start-type requires a value".to_string());
                }
                start_type = parse_start_type(&args[i])?;
            }
            "--config" => {
                i += 1;
                if i >= args.len() {
                    return Err("--config requires a value".to_string());
                }
                _config_path = Some(args[i].clone());
            }
            arg => {
                return Err(format!("Unknown option: {}", arg));
            }
        }
        i += 1;
    }

    let config = InstallConfig {
        name: SERVICE_NAME.to_string(),
        display_name: SERVICE_DISPLAY_NAME.to_string(),
        description: SERVICE_DESCRIPTION.to_string(),
        executable_path: exe_path.to_string_lossy().to_string(),
        account,
        start_type,
        ..Default::default()
    };

    println!("Installing service '{}'...", config.name);
    println!("  Display Name: {}", config.display_name);
    println!("  Executable: {}", config.executable_path);
    println!(
        "  Account: {:?}",
        config.account.account_name().unwrap_or("LocalSystem")
    );
    println!("  Start Type: {:?}", config.start_type);

    installer::install_service(&config).map_err(|e| e.to_string())?;

    println!();
    println!("Service installed successfully.");

    // Register Windows Event Log source
    println!();
    println!("Registering Windows Event Log source...");
    match usg_est_client::windows::eventlog::register_event_source() {
        Ok(()) => println!("Event Log source registered successfully."),
        Err(e) => {
            eprintln!("Warning: Failed to register Event Log source: {}", e);
            eprintln!("Event logging may not work correctly.");
        }
    }

    println!();
    println!(
        "To start the service, run: {} start",
        env::args().next().unwrap_or_default()
    );
    println!("Or use: sc start {}", SERVICE_NAME);

    Ok(())
}

#[cfg(all(windows, feature = "windows-service"))]
fn cmd_uninstall() -> Result<(), String> {
    use usg_est_client::windows::is_elevated;

    if !is_elevated() {
        return Err("Administrator privileges required.".to_string());
    }

    println!("Stopping service if running...");
    let _ = installer::stop_service(SERVICE_NAME);

    // Wait a moment for the service to stop
    std::thread::sleep(std::time::Duration::from_secs(2));

    println!("Uninstalling service '{}'...", SERVICE_NAME);
    installer::uninstall_service(SERVICE_NAME).map_err(|e| e.to_string())?;

    // Unregister Windows Event Log source
    println!("Unregistering Windows Event Log source...");
    match usg_est_client::windows::eventlog::unregister_event_source() {
        Ok(()) => println!("Event Log source unregistered successfully."),
        Err(e) => {
            eprintln!("Warning: Failed to unregister Event Log source: {}", e);
        }
    }

    println!("Service uninstalled successfully.");
    Ok(())
}

#[cfg(all(windows, feature = "windows-service"))]
fn cmd_start() -> Result<(), String> {
    use usg_est_client::windows::is_elevated;

    if !is_elevated() {
        return Err("Administrator privileges required.".to_string());
    }

    println!("Starting service '{}'...", SERVICE_NAME);
    installer::start_service(SERVICE_NAME).map_err(|e| e.to_string())?;

    println!("Service started.");
    Ok(())
}

#[cfg(all(windows, feature = "windows-service"))]
fn cmd_stop() -> Result<(), String> {
    use usg_est_client::windows::is_elevated;

    if !is_elevated() {
        return Err("Administrator privileges required.".to_string());
    }

    println!("Stopping service '{}'...", SERVICE_NAME);
    installer::stop_service(SERVICE_NAME).map_err(|e| e.to_string())?;

    println!("Service stopped.");
    Ok(())
}

#[cfg(all(windows, feature = "windows-service"))]
fn cmd_status() -> Result<(), String> {
    use usg_est_client::windows::service::ServiceStateValue;

    match installer::get_service_status(SERVICE_NAME) {
        Ok(status) => {
            let status_str = match status {
                ServiceStateValue::Stopped => "Stopped",
                ServiceStateValue::StartPending => "Start Pending",
                ServiceStateValue::StopPending => "Stop Pending",
                ServiceStateValue::Running => "Running",
                ServiceStateValue::ContinuePending => "Continue Pending",
                ServiceStateValue::PausePending => "Pause Pending",
                ServiceStateValue::Paused => "Paused",
            };
            println!("Service '{}': {}", SERVICE_NAME, status_str);
            Ok(())
        }
        Err(e) => {
            // Service might not be installed
            if e.to_string().contains("not exist") || e.to_string().contains("1060") {
                println!("Service '{}' is not installed.", SERVICE_NAME);
                Ok(())
            } else {
                Err(e.to_string())
            }
        }
    }
}

#[cfg(all(windows, feature = "windows-service"))]
fn get_service_executable_path() -> Result<PathBuf, String> {
    // Look for est-autoenroll-service.exe in the same directory as this binary
    let current_exe =
        env::current_exe().map_err(|e| format!("Failed to get current executable path: {}", e))?;

    let exe_dir = current_exe
        .parent()
        .ok_or("Failed to get executable directory")?;

    let service_exe = exe_dir.join("est-autoenroll-service.exe");

    if service_exe.exists() {
        Ok(service_exe)
    } else {
        // Fallback to current directory
        let cwd_service = PathBuf::from("est-autoenroll-service.exe");
        if cwd_service.exists() {
            Ok(cwd_service.canonicalize().map_err(|e| e.to_string())?)
        } else {
            Err(format!(
                "Service executable not found. Expected at: {}",
                service_exe.display()
            ))
        }
    }
}

#[cfg(all(windows, feature = "windows-service"))]
fn parse_account(s: &str) -> Result<ServiceAccount, String> {
    match s.to_lowercase().as_str() {
        "system" | "localsystem" => Ok(ServiceAccount::LocalSystem),
        "localservice" | "local" => Ok(ServiceAccount::LocalService),
        "networkservice" | "network" => Ok(ServiceAccount::NetworkService),
        _ => {
            // Assume it's a custom account
            Ok(ServiceAccount::Custom {
                account: s.to_string(),
                password: None,
            })
        }
    }
}

#[cfg(all(windows, feature = "windows-service"))]
fn parse_start_type(s: &str) -> Result<StartType, String> {
    match s.to_lowercase().as_str() {
        "auto" | "automatic" => Ok(StartType::Automatic),
        "delayed" | "auto-delayed" | "automaticdelayed" => Ok(StartType::AutomaticDelayed),
        "manual" | "demand" => Ok(StartType::Manual),
        "disabled" => Ok(StartType::Disabled),
        _ => Err(format!(
            "Invalid start type: {}. Use: auto, delayed, manual, disabled",
            s
        )),
    }
}
