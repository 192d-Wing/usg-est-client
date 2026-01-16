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

//! EST Enrollment Command-Line Tool
//!
//! A comprehensive CLI for certificate enrollment, renewal, and management
//! using the EST (Enrollment over Secure Transport) protocol (RFC 7030).
//!
//! # Usage
//!
//! ```text
//! est-enroll [OPTIONS] <COMMAND>
//!
//! Commands:
//!   enroll    Perform certificate enrollment
//!   renew     Force certificate renewal
//!   status    Show current certificate status
//!   check     Verify EST server connectivity
//!   export    Export certificate to file
//!   config    Configuration management
//!   diagnose  Run connectivity diagnostics
//!   ca-info   Display CA certificate information
//!   cert-info Display enrolled certificate details
//!   test-csr  Generate and display CSR without enrolling
//!
//! Options:
//!   -c, --config <PATH>   Path to configuration file
//!   -s, --server <URL>    Override EST server URL
//!   -v, --verbose         Enable verbose output
//!   -q, --quiet           Suppress non-error output
//!   --dry-run             Show what would happen without making changes
//!   -h, --help            Print help
//!   -V, --version         Print version
//! ```
//!
//! # Examples
//!
//! ```bash
//! # Enroll with default configuration
//! est-enroll enroll
//!
//! # Check server connectivity
//! est-enroll check --server https://est.example.com
//!
//! # View certificate status
//! est-enroll status
//!
//! # Validate configuration file
//! est-enroll config validate --config /path/to/config.toml
//!
//! # Run full diagnostics
//! est-enroll diagnose --server https://est.example.com
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

/// EST Enrollment Command-Line Tool
#[derive(Parser)]
#[command(name = "est-enroll")]
#[command(author = "U.S. Federal Government")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Certificate enrollment using EST (RFC 7030)", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Override EST server URL
    #[arg(short, long, global = true, value_name = "URL")]
    server: Option<String>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress non-error output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Show what would happen without making changes
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform certificate enrollment
    Enroll {
        /// Force enrollment even if certificate exists
        #[arg(short, long)]
        force: bool,

        /// Subject Common Name (overrides config)
        #[arg(long, value_name = "CN")]
        common_name: Option<String>,

        /// Subject Alternative Names (DNS)
        #[arg(long = "san-dns", value_name = "DNS")]
        san_dns: Vec<String>,

        /// Subject Alternative Names (IP)
        #[arg(long = "san-ip", value_name = "IP")]
        san_ip: Vec<String>,
    },

    /// Force certificate renewal
    Renew {
        /// Force renewal even if not due
        #[arg(short, long)]
        force: bool,

        /// Generate new key pair (vs. reusing existing)
        #[arg(long)]
        new_key: bool,
    },

    /// Show current certificate status
    Status {
        /// Show detailed certificate information
        #[arg(short, long)]
        detailed: bool,

        /// Output format (text, json)
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },

    /// Verify EST server connectivity
    Check {
        /// Test authentication
        #[arg(long)]
        test_auth: bool,

        /// Timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Skip TLS certificate verification (insecure, for testing only)
        #[arg(long)]
        insecure: bool,
    },

    /// Export certificate to file
    Export {
        /// Output file path
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,

        /// Export format (pem, der, pfx)
        #[arg(long, default_value = "pem")]
        format: ExportFormat,

        /// Include private key (requires password for PFX)
        #[arg(long)]
        include_key: bool,

        /// Password for PFX export
        #[arg(long)]
        password: Option<String>,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Run connectivity diagnostics
    Diagnose {
        /// Include detailed TLS information
        #[arg(long)]
        tls_details: bool,

        /// Skip authentication test
        #[arg(long)]
        skip_auth: bool,

        /// Skip TLS certificate verification (insecure, for testing only)
        #[arg(long)]
        insecure: bool,
    },

    /// Display CA certificate information
    CaInfo {
        /// Show all certificates in chain
        #[arg(long)]
        full_chain: bool,

        /// Output format (text, json, pem)
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },

    /// Display enrolled certificate details
    CertInfo {
        /// Certificate thumbprint (default: current enrolled cert)
        #[arg(long)]
        thumbprint: Option<String>,

        /// Output format (text, json)
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },

    /// Generate and display CSR without enrolling
    TestCsr {
        /// Output format (text, pem, der)
        #[arg(long, default_value = "pem")]
        format: CsrFormat,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Validate configuration file
    Validate,

    /// Display effective configuration
    Show {
        /// Show expanded variables
        #[arg(long)]
        expanded: bool,

        /// Output format (text, json, toml)
        #[arg(long, default_value = "toml")]
        format: ConfigFormat,
    },

    /// Generate default configuration file
    Init {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Overwrite existing file
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum OutputFormat {
    #[default]
    Text,
    Json,
    Pem,
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum ExportFormat {
    #[default]
    Pem,
    Der,
    Pfx,
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum CsrFormat {
    Text,
    #[default]
    Pem,
    Der,
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum ConfigFormat {
    Text,
    Json,
    #[default]
    Toml,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.quiet {
        tracing::Level::ERROR
    } else if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Create runtime for async operations
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create async runtime: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Run the command
    let result = runtime.block_on(run_command(cli));

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match &cli.command {
        Commands::Enroll {
            force,
            common_name,
            san_dns,
            san_ip,
        } => {
            cmd_enroll(
                &cli,
                *force,
                common_name.clone(),
                san_dns.clone(),
                san_ip.clone(),
            )
            .await
        }
        Commands::Renew { force, new_key } => cmd_renew(&cli, *force, *new_key).await,
        Commands::Status { detailed, format } => cmd_status(&cli, *detailed, *format).await,
        Commands::Check {
            test_auth,
            timeout,
            insecure,
        } => cmd_check(&cli, *test_auth, *timeout, *insecure).await,
        Commands::Export {
            output,
            format,
            include_key,
            password,
        } => {
            cmd_export(
                &cli,
                output.clone(),
                *format,
                *include_key,
                password.clone(),
            )
            .await
        }
        Commands::Config { action } => cmd_config(&cli, action).await,
        Commands::Diagnose {
            tls_details,
            skip_auth,
            insecure,
        } => cmd_diagnose(&cli, *tls_details, *skip_auth, *insecure).await,
        Commands::CaInfo { full_chain, format } => cmd_ca_info(&cli, *full_chain, *format).await,
        Commands::CertInfo { thumbprint, format } => {
            cmd_cert_info(&cli, thumbprint.clone(), *format).await
        }
        Commands::TestCsr { format, output } => cmd_test_csr(&cli, *format, output.clone()).await,
    }
}

// ============================================================================
// Command Implementations
// ============================================================================

async fn cmd_enroll(
    cli: &Cli,
    force: bool,
    common_name: Option<String>,
    san_dns: Vec<String>,
    san_ip: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use usg_est_client::auto_enroll::ConfigLoader;

    if cli.dry_run {
        println!("DRY RUN: Would perform certificate enrollment");
        println!("  Force: {}", force);
        if let Some(ref cn) = common_name {
            println!("  Common Name: {}", cn);
        }
        if !san_dns.is_empty() {
            println!("  DNS SANs: {:?}", san_dns);
        }
        if !san_ip.is_empty() {
            println!("  IP SANs: {:?}", san_ip);
        }
        return Ok(());
    }

    // Load configuration
    let mut loader = ConfigLoader::new();
    if let Some(ref path) = cli.config {
        loader = loader.with_path(path);
    }

    let mut config = loader.load()?;

    // Apply overrides
    if let Some(ref server) = cli.server {
        config.server.url = server.clone();
    }
    if let Some(ref cn) = common_name {
        config.certificate.common_name = cn.clone();
    }
    if !san_dns.is_empty() || !san_ip.is_empty() {
        use std::net::IpAddr;

        let ip_addrs: Vec<IpAddr> = san_ip.iter().filter_map(|s| s.parse().ok()).collect();

        if let Some(ref mut san) = config.certificate.san {
            if !san_dns.is_empty() {
                san.dns = san_dns.clone();
            }
            if !ip_addrs.is_empty() {
                san.ip = ip_addrs;
            }
        } else {
            config.certificate.san = Some(usg_est_client::auto_enroll::SanConfig {
                dns: san_dns,
                ip: ip_addrs,
                email: vec![],
                uri: vec![],
                include_ip: false,
            });
        }
    }

    // Validate configuration
    config.validate()?;

    println!("Starting certificate enrollment...");
    println!("  Server: {}", config.server.url);
    println!("  Common Name: {}", config.certificate.common_name);

    // Build EST client configuration
    let est_config = config.to_est_client_config()?;

    // Create EST client
    let client = usg_est_client::EstClient::new(est_config).await?;

    // Fetch CA certificates first
    println!("Fetching CA certificates...");
    let ca_certs = client.get_ca_certs().await?;
    println!("  Retrieved {} CA certificate(s)", ca_certs.len());

    // Build CSR
    #[cfg(feature = "csr-gen")]
    {
        use usg_est_client::csr::CsrBuilder;

        let mut builder = CsrBuilder::new().common_name(&config.certificate.common_name);

        if let Some(ref org) = config.certificate.organization {
            builder = builder.organization(org);
        }
        if let Some(ref ou) = config.certificate.organizational_unit {
            builder = builder.organizational_unit(ou);
        }

        // Add SANs
        if let Some(ref san) = config.certificate.san {
            for dns in &san.dns {
                builder = builder.san_dns(dns);
            }
        }

        println!("Generating CSR...");
        let (csr_der, _key_pair) = builder.build()?;

        // Enroll
        println!("Submitting enrollment request...");
        let response = client.simple_enroll(&csr_der).await?;

        match response {
            usg_est_client::EnrollmentResponse::Issued { certificate } => {
                use der::Encode;
                let cert_der = certificate.to_der()?;
                let thumbprint = compute_thumbprint(&cert_der);
                println!("Certificate issued successfully!");
                println!("  Thumbprint: {}", thumbprint);

                // Extract subject CN for display
                if let Some(cn) = get_certificate_cn(&certificate) {
                    println!("  Subject: {}", cn);
                }
            }
            usg_est_client::EnrollmentResponse::Pending { retry_after } => {
                println!("Enrollment pending - approval required");
                println!("  Retry after: {} seconds", retry_after);
                println!();
                println!("Run 'est-enroll status' to check enrollment status.");
            }
        }
    }

    #[cfg(not(feature = "csr-gen"))]
    {
        return Err("CSR generation feature not enabled".into());
    }

    Ok(())
}

async fn cmd_renew(
    cli: &Cli,
    force: bool,
    new_key: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use usg_est_client::auto_enroll::ConfigLoader;

    if cli.dry_run {
        println!("DRY RUN: Would perform certificate renewal");
        println!("  Force: {}", force);
        println!("  New key: {}", new_key);
        return Ok(());
    }

    // Load configuration
    let mut loader = ConfigLoader::new();
    if let Some(ref path) = cli.config {
        loader = loader.with_path(path);
    }

    let mut config = loader.load()?;

    if let Some(ref server) = cli.server {
        config.server.url = server.clone();
    }

    config.validate()?;

    println!("Starting certificate renewal...");
    println!("  Server: {}", config.server.url);

    // Build EST client configuration
    let est_config = config.to_est_client_config()?;
    let client = usg_est_client::EstClient::new(est_config).await?;

    // For re-enrollment, we need the existing certificate for TLS client auth
    // This is a simplified version - full implementation would load from store

    #[cfg(feature = "csr-gen")]
    {
        use usg_est_client::csr::CsrBuilder;

        let builder = CsrBuilder::new().common_name(&config.certificate.common_name);

        println!("Generating renewal CSR...");
        let (csr_der, _key_pair) = builder.build()?;

        println!("Submitting re-enrollment request...");
        let response = client.simple_reenroll(&csr_der).await?;

        match response {
            usg_est_client::EnrollmentResponse::Issued { certificate } => {
                use der::Encode;
                let cert_der = certificate.to_der()?;
                let thumbprint = compute_thumbprint(&cert_der);
                println!("Certificate renewed successfully!");
                println!("  Thumbprint: {}", thumbprint);
            }
            usg_est_client::EnrollmentResponse::Pending { retry_after } => {
                println!("Renewal pending - approval required");
                println!("  Retry after: {} seconds", retry_after);
            }
        }
    }

    #[cfg(not(feature = "csr-gen"))]
    {
        return Err("CSR generation feature not enabled".into());
    }

    Ok(())
}

async fn cmd_status(
    cli: &Cli,
    detailed: bool,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    use usg_est_client::auto_enroll::ConfigLoader;

    // Load configuration to find certificate
    let mut loader = ConfigLoader::new();
    if let Some(ref path) = cli.config {
        loader = loader.with_path(path);
    }

    match loader.load() {
        Ok(config) => {
            println!("Configuration: OK");
            println!("  Server: {}", config.server.url);
            println!("  Common Name: {}", config.certificate.common_name);

            // Check certificate status
            // This is a simplified version - full implementation would check cert store
            println!();
            println!("Certificate Status:");
            println!("  Status: Not enrolled (certificate store access requires Windows)");

            if detailed {
                println!();
                println!("Renewal Configuration:");
                println!("  Enabled: {}", config.renewal.enabled);
                println!("  Threshold: {} days", config.renewal.threshold_days);
                println!(
                    "  Check Interval: {} hours",
                    config.renewal.check_interval_hours
                );
            }
        }
        Err(e) => {
            println!("Configuration: Error");
            println!("  {}", e);
            println!();
            println!("Certificate Status: Unknown (no configuration)");
        }
    }

    let _ = format; // Would use for JSON output
    Ok(())
}

async fn cmd_check(
    cli: &Cli,
    test_auth: bool,
    timeout: u64,
    insecure: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use usg_est_client::auto_enroll::ConfigLoader;

    println!("Checking EST server connectivity...");
    println!();

    // Get server URL
    let server_url = if let Some(ref server) = cli.server {
        server.clone()
    } else {
        let mut loader = ConfigLoader::new();
        if let Some(ref path) = cli.config {
            loader = loader.with_path(path);
        }
        match loader.load() {
            Ok(config) => config.server.url,
            Err(_) => {
                return Err(
                    "No server URL provided. Use --server or configure in config file.".into(),
                );
            }
        }
    };

    println!("Server: {}", server_url);
    println!("Timeout: {} seconds", timeout);

    // Validate insecure flag usage
    if insecure {
        validate_insecure_usage(&server_url).await?;
        println!("WARNING: TLS certificate verification disabled (insecure mode)");
    }
    println!();

    // Parse URL
    let url = url::Url::parse(&server_url)?;

    // DNS resolution
    print!("DNS Resolution... ");
    let host = url.host_str().ok_or("Invalid URL: no host")?;
    match tokio::net::lookup_host(format!("{}:{}", host, url.port().unwrap_or(443))).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            println!("OK ({} address(es))", addrs.len());
            for addr in &addrs {
                println!("  {}", addr);
            }
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
            return Err("DNS resolution failed".into());
        }
    }

    // TCP connectivity
    print!("TCP Connection... ");
    let addr = format!("{}:{}", host, url.port().unwrap_or(443));
    match tokio::time::timeout(
        std::time::Duration::from_secs(timeout),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => println!("OK"),
        Ok(Err(e)) => {
            println!("FAILED");
            println!("  Error: {}", e);
            return Err("TCP connection failed".into());
        }
        Err(_) => {
            println!("TIMEOUT");
            return Err("TCP connection timed out".into());
        }
    }

    // EST server check
    print!("EST Server... ");

    // Build minimal config for testing
    let mut builder = usg_est_client::EstClientConfig::builder().server_url(&server_url)?;

    if insecure {
        builder = builder.trust_any_insecure();
    }

    let est_config = builder.build()?;

    let client = usg_est_client::EstClient::new(est_config).await?;

    match client.get_ca_certs().await {
        Ok(certs) => {
            println!("OK");
            println!("  CA certificates: {}", certs.len());
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    if test_auth {
        println!();
        println!("Authentication test not yet implemented.");
    }

    println!();
    println!("Check complete.");
    Ok(())
}

async fn cmd_export(
    cli: &Cli,
    output: PathBuf,
    format: ExportFormat,
    include_key: bool,
    password: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if cli.dry_run {
        println!("DRY RUN: Would export certificate");
        println!("  Output: {}", output.display());
        println!("  Format: {:?}", format);
        println!("  Include key: {}", include_key);
        return Ok(());
    }

    println!("Certificate export requires Windows certificate store access.");
    println!("This feature is not yet fully implemented on this platform.");

    let _ = (output, format, include_key, password);
    Ok(())
}

async fn cmd_config(cli: &Cli, action: &ConfigAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ConfigAction::Validate => {
            use usg_est_client::auto_enroll::ConfigLoader;

            let mut loader = ConfigLoader::new();
            if let Some(ref path) = cli.config {
                loader = loader.with_path(path);
            }

            println!("Validating configuration...");

            match loader.load() {
                Ok(config) => match config.validate() {
                    Ok(()) => {
                        println!("Configuration is valid.");
                        println!();
                        println!("Summary:");
                        println!("  Server: {}", config.server.url);
                        println!("  Common Name: {}", config.certificate.common_name);
                        println!("  Trust Mode: {:?}", config.trust.mode);
                        println!("  Auth Method: {:?}", config.authentication.method);
                        println!("  Renewal Enabled: {}", config.renewal.enabled);
                    }
                    Err(e) => {
                        println!("Configuration validation failed:");
                        println!("  {}", e);
                        return Err("Validation failed".into());
                    }
                },
                Err(e) => {
                    println!("Failed to load configuration:");
                    println!("  {}", e);
                    return Err("Failed to load configuration".into());
                }
            }
        }
        ConfigAction::Show { expanded, format } => {
            use usg_est_client::auto_enroll::ConfigLoader;

            let mut loader = ConfigLoader::new();
            if let Some(ref path) = cli.config {
                loader = loader.with_path(path);
            }

            match loader.load() {
                Ok(mut config) => {
                    if *expanded {
                        config.expand_variables()?;
                    }

                    match *format {
                        ConfigFormat::Toml => {
                            // Re-serialize to TOML
                            let toml_str = toml::to_string_pretty(&config)?;
                            println!("{}", toml_str);
                        }
                        ConfigFormat::Json => {
                            let json_str = serde_json::to_string_pretty(&config)?;
                            println!("{}", json_str);
                        }
                        ConfigFormat::Text => {
                            println!("Server:");
                            println!("  URL: {}", config.server.url);
                            println!("  CA Label: {:?}", config.server.ca_label);
                            println!();
                            println!("Trust:");
                            println!("  Mode: {:?}", config.trust.mode);
                            println!("  CA Bundle: {:?}", config.trust.ca_bundle_path);
                            println!();
                            println!("Authentication:");
                            println!("  Method: {:?}", config.authentication.method);
                            println!();
                            println!("Certificate:");
                            println!("  Common Name: {}", config.certificate.common_name);
                            println!("  Organization: {:?}", config.certificate.organization);
                            if let Some(ref san) = config.certificate.san {
                                println!("  DNS SANs: {:?}", san.dns);
                            }
                            println!();
                            println!("Renewal:");
                            println!("  Enabled: {}", config.renewal.enabled);
                            println!("  Threshold: {} days", config.renewal.threshold_days);
                        }
                    }
                }
                Err(e) => {
                    println!("Failed to load configuration: {}", e);
                    return Err("Failed to load configuration".into());
                }
            }
        }
        ConfigAction::Init { output, force } => {
            use usg_est_client::auto_enroll::write_default_config;

            let output_path = output
                .clone()
                .unwrap_or_else(|| PathBuf::from("est-config.toml"));

            if output_path.exists() && !*force {
                return Err(format!(
                    "File already exists: {}. Use --force to overwrite.",
                    output_path.display()
                )
                .into());
            }

            if cli.dry_run {
                println!("DRY RUN: Would create configuration file");
                println!("  Path: {}", output_path.display());
                return Ok(());
            }

            write_default_config(&output_path)?;
            println!(
                "Created default configuration file: {}",
                output_path.display()
            );
            println!();
            println!("Edit the file to customize settings, then run:");
            println!(
                "  est-enroll config validate --config {}",
                output_path.display()
            );
        }
    }
    Ok(())
}

async fn cmd_diagnose(
    cli: &Cli,
    tls_details: bool,
    skip_auth: bool,
    insecure: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use usg_est_client::auto_enroll::ConfigLoader;

    println!("EST Enrollment Diagnostics");
    println!("==========================");
    println!();

    // Load configuration
    let mut loader = ConfigLoader::new();
    if let Some(ref path) = cli.config {
        loader = loader.with_path(path);
    }

    let config = match loader.load() {
        Ok(c) => {
            println!("[OK] Configuration loaded");
            Some(c)
        }
        Err(e) => {
            println!("[WARN] Configuration: {}", e);
            if cli.server.is_none() {
                return Err(
                    "No configuration available. Use --server to specify EST server.".into(),
                );
            }
            println!("Using --server override...");
            None
        }
    };

    let server_url = if let Some(ref server) = cli.server {
        server.clone()
    } else if let Some(ref cfg) = config {
        cfg.server.url.clone()
    } else {
        return Err("No server URL available".into());
    };
    println!();
    println!("Target Server: {}", server_url);

    // Validate insecure flag usage
    if insecure {
        if let Err(e) = validate_insecure_usage(&server_url).await {
            println!("[ERROR] {}", e);
            return Err(e);
        }
        println!("WARNING: TLS certificate verification disabled (insecure mode)");
    }
    println!();

    // Parse URL
    let url = url::Url::parse(&server_url)?;
    let host = url.host_str().ok_or("Invalid URL")?;
    let port = url.port().unwrap_or(443);

    // 1. DNS Resolution
    print!("1. DNS Resolution... ");
    match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            println!("[OK] {} address(es) found", addrs.len());
            for addr in &addrs {
                println!("   - {}", addr);
            }
        }
        Err(e) => {
            println!("[FAIL] {}", e);
        }
    }

    // 2. TCP Connectivity
    print!("2. TCP Connectivity (port {})... ", port);
    match tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await {
        Ok(_) => println!("[OK]"),
        Err(e) => println!("[FAIL] {}", e),
    }

    // 3. TLS Handshake
    print!("3. TLS Handshake... ");
    let mut builder = usg_est_client::EstClientConfig::builder().server_url(server_url)?;

    if insecure {
        builder = builder.trust_any_insecure();
    }

    let est_config = builder.build()?;

    match usg_est_client::EstClient::new(est_config).await {
        Ok(client) => {
            println!("[OK]");

            if tls_details {
                println!("   TLS Version: 1.2 or higher (enforced)");
                println!("   Cipher Suite: (depends on server)");
            }

            // 4. EST Server Capabilities
            print!("4. EST Server Capabilities... ");
            match client.get_ca_certs().await {
                Ok(certs) => {
                    println!("[OK]");
                    println!("   - /cacerts: {} certificate(s)", certs.len());
                }
                Err(e) => {
                    println!("[FAIL] {}", e);
                }
            }

            // 5. CSR Attributes
            print!("5. CSR Attributes (/csrattrs)... ");
            match client.get_csr_attributes().await {
                Ok(attrs) => {
                    println!("[OK]");
                    println!("   - {} attribute(s)", attrs.oids().len());
                }
                Err(e) => {
                    if e.to_string().contains("501") || e.to_string().contains("Not Implemented") {
                        println!("[OK] Not implemented by server");
                    } else {
                        println!("[WARN] {}", e);
                    }
                }
            }

            // 6. Authentication test
            if !skip_auth {
                println!("6. Authentication Test... [SKIPPED] (requires credentials)");
            }
        }
        Err(e) => {
            println!("[FAIL] {}", e);
        }
    }

    println!();
    println!("Diagnostics complete.");
    Ok(())
}

async fn cmd_ca_info(
    cli: &Cli,
    full_chain: bool,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    use usg_est_client::auto_enroll::ConfigLoader;

    // Get server URL
    let server_url = if let Some(ref server) = cli.server {
        server.clone()
    } else {
        let mut loader = ConfigLoader::new();
        if let Some(ref path) = cli.config {
            loader = loader.with_path(path);
        }
        loader.load()?.server.url
    };

    println!("Fetching CA certificates from {}...", server_url);
    println!();

    let est_config = usg_est_client::EstClientConfig::builder()
        .server_url(&server_url)?
        .build()?;

    let client = usg_est_client::EstClient::new(est_config).await?;
    let certs = client.get_ca_certs().await?;

    let count = if full_chain {
        certs.len()
    } else {
        1.min(certs.len())
    };

    match format {
        OutputFormat::Text => {
            println!("CA Certificates: {} total", certs.len());
            println!();
            for (i, cert) in certs.iter().take(count).enumerate() {
                println!("Certificate {}:", i + 1);
                if let Some(cn) = get_certificate_cn(cert) {
                    println!("  Subject: {}", cn);
                }
                use der::Encode;
                if let Ok(der) = cert.to_der() {
                    println!("  Thumbprint: {}", compute_thumbprint(&der));
                }
                println!();
            }
        }
        OutputFormat::Pem => {
            use base64::prelude::*;
            use der::Encode;
            for cert in certs.iter().take(count) {
                if let Ok(der) = cert.to_der() {
                    println!("-----BEGIN CERTIFICATE-----");
                    let b64 = BASE64_STANDARD.encode(&der);
                    for chunk in b64.as_bytes().chunks(64) {
                        println!("{}", std::str::from_utf8(chunk).unwrap_or(""));
                    }
                    println!("-----END CERTIFICATE-----");
                    println!();
                }
            }
        }
        OutputFormat::Json => {
            use der::Encode;
            let mut entries = Vec::new();
            for cert in certs.iter().take(count) {
                let mut entry = serde_json::Map::new();
                if let Some(cn) = get_certificate_cn(cert) {
                    entry.insert("subject".to_string(), serde_json::Value::String(cn));
                }
                if let Ok(der) = cert.to_der() {
                    entry.insert(
                        "thumbprint".to_string(),
                        serde_json::Value::String(compute_thumbprint(&der)),
                    );
                }
                entries.push(serde_json::Value::Object(entry));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Array(entries))?
            );
        }
    }

    Ok(())
}

async fn cmd_cert_info(
    cli: &Cli,
    thumbprint: Option<String>,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Certificate info requires access to certificate store.");
    println!("This feature is platform-specific.");

    if let Some(ref tp) = thumbprint {
        println!("Looking for certificate with thumbprint: {}", tp);
    } else {
        println!("Looking for currently enrolled certificate...");
    }

    let _ = (cli, format);
    println!();
    println!("Not yet implemented on this platform.");
    Ok(())
}

async fn cmd_test_csr(
    cli: &Cli,
    format: CsrFormat,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use usg_est_client::auto_enroll::ConfigLoader;

    // Load configuration
    let mut loader = ConfigLoader::new();
    if let Some(ref path) = cli.config {
        loader = loader.with_path(path);
    }

    let config = loader.load().ok();

    #[cfg(feature = "csr-gen")]
    {
        use base64::prelude::*;
        use usg_est_client::csr::CsrBuilder;

        let common_name = config
            .as_ref()
            .map(|c| c.certificate.common_name.clone())
            .unwrap_or_else(|| "test.example.com".to_string());

        let mut builder = CsrBuilder::new().common_name(&common_name);

        if let Some(ref cfg) = config {
            if let Some(ref org) = cfg.certificate.organization {
                builder = builder.organization(org);
            }
            if let Some(ref ou) = cfg.certificate.organizational_unit {
                builder = builder.organizational_unit(ou);
            }
            if let Some(ref san) = cfg.certificate.san {
                for dns in &san.dns {
                    builder = builder.san_dns(dns);
                }
            }
        }

        println!("Generating test CSR...");
        println!("  Common Name: {}", common_name);
        println!();

        let (csr_der, _key_pair) = builder.build()?;

        let output_str = match format {
            CsrFormat::Pem => {
                let b64 = BASE64_STANDARD.encode(&csr_der);
                let mut pem = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
                for chunk in b64.as_bytes().chunks(64) {
                    pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
                    pem.push('\n');
                }
                pem.push_str("-----END CERTIFICATE REQUEST-----\n");
                pem
            }
            CsrFormat::Der => {
                // For DER, we need to write binary
                if let Some(ref path) = output {
                    std::fs::write(path, &csr_der)?;
                    println!("DER-encoded CSR written to: {}", path.display());
                    return Ok(());
                } else {
                    return Err("DER format requires --output file".into());
                }
            }
            CsrFormat::Text => {
                format!(
                    "CSR Summary:\n  Subject: CN={}\n  Size: {} bytes\n  Format: PKCS#10\n",
                    common_name,
                    csr_der.len()
                )
            }
        };

        if let Some(ref path) = output {
            std::fs::write(path, &output_str)?;
            println!("CSR written to: {}", path.display());
        } else {
            println!("{}", output_str);
        }
    }

    #[cfg(not(feature = "csr-gen"))]
    {
        return Err("CSR generation feature not enabled".into());
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

fn compute_thumbprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(der);
    hash.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn get_certificate_cn(cert: &x509_cert::Certificate) -> Option<String> {
    use const_oid::db::rfc4519::CN;

    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == CN
                && let Ok(s) = std::str::from_utf8(atv.value.value())
            {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Validate that --insecure flag is only used with the official RFC 7030 test server.
///
/// This prevents accidental use of --insecure with production servers.
/// Only allows: https://testrfc7030.com (resolves to 54.70.32.33)
async fn validate_insecure_usage(server_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    const ALLOWED_TEST_SERVER: &str = "testrfc7030.com";
    const ALLOWED_TEST_IP: &str = "54.70.32.33";

    // Parse URL to extract hostname
    let url = url::Url::parse(server_url)?;
    let host = url
        .host_str()
        .ok_or("Invalid URL: no host specified")?
        .to_lowercase();

    // Check if it's the allowed test server hostname
    if host == ALLOWED_TEST_SERVER {
        // Verify it resolves to the expected IP
        match tokio::net::lookup_host(format!("{}:{}", host, url.port().unwrap_or(443))).await {
            Ok(addrs) => {
                let resolved_ips: Vec<String> = addrs.map(|addr| addr.ip().to_string()).collect();

                if resolved_ips.iter().any(|ip| ip == ALLOWED_TEST_IP) {
                    // Valid: hostname matches and resolves to expected IP
                    return Ok(());
                } else {
                    return Err(format!(
                        "Security Error: --insecure flag can only be used with the official RFC 7030 test server.\n\
                         Server '{}' resolves to {:?}, but expected {}.\n\
                         \n\
                         For testing with other servers, use one of these options:\n\
                         1. Configure explicit trust: Add your CA certificate to the trust store\n\
                         2. Use bootstrap mode: See 'cargo run --example bootstrap'\n\
                         3. Contact your administrator for proper CA certificates",
                        host, resolved_ips, ALLOWED_TEST_IP
                    )
                    .into());
                }
            }
            Err(e) => {
                return Err(format!(
                    "Security Error: Failed to verify server identity: {}\n\
                     --insecure flag can only be used with verified test servers.",
                    e
                )
                .into());
            }
        }
    }

    // Check if it's the IP address directly
    if host == ALLOWED_TEST_IP {
        return Ok(());
    }

    // Not an allowed server
    Err(format!(
        "Security Error: --insecure flag is restricted to the official RFC 7030 test server only.\n\
         \n\
         Allowed server: https://{}\n\
         Your server:    {}\n\
         \n\
         The --insecure flag bypasses critical TLS security checks and is restricted\n\
         to prevent accidental use in production environments.\n\
         \n\
         For testing with '{}', use one of these secure alternatives:\n\
         1. Configure explicit trust with your CA certificate:\n\
            [trust]\n\
            mode = \"explicit\"\n\
            ca_bundle_path = \"/path/to/ca-bundle.pem\"\n\
         \n\
         2. Use bootstrap/TOFU mode for initial CA discovery:\n\
            cargo run --example bootstrap -- --server {}\n\
         \n\
         3. Add your CA to the system trust store\n\
         \n\
         For more information, see CONFIGURATION.md",
        ALLOWED_TEST_SERVER, server_url, host, server_url
    )
    .into())
}
