use checkssl::{CheckSSL, CheckSSLConfig};
use std::env;
use std::process;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    let mut domain = String::new();
    let mut port = 443u16;
    let mut timeout = 5u64;
    let mut json_output = false;
    let mut verbose = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help(&args[0]);
                process::exit(0);
            }
            "-p" | "--port" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("Error: Invalid port number");
                        process::exit(1);
                    });
                    i += 1;
                } else {
                    eprintln!("Error: --port requires a value");
                    process::exit(1);
                }
            }
            "-t" | "--timeout" => {
                if i + 1 < args.len() {
                    timeout = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("Error: Invalid timeout value");
                        process::exit(1);
                    });
                    i += 1;
                } else {
                    eprintln!("Error: --timeout requires a value");
                    process::exit(1);
                }
            }
            "-j" | "--json" => {
                json_output = true;
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            _ => {
                if !args[i].starts_with('-') && domain.is_empty() {
                    domain = args[i].clone();
                } else {
                    eprintln!("Error: Unknown option or multiple domains specified: {}", args[i]);
                    process::exit(1);
                }
            }
        }
        i += 1;
    }
    
    if domain.is_empty() {
        eprintln!("Error: No domain specified");
        print_usage(&args[0]);
        process::exit(1);
    }
    
    let config = CheckSSLConfig {
        timeout: Duration::from_secs(timeout),
        port,
    };
    
    if verbose && !json_output {
        eprintln!("Checking SSL certificate for {}:{} (timeout: {}s)", domain, port, timeout);
    }
    
    match CheckSSL::from_domain_with_config(domain.clone(), config) {
        Ok(cert) => {
            if json_output {
                print_json_output(&cert);
            } else {
                print_certificate_info(&cert, verbose);
            }
            
            if !cert.server.is_valid {
                process::exit(2);
            }
            
            if cert.server.days_to_expiration < 30 {
                if !json_output {
                    eprintln!("\nWarning: Certificate expires in {} days!", cert.server.days_to_expiration);
                }
                process::exit(3);
            }
        }
        Err(e) => {
            if json_output {
                println!("{{\"error\": \"{}\"}}", escape_json(&format!("{}", e)));
            } else {
                eprintln!("Error checking certificate: {}", e);
            }
            process::exit(1);
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} [OPTIONS] <domain>", program);
    eprintln!("Try '{} --help' for more information.", program);
}

fn print_help(program: &str) {
    println!("CheckSSL CLI - SSL/TLS Certificate Checker");
    println!();
    println!("Usage: {} [OPTIONS] <domain>", program);
    println!();
    println!("Arguments:");
    println!("  <domain>              Domain to check (e.g., example.com)");
    println!();
    println!("Options:");
    println!("  -h, --help            Show this help message");
    println!("  -p, --port <PORT>     Port to connect to (default: 443)");
    println!("  -t, --timeout <SECS>  Connection timeout in seconds (default: 5)");
    println!("  -j, --json            Output in JSON format");
    println!("  -v, --verbose         Show detailed certificate information");
    println!();
    println!("Exit Codes:");
    println!("  0  - Certificate is valid");
    println!("  1  - Error occurred");
    println!("  2  - Certificate is invalid");
    println!("  3  - Certificate expires within 30 days");
    println!();
    println!("Examples:");
    println!("  {} example.com", program);
    println!("  {} --port 8443 example.com", program);
    println!("  {} --json example.com", program);
    println!("  {} --verbose example.com", program);
}

fn print_certificate_info(cert: &checkssl::Cert, verbose: bool) {
    println!("Certificate Information for {}", cert.server.common_name);
    println!("{}", "=".repeat(50));
    
    println!("Status: {}", if cert.server.is_valid { "VALID ✓" } else { "INVALID ✗" });
    println!("Common Name: {}", cert.server.common_name);
    println!("Issuer: {}", cert.server.issuer_cn);
    println!("Days to Expiration: {}", cert.server.days_to_expiration);
    println!("Expires: {}", cert.server.time_to_expiration);
    
    if !cert.server.sans.is_empty() {
        println!("Subject Alternative Names:");
        for san in &cert.server.sans {
            println!("  - {}", san);
        }
    }
    
    if verbose {
        println!();
        println!("Detailed Information:");
        println!("{}", "-".repeat(30));
        println!("Serial Number: {}", cert.server.serial_number);
        println!("Version: {}", cert.server.version);
        println!("Signature Algorithm: {}", cert.server.signature_algorithm);
        println!("Public Key Algorithm: {}", cert.server.public_key_algorithm);
        
        if let Some(size) = cert.server.public_key_size {
            println!("Public Key Size: {} bits", size);
        }
        
        println!("SHA256 Fingerprint: {}", cert.server.fingerprint_sha256);
        println!("SHA1 Fingerprint: {}", cert.server.fingerprint_sha1);
        
        let not_before = chrono::NaiveDateTime::from_timestamp_opt(cert.server.not_before, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let not_after = chrono::NaiveDateTime::from_timestamp_opt(cert.server.not_after, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        
        println!("Valid From: {}", not_before);
        println!("Valid Until: {}", not_after);
        
        if !cert.server.key_usage.is_empty() {
            println!("Key Usage: {}", cert.server.key_usage.join(", "));
        }
        
        if !cert.server.extended_key_usage.is_empty() {
            println!("Extended Key Usage: {}", cert.server.extended_key_usage.join(", "));
        }
        
        println!();
        println!("Issuer Information:");
        println!("{}", "-".repeat(30));
        println!("Full Issuer: {}", cert.server.issuer);
        
        if !cert.server.organization.is_empty() {
            println!("Organization: {}", cert.server.organization);
        }
        
        if !cert.server.organizational_unit.is_empty() {
            println!("Organizational Unit: {}", cert.server.organizational_unit);
        }
        
        if !cert.server.country.is_empty() {
            println!("Country: {}", cert.server.country);
        }
        
        if !cert.server.state.is_empty() {
            println!("State: {}", cert.server.state);
        }
        
        if !cert.server.locality.is_empty() {
            println!("Locality: {}", cert.server.locality);
        }
        
        println!();
        println!("Certificate Chain:");
        println!("{}", "-".repeat(30));
        println!("Chain Length: {}", cert.chain_length);
        println!("Protocol Version: {}", cert.protocol_version);
        
        if cert.intermediate.is_ca {
            println!();
            println!("Intermediate CA:");
            println!("  Common Name: {}", cert.intermediate.common_name);
            println!("  Issuer: {}", cert.intermediate.issuer_cn);
            println!("  SHA256 Fingerprint: {}", cert.intermediate.fingerprint_sha256);
            
            if let Some(path_len) = cert.intermediate.path_len_constraint {
                println!("  Path Length Constraint: {}", path_len);
            }
        }
    }
}

fn print_json_output(cert: &checkssl::Cert) {
    let json = serde_json::to_string_pretty(cert).unwrap_or_else(|e| {
        format!("{{\"error\": \"Failed to serialize certificate: {}\"}}", e)
    });
    println!("{}", json);
}

fn escape_json(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            c => c.to_string(),
        })
        .collect()
}