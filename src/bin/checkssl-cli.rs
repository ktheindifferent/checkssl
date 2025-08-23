use checkssl::{CheckSSL, CheckSSLConfig, CertificateFormat, check_certificate_from_file, analyze_certificate, generate_security_report, batch_check_domains, BatchConfig, BatchStatistics};
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
    let mut analyze_security = false;
    let mut file_path = String::new();
    let mut batch_file = String::new();
    
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
            "-s" | "--security" => {
                analyze_security = true;
            }
            "-f" | "--file" => {
                if i + 1 < args.len() {
                    file_path = args[i + 1].clone();
                    i += 1;
                } else {
                    eprintln!("Error: --file requires a path");
                    process::exit(1);
                }
            }
            "-b" | "--batch" => {
                if i + 1 < args.len() {
                    batch_file = args[i + 1].clone();
                    i += 1;
                } else {
                    eprintln!("Error: --batch requires a file path");
                    process::exit(1);
                }
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
    
    // Handle batch processing
    if !batch_file.is_empty() {
        process_batch_file(&batch_file, port, timeout);
        return;
    }
    
    // Handle file certificate checking
    if !file_path.is_empty() {
        process_certificate_file(&file_path, json_output, verbose, analyze_security);
        return;
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
            if analyze_security {
                let analysis = analyze_certificate(&cert);
                let report = generate_security_report(&analysis);
                println!("\n{}", report);
            }
            
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
    println!("  -s, --security        Analyze certificate security");
    println!("  -f, --file <PATH>     Check certificate from PEM/DER file");
    println!("  -b, --batch <FILE>    Check multiple domains from file");
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
        
        let not_before = chrono::DateTime::from_timestamp(cert.server.not_before, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let not_after = chrono::DateTime::from_timestamp(cert.server.not_after, 0)
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

fn process_certificate_file(path: &str, json_output: bool, verbose: bool, analyze_security: bool) {
    use std::path::Path;
    
    match check_certificate_from_file(Path::new(path), CertificateFormat::Auto) {
        Ok(cert) => {
            if analyze_security {
                let analysis = analyze_certificate(&cert);
                let report = generate_security_report(&analysis);
                println!("{}", report);
            }
            
            if json_output {
                print_json_output(&cert);
            } else {
                print_certificate_info(&cert, verbose);
            }
            
            if !cert.server.is_valid {
                process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("Error checking certificate file: {}", e);
            process::exit(1);
        }
    }
}

fn process_batch_file(batch_file: &str, port: u16, timeout: u64) {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;
    
    let file = match File::open(Path::new(batch_file)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening batch file: {}", e);
            process::exit(1);
        }
    };
    
    let reader = BufReader::new(file);
    let mut domains = Vec::new();
    
    for line in reader.lines() {
        if let Ok(domain) = line {
            let domain = domain.trim();
            if !domain.is_empty() && !domain.starts_with('#') {
                domains.push(domain.to_string());
            }
        }
    }
    
    if domains.is_empty() {
        eprintln!("No domains found in batch file");
        process::exit(1);
    }
    
    println!("Checking {} domains...", domains.len());
    
    let config = BatchConfig {
        max_concurrent: 5,
        check_config: CheckSSLConfig {
            timeout: Duration::from_secs(timeout),
            port,
        },
        continue_on_error: true,
        delay_between_checks: None,
    };
    
    let results = batch_check_domains(domains, config);
    let stats = BatchStatistics::from_results(&results, 30);
    
    // Print results
    println!("\nResults:");
    println!("{}", "=".repeat(60));
    
    for result in &results {
        match &result.result {
            Ok(cert) => {
                println!("✓ {} - Valid, expires in {} days", 
                    result.domain, 
                    cert.server.days_to_expiration);
            }
            Err(e) => {
                println!("✗ {} - Error: {}", result.domain, e);
            }
        }
    }
    
    println!("\n{}", "=".repeat(60));
    stats.print_summary();
    
    if stats.failed > 0 {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    
    #[test]
    fn test_timestamp_conversion_valid() {
        // Test with a known timestamp (2024-01-01 00:00:00 UTC)
        let timestamp: i64 = 1704067200;
        let result = chrono::DateTime::from_timestamp(timestamp, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
        
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "2024-01-01 00:00:00 UTC");
    }
    
    #[test]
    fn test_timestamp_conversion_with_nanoseconds() {
        // Test with nanoseconds
        let timestamp: i64 = 1704067200;
        let nanos: u32 = 500_000_000; // 0.5 seconds
        let result = chrono::DateTime::from_timestamp(timestamp, nanos)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S%.f UTC").to_string());
        
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("2024-01-01 00:00:00.5"));
    }
    
    #[test]
    fn test_timestamp_conversion_invalid() {
        // Test with an invalid timestamp (too large)
        let invalid_timestamp: i64 = i64::MAX;
        let result = chrono::DateTime::from_timestamp(invalid_timestamp, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        
        assert_eq!(result, "Unknown");
    }
    
    #[test]
    fn test_timestamp_conversion_negative() {
        // Test with a negative timestamp (before Unix epoch)
        let negative_timestamp: i64 = -86400; // 1 day before epoch
        let result = chrono::DateTime::from_timestamp(negative_timestamp, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
        
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "1969-12-31 00:00:00 UTC");
    }
}