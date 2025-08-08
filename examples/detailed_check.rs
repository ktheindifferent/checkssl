use checkssl::{CheckSSL, CheckSSLConfig};
use std::time::Duration;

fn main() {
    println!("=== Basic SSL Check ===");
    match CheckSSL::from_domain("rust-lang.org".to_string()) {
        Ok(cert) => {
            println!("Server Certificate:");
            println!("  Common Name: {}", cert.server.common_name);
            println!("  Issuer CN: {}", cert.server.issuer_cn);
            println!("  Full Issuer: {}", cert.server.issuer);
            println!("  Organization: {}", cert.server.organization);
            println!("  Organizational Unit: {}", cert.server.organizational_unit);
            println!("  Serial Number: {}", cert.server.serial_number);
            println!("  Version: {}", cert.server.version);
            println!("  Valid: {}", cert.server.is_valid);
            println!("  Days to Expiration: {}", cert.server.days_to_expiration);
            println!("  Signature Algorithm: {}", cert.server.signature_algorithm);
            println!("  Public Key Algorithm: {}", cert.server.public_key_algorithm);
            println!("  Key Usage: {:?}", cert.server.key_usage);
            println!("  Extended Key Usage: {:?}", cert.server.extended_key_usage);
            println!("  SHA256 Fingerprint: {}", cert.server.fingerprint_sha256);
            println!("  SANs: {:?}", cert.server.sans);
            println!();
            println!("Intermediate Certificate:");
            println!("  Common Name: {}", cert.intermediate.common_name);
            println!("  Is CA: {}", cert.intermediate.is_ca);
            println!("  Path Length Constraint: {:?}", cert.intermediate.path_len_constraint);
            println!("  Key Usage: {:?}", cert.intermediate.key_usage);
            println!();
            println!("Chain Info:");
            println!("  Chain Length: {}", cert.chain_length);
            println!("  Protocol Version: {}", cert.protocol_version);
        }
        Err(e) => {
            eprintln!("Error checking SSL: {}", e);
        }
    }
    
    println!("\n=== Custom Configuration Check ===");
    let config = CheckSSLConfig {
        timeout: Duration::from_secs(10),
        port: 443,
    };
    
    match CheckSSL::from_domain_with_config("github.com".to_string(), config) {
        Ok(cert) => {
            println!("Certificate for github.com:");
            println!("  Common Name: {}", cert.server.common_name);
            println!("  Valid: {}", cert.server.is_valid);
            println!("  Days to Expiration: {}", cert.server.days_to_expiration);
            println!("  SHA256 Fingerprint: {}", cert.server.fingerprint_sha256);
        }
        Err(e) => {
            eprintln!("Error checking SSL: {}", e);
        }
    }
}