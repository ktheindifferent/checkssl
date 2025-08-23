use checkssl::{load_certificate_chain_from_files, CertificateFormat};
use std::path::Path;

fn main() {
    println!("=== Loading Certificate Chain from Multiple Files ===\n");
    
    // Example 1: Load and combine certificates from separate files
    demo_load_chain();
    
    // Example 2: Build a complete chain for validation
    demo_chain_validation();
    
    // Example 3: Load certificates with different formats
    demo_mixed_formats();
}

fn demo_load_chain() {
    println!("Example 1: Loading certificates from multiple files");
    println!("{}", "-".repeat(50));
    
    // In a real scenario, you would have actual certificate files
    // For demonstration, we'll show the pattern
    let cert_paths = vec![
        Path::new("./certs/server.crt"),
        Path::new("./certs/intermediate.crt"),
        Path::new("./certs/root.crt"),
    ];
    
    println!("Attempting to load certificates from:");
    for path in &cert_paths {
        println!("  - {}", path.display());
    }
    
    match load_certificate_chain_from_files(&cert_paths, CertificateFormat::Auto) {
        Ok(chain) => {
            println!("Successfully loaded {} certificates", chain.len());
            for (i, cert) in chain.iter().enumerate() {
                println!("  Certificate {}: {} bytes", i + 1, cert.len());
            }
        }
        Err(e) => {
            println!("Note: This example requires certificate files to exist");
            println!("Error loading chain: {}", e);
        }
    }
    println!();
}

fn demo_chain_validation() {
    println!("Example 2: Building a chain for validation");
    println!("{}", "-".repeat(50));
    
    // Example of how you might use this for building a validation chain
    let server_cert = Path::new("./certs/example.com.crt");
    let intermediate_cert = Path::new("./certs/intermediate.crt");
    
    let chain_files = vec![server_cert, intermediate_cert];
    
    println!("Building certificate chain for validation...");
    
    match load_certificate_chain_from_files(&chain_files, CertificateFormat::PEM) {
        Ok(chain) => {
            println!("Certificate chain built successfully:");
            println!("  Total certificates in chain: {}", chain.len());
            
            // You could now use this chain for validation
            println!("  Chain ready for validation operations");
        }
        Err(e) => {
            println!("Could not build chain: {}", e);
            println!("Note: Ensure certificate files exist in the specified paths");
        }
    }
    println!();
}

fn demo_mixed_formats() {
    println!("Example 3: Loading certificates with auto-detection");
    println!("{}", "-".repeat(50));
    
    // The function supports PEM, DER, and auto-detection
    let mixed_certs = vec![
        Path::new("./certs/cert1.pem"),
        Path::new("./certs/cert2.der"),
        Path::new("./certs/cert3.crt"),
    ];
    
    println!("Loading certificates with format auto-detection:");
    
    // Using Auto format to automatically detect certificate format
    match load_certificate_chain_from_files(&mixed_certs, CertificateFormat::Auto) {
        Ok(chain) => {
            println!("Successfully loaded {} certificates with auto-detection", chain.len());
            
            // All certificates are converted to DER format internally
            println!("All certificates normalized to DER format");
            
            // You can now use the chain for various operations
            for (i, cert_data) in chain.iter().enumerate() {
                println!("  Certificate {}: {} bytes (DER format)", i + 1, cert_data.len());
            }
        }
        Err(e) => {
            println!("Error during auto-detection: {}", e);
            
            // You might want to try with explicit format
            println!("\nTip: If auto-detection fails, try specifying the format explicitly:");
            println!("  - CertificateFormat::PEM for PEM files");
            println!("  - CertificateFormat::DER for DER files");
        }
    }
    println!();
    
    // Show how to verify individual certificates from the chain
    println!("Tip: You can verify individual certificates after loading:");
    println!("  Use check_certificate_from_file() for detailed certificate info");
}