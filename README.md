# checkssl

> A comprehensive SSL/TLS certificate validation library for Rust with advanced security analysis

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%E2%9C%94-orange.svg)](https://www.rust-lang.org)

## Features

### Core Functionality
- ✅ **SSL/TLS Certificate Validation** - Check certificates from live domains
- ✅ **Detailed Certificate Information** - Extract comprehensive certificate details
- ✅ **Certificate Chain Validation** - Validate complete certificate chains
- ✅ **SNI Support** - Automatic Server Name Indication for virtual hosts
- ✅ **Custom Timeout Configuration** - Configurable connection timeouts

### Enhanced Features (New)
- 🔄 **Retry Logic with Exponential Backoff** - Automatic retry for transient failures
- 📄 **PEM/DER File Support** - Check certificates from local files
- 📦 **Batch Domain Checking** - Check multiple domains concurrently
- 💾 **Certificate Caching** - In-memory caching for improved performance
- 🔐 **Security Analysis** - Detect weak cryptographic algorithms
- ⚠️ **Comprehensive Error Handling** - Detailed error types and recovery
- 🔍 **OCSP Support** - Online Certificate Status Protocol checking
- 📊 **Certificate Statistics** - Batch processing with detailed statistics

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
checkssl = "0.2.3"
```

With optional features:
```toml
[dependencies]
checkssl = { version = "0.2.3", features = ["async", "batch", "cache"] }
```

## Quick Start

### Basic Usage

```rust
use checkssl::CheckSSL;

fn main() {
    // Simple certificate check
    match CheckSSL::from_domain("rust-lang.org".to_string()) {
        Ok(cert) => {
            println!("Certificate is valid: {}", cert.server.is_valid);
            println!("Days to expiration: {}", cert.server.days_to_expiration);
            println!("Issuer: {}", cert.server.issuer_cn);
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}
```

### With Custom Configuration

```rust
use checkssl::{CheckSSL, CheckSSLConfig};
use std::time::Duration;

fn main() {
    let config = CheckSSLConfig {
        timeout: Duration::from_secs(10),
        port: 8443,
    };
    
    match CheckSSL::from_domain_with_config("example.com".to_string(), config) {
        Ok(cert) => println!("Certificate valid: {}", cert.server.is_valid),
        Err(e) => eprintln!("Error: {}", e),
    }
}
```

## Advanced Features

### 🔄 Retry Logic with Exponential Backoff

Automatically retry failed connections with configurable backoff:

```rust
use checkssl::{CheckSSL, CheckSSLConfig, RetryConfig, retry_with_backoff};
use std::time::Duration;

fn main() {
    let retry_config = RetryConfig {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(10),
        backoff_multiplier: 2.0,
        jitter: true,
    };
    
    let result = retry_with_backoff(&retry_config, || {
        CheckSSL::from_domain("example.com".to_string())
    });
    
    match result {
        Ok(cert) => println!("Success after retries: {}", cert.server.common_name),
        Err(e) => eprintln!("Failed after retries: {}", e),
    }
}
```

### 📄 PEM/DER File Support

Check certificates from local files:

```rust
use checkssl::{check_certificate_from_file, CertificateFormat};
use std::path::Path;

fn main() {
    // Auto-detect format
    match check_certificate_from_file(Path::new("cert.pem"), CertificateFormat::Auto) {
        Ok(cert) => {
            println!("Certificate CN: {}", cert.server.common_name);
            println!("Valid: {}", cert.server.is_valid);
        }
        Err(e) => eprintln!("Error: {}", e),
    }
    
    // Convert between formats
    use checkssl::{der_to_pem, pem_to_der};
    
    let der_data = vec![0x30, 0x82, /* ... */];
    let pem_string = der_to_pem(&der_data).unwrap();
    println!("PEM:\n{}", pem_string);
}
```

### 📦 Batch Domain Checking

Check multiple domains concurrently:

```rust
use checkssl::{batch_check_domains, BatchConfig, BatchStatistics};
use checkssl::CheckSSLConfig;
use std::time::Duration;

fn main() {
    let domains = vec![
        "google.com".to_string(),
        "github.com".to_string(),
        "rust-lang.org".to_string(),
    ];
    
    let config = BatchConfig {
        max_concurrent: 5,
        check_config: CheckSSLConfig::default(),
        continue_on_error: true,
        delay_between_checks: Some(Duration::from_millis(100)),
    };
    
    let results = batch_check_domains(domains, config);
    let stats = BatchStatistics::from_results(&results, 30);
    
    stats.print_summary();
    
    // Export results
    use checkssl::{export_batch_results_json, export_batch_results_csv};
    
    let json = export_batch_results_json(&results).unwrap();
    let csv = export_batch_results_csv(&results);
}
```

### 💾 Certificate Caching

Improve performance with in-memory caching:

```rust
use checkssl::{CertificateCache, CacheConfig, EvictionStrategy, check_with_cache};
use std::time::Duration;

fn main() {
    let cache_config = CacheConfig {
        max_entries: 1000,
        ttl: Duration::from_secs(3600),
        track_access: true,
        eviction_strategy: EvictionStrategy::LRU,
    };
    
    let cache = CertificateCache::with_config(cache_config);
    
    // Check with caching
    let cert = check_with_cache(&cache, "example.com", 443, || {
        CheckSSL::from_domain("example.com".to_string())
    }).unwrap();
    
    // Get cache statistics
    let stats = cache.statistics();
    println!("Cache hit rate: {:.2}%", stats.hit_rate() * 100.0);
}
```

### 🔐 Security Analysis

Analyze certificates for security issues:

```rust
use checkssl::{CheckSSL, analyze_certificate, generate_security_report};

fn main() {
    let cert = CheckSSL::from_domain("example.com".to_string()).unwrap();
    let analysis = analyze_certificate(&cert);
    
    println!("Security Level: {:?}", analysis.security_level);
    
    for issue in &analysis.issues {
        println!("Issue: {} (Severity: {:?})", issue.description, issue.severity);
        println!("Recommendation: {}", issue.recommendation);
    }
    
    // Generate detailed report
    let report = generate_security_report(&analysis);
    println!("{}", report);
}
```

## CLI Usage

The library includes a powerful command-line interface:

```bash
# Basic check
checkssl example.com

# Check with custom port and timeout
checkssl --port 8443 --timeout 10 example.com

# Analyze security
checkssl --security example.com

# Check certificate from file
checkssl --file /path/to/cert.pem

# Batch check from file
checkssl --batch domains.txt

# JSON output
checkssl --json example.com

# Verbose output
checkssl --verbose example.com
```

### Batch File Format

Create a `domains.txt` file:
```
google.com
github.com
rust-lang.org
# Comments are supported
example.com
```

## Error Handling

The library provides comprehensive error types:

```rust
use checkssl::{CheckSSL, CheckSSLError};

match CheckSSL::from_domain("example.com".to_string()) {
    Ok(cert) => { /* ... */ }
    Err(e) => {
        match e {
            CheckSSLError::NetworkError(msg) => eprintln!("Network error: {}", msg),
            CheckSSLError::TimeoutError(msg) => eprintln!("Timeout: {}", msg),
            CheckSSLError::CertificateExpired { common_name, expired_since } => {
                eprintln!("{} expired {} days ago", common_name, expired_since)
            }
            _ => eprintln!("Other error: {}", e),
        }
    }
}
```

## Security Features

### Weak Algorithm Detection
- MD5 signatures (Critical)
- SHA1 signatures (Weak)
- Small RSA keys (<2048 bits)
- Small EC keys (<256 bits)

### Certificate Validation
- Expiration checking
- Chain validation
- Basic constraints validation
- Key usage validation
- Extended key usage validation

### Recommendations
- Automatic security recommendations
- Industry best practices
- Compliance guidance

## Performance

### Benchmarks

Run benchmarks with:
```bash
cargo bench
```

### Optimization Tips
1. Use certificate caching for repeated checks
2. Enable batch processing for multiple domains
3. Configure appropriate timeouts
4. Use connection pooling (when available)

## API Documentation

Full API documentation is available at [docs.rs/checkssl](https://docs.rs/checkssl).

Key modules:
- `checkssl` - Core certificate checking
- `retry` - Retry logic and backoff strategies
- `pem_support` - PEM/DER file handling
- `batch` - Batch processing functionality
- `cache` - Certificate caching
- `crypto_analysis` - Security analysis

## Examples

More examples in the `examples/` directory:

```bash
# Run detailed check example
cargo run --example detailed_check
```

## Testing

Run tests with:
```bash
cargo test

# Run integration tests (requires internet)
cargo test --test integration_tests -- --ignored
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT © Aldi Priya Perdana, Caleb Smith

## Acknowledgments

This library uses:
- [rustls](https://github.com/rustls/rustls) - Modern TLS library
- [x509-parser](https://github.com/rusticata/x509-parser) - X.509 certificate parsing
- [webpki](https://github.com/briansmith/webpki) - Web PKI certificate validation

## Changelog

### v0.3.0 (Latest)
- ✨ Added retry logic with exponential backoff
- ✨ Added PEM/DER file support
- ✨ Added batch domain checking
- ✨ Added certificate caching
- ✨ Added security analysis
- ✨ Enhanced error handling
- ✨ Improved OCSP support
- ✨ Added CLI enhancements

### v0.2.3
- Initial stable release
- Basic certificate checking
- SNI support
- Custom timeouts