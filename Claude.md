# CheckSSL - Rust SSL/TLS Certificate Validation Library

## Project Overview

CheckSSL is a comprehensive SSL/TLS certificate validation library for Rust that provides advanced security analysis, batch processing, caching, and extensive certificate validation features. It's designed for both library usage and command-line operation.

## Codebase Structure

### Root Directory
- `Cargo.toml` - Rust package manifest (v0.2.3)
- `LICENSE` - MIT License
- `README.md` - Main project documentation
- `ENHANCEMENTS.md` - Feature enhancement documentation
- `CROSS_PLATFORM.md` - Cross-platform support documentation
- `overview.md` - Project overview
- `project_description.md` - Detailed project description
- `todo.md` - Project task list

### Source Code (`src/`)

#### Core Modules
- `lib.rs` - Main library entry point, exports public API
- `main.rs` - Main executable entry point
- `error.rs` - Comprehensive error types and handling

#### Feature Modules
- `chain_validator.rs` - Certificate chain validation logic
- `crypto_analysis.rs` - Security analysis and weak algorithm detection
- `ocsp.rs` - Online Certificate Status Protocol support
- `platform.rs` - Platform-specific certificate handling
- `custom_roots.rs` - Custom root certificate management

#### Enhanced Features
- `batch.rs` - Batch domain checking functionality
- `cache.rs` - In-memory certificate caching with LRU eviction
- `retry.rs` - Retry logic with exponential backoff
- `pem_support.rs` - PEM/DER file format support

#### Testing
- `tests.rs` - Unit tests module

### Binary (`src/bin/`)
- `checkssl-cli.rs` - Command-line interface implementation

### Tests (`tests/`)
- `integration_tests.rs` - Integration tests with live SSL checks
- `cross_platform_tests.rs` - Platform-specific tests
- `enhanced_features_tests.rs` - Tests for new features
- `sni_tests.rs` - Server Name Indication tests

### Examples (`examples/`)
- `detailed_check.rs` - Comprehensive usage example

### Benchmarks (`benches/`)
- `ssl_benchmarks.rs` - Performance benchmarks

## Dependencies

### Core Dependencies
- `rustls` (0.18.1) - Modern TLS library
- `webpki` (0.21.3) - Web PKI certificate validation
- `webpki-roots` (0.20.0) - Mozilla's root certificates
- `x509-parser` (0.8.0-beta4) - X.509 certificate parsing

### Utility Dependencies
- `chrono` (0.4.13) - Date/time handling with serde support
- `serde` (1.0.114) - Serialization framework
- `serde_json` (1.0) - JSON serialization
- `savefile` - Binary serialization
- `sha2` (0.10) - SHA-256 hashing
- `sha1` (0.10) - SHA-1 hashing (for fingerprints)
- `base64` (0.21) - Base64 encoding/decoding
- `rustls-pemfile` (0.2) - PEM file parsing
- `lazy_static` (1.4) - Lazy static initialization

### Optional Dependencies
- `tokio` (1.0) - Async runtime (feature: async)

### Platform-Specific Dependencies
- Unix: `libc` (0.2)
- Windows: `winapi` (0.3)

### Dev Dependencies
- `criterion` (0.5) - Benchmarking framework
- `tempfile` (3.8) - Temporary file handling
- `tokio` (full features for testing)

## Features

### Cargo Features
- `default` - Basic functionality
- `async` - Asynchronous API support (enables tokio)
- `batch` - Batch domain checking
- `cache` - Certificate caching

## Key Functionality

### Certificate Validation
- Live domain SSL/TLS certificate checking
- Certificate chain validation
- Expiration date checking
- Signature verification
- Basic constraints validation
- Key usage validation

### Security Analysis
- Weak algorithm detection (MD5, SHA1, small keys)
- Security level assessment
- Detailed security recommendations
- Compliance guidance

### Enhanced Features
- **Retry Logic**: Automatic retry with exponential backoff for transient failures
- **File Support**: Check certificates from PEM/DER files
- **Batch Processing**: Concurrent checking of multiple domains
- **Caching**: In-memory cache with LRU eviction strategy
- **OCSP**: Online Certificate Status Protocol support
- **SNI**: Automatic Server Name Indication for virtual hosts

### CLI Features
- Basic certificate checking
- Custom port and timeout configuration
- Security analysis mode
- File-based certificate checking
- Batch checking from file
- JSON output format
- Verbose output mode

## API Design

### Main Types
- `CheckSSL` - Main certificate checking struct
- `CheckSSLConfig` - Configuration for checks
- `CheckSSLError` - Error types enumeration
- `Certificate` - Certificate information
- `CertificateCache` - Caching implementation
- `BatchConfig` - Batch processing configuration
- `RetryConfig` - Retry logic configuration
- `SecurityAnalysis` - Security assessment results

### Key Functions
- `CheckSSL::from_domain()` - Basic domain checking
- `CheckSSL::from_domain_with_config()` - Configurable checking
- `check_certificate_from_file()` - File-based checking
- `batch_check_domains()` - Batch processing
- `check_with_cache()` - Cached checking
- `analyze_certificate()` - Security analysis
- `retry_with_backoff()` - Retry wrapper

## Testing Strategy

### Unit Tests
- Located in `src/tests.rs` and individual module files
- Test core functionality in isolation

### Integration Tests
- `tests/integration_tests.rs` - Live SSL checks
- `tests/cross_platform_tests.rs` - Platform compatibility
- `tests/enhanced_features_tests.rs` - Feature validation
- `tests/sni_tests.rs` - SNI functionality

### Benchmarks
- Performance testing with Criterion
- Focus on certificate validation speed
- Cache performance metrics

## Build and Run

### Build Library
```bash
cargo build --release
```

### Run CLI
```bash
cargo run --bin checkssl -- example.com
```

### Run Tests
```bash
# Unit tests
cargo test

# Integration tests (requires internet)
cargo test --test integration_tests -- --ignored

# All tests
cargo test --all
```

### Run Benchmarks
```bash
cargo bench
```

## Performance Considerations

- Connection pooling for batch operations
- In-memory caching with configurable TTL
- Concurrent processing for batch checks
- Lazy initialization of expensive resources
- Efficient certificate parsing and validation

## Security Considerations

- No storage of private keys
- Secure TLS connections using rustls
- Proper certificate chain validation
- Detection of weak cryptographic algorithms
- Comprehensive error handling without information leakage

## Platform Support

- Linux (primary target)
- macOS (full support)
- Windows (full support)
- Platform-specific root certificate handling

## Version Information

Current Version: 0.2.3
Rust Edition: 2018
License: MIT

## Repository

GitHub: https://github.com/pixelcoda/checkssl/

## Authors

- Aldi Perdana <aldidana@gmail.com>
- Caleb Smith <calebsmithwoolrich@gmail.com>