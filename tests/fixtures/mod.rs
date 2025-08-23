//! Test fixtures and mock data for comprehensive testing

use checkssl::{Cert, ServerCert, IntermediateCert, CheckSSLError};
use std::time::Duration;

/// Create a mock certificate with configurable parameters
pub fn create_mock_cert(domain: &str, days_to_expiration: i64, is_valid: bool) -> Cert {
    Cert {
        server: ServerCert {
            common_name: domain.to_string(),
            is_valid,
            days_to_expiration,
            not_before: 0,
            not_after: 86400 * (days_to_expiration + 365),
            signature_algorithm: "SHA256withRSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            public_key_size: Some(2048),
            sans: vec![domain.to_string(), format!("www.{}", domain)],
            key_usage: vec!["Digital Signature".to_string(), "Key Encipherment".to_string()],
            extended_key_usage: vec!["Server Auth".to_string(), "Client Auth".to_string()],
            ..Default::default()
        },
        intermediate: IntermediateCert {
            common_name: "Test Intermediate CA".to_string(),
            is_ca: true,
            is_valid: true,
            signature_algorithm: "SHA256withRSA".to_string(),
            ..Default::default()
        },
        chain_length: 3,
        protocol_version: "TLSv1.3".to_string(),
    }
}

/// Create a weak certificate for security testing
pub fn create_weak_cert(domain: &str) -> Cert {
    Cert {
        server: ServerCert {
            common_name: domain.to_string(),
            is_valid: true,
            days_to_expiration: 30,
            signature_algorithm: "SHA1withRSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            public_key_size: Some(1024),
            ..Default::default()
        },
        intermediate: IntermediateCert {
            signature_algorithm: "MD5withRSA".to_string(),
            is_ca: true,
            is_valid: true,
            ..Default::default()
        },
        chain_length: 2,
        protocol_version: "TLSv1.0".to_string(),
    }
}

/// Create a certificate with specific signature algorithm
pub fn create_cert_with_algorithm(sig_algo: &str, key_size: usize) -> Cert {
    Cert {
        server: ServerCert {
            common_name: "test.example.com".to_string(),
            is_valid: true,
            days_to_expiration: 90,
            signature_algorithm: sig_algo.to_string(),
            public_key_algorithm: if sig_algo.contains("ECDSA") { "EC" } else { "RSA" }.to_string(),
            public_key_size: Some(key_size),
            sans: vec!["test.example.com".to_string()],
            key_usage: vec!["Digital Signature".to_string()],
            extended_key_usage: vec!["Server Auth".to_string()],
            ..Default::default()
        },
        intermediate: IntermediateCert::default(),
        chain_length: 2,
        protocol_version: "TLSv1.3".to_string(),
    }
}

/// Create sample DER-encoded certificate data for OCSP testing
pub fn create_mock_der_cert() -> Vec<u8> {
    // This is a simplified mock certificate structure
    // In real tests, you would use actual certificate data
    vec![
        0x30, 0x82, 0x03, 0x21, // SEQUENCE header
        0x30, 0x82, 0x02, 0x09, // TBS Certificate
        0xa0, 0x03, 0x02, 0x01, 0x02, // Version
        0x02, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, // Serial number
        // ... rest of certificate structure
    ]
}

/// Create mock issuer certificate DER data
pub fn create_mock_issuer_der() -> Vec<u8> {
    vec![
        0x30, 0x82, 0x03, 0x50, // SEQUENCE header
        0x30, 0x82, 0x02, 0x38, // TBS Certificate
        0xa0, 0x03, 0x02, 0x01, 0x02, // Version
        0x02, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // Serial number
        // ... rest of issuer certificate
    ]
}

/// Create a retryable error for testing
pub fn create_retryable_error(message: &str) -> CheckSSLError {
    CheckSSLError::NetworkError(message.to_string())
}

/// Create a non-retryable error for testing
pub fn create_non_retryable_error(message: &str) -> CheckSSLError {
    CheckSSLError::CertificateParseError(message.to_string())
}

/// Generate test data of various sizes for cache testing
pub fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Create a timeout duration for testing
pub fn test_timeout() -> Duration {
    Duration::from_millis(100)
}

/// Mock OCSP responder URL
pub fn mock_ocsp_url() -> String {
    "http://ocsp.test.example.com".to_string()
}

/// Create mock OCSP response data
pub fn create_mock_ocsp_response(status: &str) -> Vec<u8> {
    match status {
        "good" => vec![0x30, 0x82, 0x01, 0x00, 0x80, 0x00], // Simplified good response
        "revoked" => vec![0x30, 0x82, 0x01, 0x00, 0x80, 0x01], // Simplified revoked response
        _ => vec![0x30, 0x82, 0x01, 0x00, 0x80, 0x02], // Unknown status
    }
}