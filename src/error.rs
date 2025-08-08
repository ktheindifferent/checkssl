//! Error types for the CheckSSL library.
//!
//! This module defines custom error types that provide detailed
//! information about what went wrong during certificate checking.

use std::fmt;
use std::error::Error;
use std::io;

/// Errors that can occur during SSL certificate checking.
///
/// This enum provides specific error variants for different failure modes,
/// making it easier to handle errors appropriately.
#[derive(Debug)]
pub enum CheckSSLError {
    NetworkError(String),
    CertificateParseError(String),
    ValidationError(String),
    TimeoutError(String),
    DnsResolutionError(String),
    TlsHandshakeError(String),
    InvalidDomainError(String),
    CertificateExpired {
        common_name: String,
        expired_since: i64,
    },
    CertificateNotYetValid {
        common_name: String,
        valid_from: i64,
    },
    ChainValidationError(String),
    OcspError(String),
    CrlError(String),
    IoError(io::Error),
}

impl fmt::Display for CheckSSLError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckSSLError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            CheckSSLError::CertificateParseError(msg) => write!(f, "Certificate parse error: {}", msg),
            CheckSSLError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            CheckSSLError::TimeoutError(msg) => write!(f, "Timeout error: {}", msg),
            CheckSSLError::DnsResolutionError(msg) => write!(f, "DNS resolution error: {}", msg),
            CheckSSLError::TlsHandshakeError(msg) => write!(f, "TLS handshake error: {}", msg),
            CheckSSLError::InvalidDomainError(msg) => write!(f, "Invalid domain: {}", msg),
            CheckSSLError::CertificateExpired { common_name, expired_since } => {
                write!(f, "Certificate for '{}' expired {} days ago", common_name, expired_since)
            },
            CheckSSLError::CertificateNotYetValid { common_name, valid_from } => {
                write!(f, "Certificate for '{}' not valid for {} more days", common_name, valid_from)
            },
            CheckSSLError::ChainValidationError(msg) => write!(f, "Certificate chain validation error: {}", msg),
            CheckSSLError::OcspError(msg) => write!(f, "OCSP error: {}", msg),
            CheckSSLError::CrlError(msg) => write!(f, "CRL error: {}", msg),
            CheckSSLError::IoError(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl Error for CheckSSLError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CheckSSLError::IoError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for CheckSSLError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::TimedOut => CheckSSLError::TimeoutError("Connection timed out".to_string()),
            io::ErrorKind::InvalidInput => CheckSSLError::InvalidDomainError(err.to_string()),
            io::ErrorKind::NotFound => CheckSSLError::CertificateParseError("Certificate not found".to_string()),
            _ => CheckSSLError::IoError(err),
        }
    }
}

