//! Support for custom root certificate stores.
//!
//! This module provides functionality to use custom root certificates
//! for SSL/TLS validation, useful for private PKI infrastructures.

use crate::error::CheckSSLError;
use rustls::{RootCertStore, Certificate};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Builder for creating custom root certificate stores.
///
/// Allows loading root certificates from files or raw PEM/DER data.
///
/// # Example
///
/// ```no_run
/// use checkssl::CustomRootStoreBuilder;
///
/// let store = CustomRootStoreBuilder::new()
///     .add_pem_file("/path/to/ca.pem")
///     .unwrap()
///     .add_der_file("/path/to/ca.der")
///     .unwrap()
///     .build();
/// ```
pub struct CustomRootStoreBuilder {
    store: RootCertStore,
    include_webpki_roots: bool,
}

impl CustomRootStoreBuilder {
    /// Create a new custom root store builder.
    pub fn new() -> Self {
        CustomRootStoreBuilder {
            store: RootCertStore::empty(),
            include_webpki_roots: false,
        }
    }

    /// Include the standard webpki root certificates.
    ///
    /// This adds all the standard trusted root certificates from
    /// major Certificate Authorities.
    pub fn with_webpki_roots(mut self) -> Self {
        self.include_webpki_roots = true;
        self
    }

    /// Add a root certificate from a PEM file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the PEM file containing the certificate
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn add_pem_file<P: AsRef<Path>>(mut self, path: P) -> Result<Self, CheckSSLError> {
        let file = File::open(path).map_err(|e| {
            CheckSSLError::CertificateParseError(format!("Failed to open PEM file: {}", e))
        })?;
        
        let mut reader = BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader).map_err(|e| {
            CheckSSLError::CertificateParseError(format!("Failed to parse PEM certificates: {}", e))
        })?;

        for cert in certs {
            self.store.add(&Certificate(cert)).map_err(|e| {
                CheckSSLError::CertificateParseError(format!("Failed to add certificate to store: {}", e))
            })?;
        }

        Ok(self)
    }

    /// Add a root certificate from a DER file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the DER file containing the certificate
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn add_der_file<P: AsRef<Path>>(mut self, path: P) -> Result<Self, CheckSSLError> {
        let mut file = File::open(path).map_err(|e| {
            CheckSSLError::CertificateParseError(format!("Failed to open DER file: {}", e))
        })?;
        
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).map_err(|e| {
            CheckSSLError::CertificateParseError(format!("Failed to read DER file: {}", e))
        })?;

        self.store.add(&Certificate(contents)).map_err(|e| {
            CheckSSLError::CertificateParseError(format!("Failed to add DER certificate to store: {}", e))
        })?;

        Ok(self)
    }

    /// Add a root certificate from PEM data.
    ///
    /// # Arguments
    ///
    /// * `pem_data` - PEM-encoded certificate data
    pub fn add_pem_data(mut self, pem_data: &[u8]) -> Result<Self, CheckSSLError> {
        let mut reader = BufReader::new(pem_data);
        let certs = rustls_pemfile::certs(&mut reader).map_err(|e| {
            CheckSSLError::CertificateParseError(format!("Failed to parse PEM data: {}", e))
        })?;

        for cert in certs {
            self.store.add(&Certificate(cert)).map_err(|e| {
                CheckSSLError::CertificateParseError(format!("Failed to add certificate to store: {}", e))
            })?;
        }

        Ok(self)
    }

    /// Add a root certificate from DER data.
    ///
    /// # Arguments
    ///
    /// * `der_data` - DER-encoded certificate data
    pub fn add_der_data(mut self, der_data: Vec<u8>) -> Result<Self, CheckSSLError> {
        self.store.add(&Certificate(der_data)).map_err(|e| {
            CheckSSLError::CertificateParseError(format!("Failed to add DER certificate to store: {}", e))
        })?;

        Ok(self)
    }

    /// Add all certificates from a directory.
    ///
    /// Searches for .pem and .crt files in the specified directory.
    ///
    /// # Arguments
    ///
    /// * `dir_path` - Path to directory containing certificate files
    pub fn add_directory<P: AsRef<Path>>(mut self, dir_path: P) -> Result<Self, CheckSSLError> {
        let dir = std::fs::read_dir(dir_path).map_err(|e| {
            CheckSSLError::CertificateParseError(format!("Failed to read directory: {}", e))
        })?;

        for entry in dir {
            let entry = entry.map_err(|e| {
                CheckSSLError::CertificateParseError(format!("Failed to read directory entry: {}", e))
            })?;
            
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    match ext.to_str() {
                        Some("pem") | Some("crt") => {
                            self = self.add_pem_file(&path)?;
                        }
                        Some("der") => {
                            self = self.add_der_file(&path)?;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(self)
    }

    /// Build the final root certificate store.
    pub fn build(mut self) -> RootCertStore {
        if self.include_webpki_roots {
            self.store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        }
        self.store
    }

    /// Get the number of certificates in the store.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

impl Default for CustomRootStoreBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Extended configuration for SSL checks with custom root certificates.
#[derive(Debug, Clone)]
pub struct CheckSSLConfigWithRoots {
    /// Base configuration (timeout, port)
    pub base_config: crate::CheckSSLConfig,
    /// Custom root certificate store
    pub root_store: Option<RootCertStore>,
}

impl CheckSSLConfigWithRoots {
    /// Create a new configuration with custom roots.
    pub fn new(base_config: crate::CheckSSLConfig) -> Self {
        CheckSSLConfigWithRoots {
            base_config,
            root_store: None,
        }
    }

    /// Set a custom root certificate store.
    pub fn with_root_store(mut self, store: RootCertStore) -> Self {
        self.root_store = Some(store);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_root_store_builder() {
        let builder = CustomRootStoreBuilder::new();
        assert!(builder.is_empty());
    }

    #[test]
    fn test_with_webpki_roots() {
        let store = CustomRootStoreBuilder::new()
            .with_webpki_roots()
            .build();
        assert!(store.len() > 0);
    }

    #[test]
    fn test_add_pem_data() {
        let pem_data = b"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHIG...
-----END CERTIFICATE-----";
        
        let result = CustomRootStoreBuilder::new()
            .add_pem_data(pem_data);
        
        // This will fail with invalid certificate data, which is expected
        assert!(result.is_err());
    }
}