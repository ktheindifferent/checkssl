//! # CheckSSL
//!
//! A Rust library for validating SSL/TLS certificates.
//!
//! ## Features
//!
//! - Certificate validation and information extraction
//! - Configurable timeouts and ports
//! - Both synchronous and asynchronous APIs
//! - Certificate chain validation
//! - SHA256 and SHA1 fingerprint generation
//! - Comprehensive error handling
//!
//! ## Quick Start
//!
//! ```no_run
//! use checkssl::CheckSSL;
//!
//! // Basic certificate check
//! match CheckSSL::from_domain("rust-lang.org".to_string()) {
//!     Ok(cert) => {
//!         println!("Certificate is valid: {}", cert.server.is_valid);
//!         println!("Days to expiration: {}", cert.server.days_to_expiration);
//!     }
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! ```

mod error;
mod chain_validator;
mod custom_roots;
mod platform;
mod ocsp;
mod retry;
mod pem_support;
mod batch;
mod cache;
mod crypto_analysis;

use std::sync::{Arc};
use rustls::Session;
use std::net::TcpStream;
use std::io::{Write};
use std::fmt::Debug;
use x509_parser::{parse_x509_der};
use x509_parser::objects::*;
use x509_parser::extensions::*;
use serde::{Serialize, Deserialize};
use std::time::Duration;
extern crate savefile;
#[macro_use]
extern crate savefile_derive;
use std::net::{ToSocketAddrs};
use std::thread;
use std::sync::mpsc;
use std::future::Future;
use std::pin::Pin;
use sha2::{Sha256, Digest as Sha2Digest};
use sha1::{Sha1};
use x509_parser::x509::X509Certificate;

pub use error::CheckSSLError;
pub use chain_validator::{ChainValidator, ChainValidationResult, CertificateInfo};
pub use custom_roots::{CustomRootStoreBuilder, CheckSSLConfigWithRoots};
pub use platform::{platform_name, architecture, get_system_cert_paths};
pub use ocsp::{check_ocsp_status, OcspStatus, OcspRequest, OcspResponse, RevocationReason};
pub use retry::{RetryConfig, retry_with_backoff, RetryableError};
pub use pem_support::{CertificateFormat, load_certificates_from_file, check_certificate_from_file, der_to_pem, pem_to_der};
pub use batch::{batch_check_domains, BatchConfig, BatchCheckResult, BatchStatistics, export_batch_results_json, export_batch_results_csv};
pub use cache::{CertificateCache, CacheConfig, EvictionStrategy, global_cache, check_with_cache};
pub use crypto_analysis::{analyze_certificate, CryptoAnalysis, SecurityLevel, generate_security_report};

/// Helper function to extract RDN value from a certificate attribute
pub(crate) fn extract_rdn_value(rdn_seq: &x509_parser::x509::RelativeDistinguishedName) -> Result<String, CheckSSLError> {
    rdn_seq.set.first()
        .ok_or_else(|| CheckSSLError::CertificateParseError("No attribute in RDN".to_string()))
        .and_then(|attr| {
            attr.attr_value.content.as_str()
                .map(|s| s.to_string())
                .map_err(|_| CheckSSLError::CertificateParseError("Failed to extract RDN value".to_string()))
        })
}

/// Helper function to extract public key algorithm from signature algorithm
pub(crate) fn extract_public_key_algorithm(signature_algorithm: &str) -> String {
    if signature_algorithm.contains("RSA") {
        "RSA".to_string()
    } else if signature_algorithm.contains("ECDSA") {
        "EC".to_string()
    } else if signature_algorithm.contains("DSA") {
        "DSA".to_string()
    } else {
        "Unknown".to_string()
    }
}

/// Helper function to extract key usage flags
pub(crate) fn extract_key_usage(key_usage: &x509_parser::extensions::KeyUsage) -> Vec<String> {
    let mut usage = Vec::new();
    if key_usage.digital_signature() { usage.push("Digital Signature".to_string()); }
    if key_usage.non_repudiation() { usage.push("Non Repudiation".to_string()); }
    if key_usage.key_encipherment() { usage.push("Key Encipherment".to_string()); }
    if key_usage.data_encipherment() { usage.push("Data Encipherment".to_string()); }
    if key_usage.key_agreement() { usage.push("Key Agreement".to_string()); }
    if key_usage.key_cert_sign() { usage.push("Key Cert Sign".to_string()); }
    if key_usage.crl_sign() { usage.push("CRL Sign".to_string()); }
    if key_usage.encipher_only() { usage.push("Encipher Only".to_string()); }
    if key_usage.decipher_only() { usage.push("Decipher Only".to_string()); }
    usage
}

/// Helper function to process certificate subject/issuer fields
pub(crate) fn process_certificate_names(x509cert: &X509Certificate, is_issuer: bool) -> Result<(String, String), CheckSSLError> {
    let name = if is_issuer { x509cert.issuer() } else { x509cert.subject() };
    let mut full_name = Vec::new();
    let mut cn = String::new();
    
    for rdn_seq in &name.rdn_seq {
        if let Some(attr) = rdn_seq.set.first() {
            let attr_name = oid2sn(&attr.attr_type)
                .map_err(|_| CheckSSLError::CertificateParseError("Error converting Oid to Nid".to_string()))?;
            let rdn_content = extract_rdn_value(rdn_seq)?;
            full_name.push(format!("{}={}", attr_name, rdn_content));
            if attr_name == "CN" {
                cn = rdn_content;
            }
        }
    }
    
    Ok((full_name.join(", "), cn))
}

/// Helper function to populate certificate subject fields
pub(crate) fn populate_subject_fields(x509cert: &X509Certificate) -> Result<(String, String, String, String, String, String), CheckSSLError> {
    let subject = x509cert.subject();
    let mut common_name = String::new();
    let mut country = String::new();
    let mut state = String::new();
    let mut locality = String::new();
    let mut organization = String::new();
    let mut organizational_unit = String::new();
    
    for rdn_seq in &subject.rdn_seq {
        if let Some(attr) = rdn_seq.set.first() {
            let attr_name = oid2sn(&attr.attr_type)
                .map_err(|_| CheckSSLError::CertificateParseError("Error converting Oid to Nid".to_string()))?;
            let rdn_content = extract_rdn_value(rdn_seq)?;
            
            match attr_name {
                "C" => country = rdn_content,
                "ST" => state = rdn_content,
                "L" => locality = rdn_content,
                "CN" => common_name = rdn_content,
                "O" => organization = rdn_content,
                "OU" => organizational_unit = rdn_content,
                _ => {}
            }
        }
    }
    
    Ok((common_name, country, state, locality, organization, organizational_unit))
}

/// Information about the server's SSL certificate.
///
/// Contains detailed information extracted from the server certificate
/// including validity, issuer, subject, and cryptographic details.
#[derive(Serialize, Deserialize, Savefile, Debug, Clone, PartialEq, Default)]
pub struct ServerCert {
    pub common_name: String,
    pub signature_algorithm: String,
    pub sans: Vec<String>,
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: String,
    pub serial_number: String,
    pub version: i32,
    pub not_after: i64,
    pub not_before: i64,
    pub issuer: String,
    pub issuer_cn: String,
    pub is_valid: bool,
    pub time_to_expiration: String,
    pub days_to_expiration: i64,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub public_key_algorithm: String,
    pub public_key_size: Option<usize>,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
}

/// Information about an intermediate certificate in the chain.
///
/// Intermediate certificates are used by Certificate Authorities to
/// sign server certificates while keeping the root certificate secure.
#[derive(Serialize, Deserialize, Savefile, Debug, Clone, PartialEq, Default)]
pub struct IntermediateCert {
    pub common_name: String,
    pub signature_algorithm: String,
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: String,
    pub serial_number: String,
    pub version: i32,
    pub not_after: i64,
    pub not_before: i64,
    pub issuer: String,
    pub issuer_cn: String,
    pub is_valid: bool,
    pub time_to_expiration: String,
    pub days_to_expiration: i64,
    pub key_usage: Vec<String>,
    pub is_ca: bool,
    pub path_len_constraint: Option<u32>,
    pub public_key_algorithm: String,
    pub public_key_size: Option<usize>,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
}

/// Complete certificate information including server and intermediate certificates.
///
/// This is the main return type for certificate checks, containing
/// both the server certificate and intermediate certificate information.
#[derive(Serialize, Deserialize, Savefile, Debug, Clone, PartialEq, Default)]
pub struct Cert {
    pub server: ServerCert,
    pub intermediate: IntermediateCert,
    pub chain_length: usize,
    pub protocol_version: String,
}

/// Configuration options for SSL certificate checks.
///
/// Allows customization of timeout and port settings.
///
/// # Example
///
/// ```
/// use checkssl::CheckSSLConfig;
/// use std::time::Duration;
///
/// let config = CheckSSLConfig {
///     timeout: Duration::from_secs(10),
///     port: 8443,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct CheckSSLConfig {
    pub timeout: Duration,
    pub port: u16,
}

impl Default for CheckSSLConfig {
    fn default() -> Self {
        CheckSSLConfig {
            timeout: Duration::from_secs(5),
            port: 443,
        }
    }
}

/// Main struct for performing SSL certificate checks.
///
/// This struct provides static methods for checking SSL certificates
/// from domains using various configurations. SNI (Server Name Indication)
/// is automatically enabled for all domain checks, ensuring proper certificate
/// validation for virtual hosts and shared hosting environments.
pub struct CheckSSL();

impl CheckSSL {
    /// Check SSL certificate from a domain using default settings.
    ///
    /// This is the simplest way to check an SSL certificate. It uses:
    /// - Port 443 (HTTPS default)
    /// - 5 second timeout
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain name to check (e.g., "example.com")
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing:
    /// - `Ok(Cert)` - Certificate information if successful
    /// - `Err(CheckSSLError)` - Error details if the check fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use checkssl::CheckSSL;
    ///
    /// match CheckSSL::from_domain("rust-lang.org".to_string()) {
    ///     Ok(certificate) => {
    ///         println!("Certificate valid: {}", certificate.server.is_valid);
    ///         println!("Common name: {}", certificate.server.common_name);
    ///         println!("Days to expiration: {}", certificate.server.days_to_expiration);
    ///     }
    ///     Err(e) => {
    ///         eprintln!("Certificate check failed: {}", e);
    ///     }
    /// }
    /// ```
    pub fn from_domain(domain: String) -> Result<Cert, CheckSSLError> {
        Self::from_domain_with_config(domain, CheckSSLConfig::default())
    }

    /// Check SSL certificate with custom configuration.
    ///
    /// Allows customization of timeout and port settings for the certificate check.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain name to check
    /// * `config` - Custom configuration for the check
    ///
    /// # Example
    ///
    /// ```no_run
    /// use checkssl::{CheckSSL, CheckSSLConfig};
    /// use std::time::Duration;
    ///
    /// let config = CheckSSLConfig {
    ///     timeout: Duration::from_secs(10),
    ///     port: 8443,
    /// };
    ///
    /// match CheckSSL::from_domain_with_config("example.com".to_string(), config) {
    ///     Ok(cert) => println!("Certificate valid: {}", cert.server.is_valid),
    ///     Err(e) => eprintln!("Error: {}", e),
    /// }
    /// ```
    pub fn from_domain_with_config(domain: String, config: CheckSSLConfig) -> Result<Cert, CheckSSLError> {
        Self::check_cert_blocking(domain, config)
    }

    /// Check SSL certificate asynchronously.
    ///
    /// Returns a future that can be awaited for the certificate check result.
    /// Uses default configuration (port 443, 5 second timeout).
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain name to check
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() {
    /// use checkssl::CheckSSL;
    ///
    /// let future = CheckSSL::from_domain_async("rust-lang.org".to_string());
    /// match future.await {
    ///     Ok(cert) => println!("Certificate valid: {}", cert.server.is_valid),
    ///     Err(e) => eprintln!("Error: {}", e),
    /// }
    /// # }
    /// ```
    pub fn from_domain_async(domain: String) -> Pin<Box<dyn Future<Output = Result<Cert, CheckSSLError>> + Send>> {
        Self::from_domain_async_with_config(domain, CheckSSLConfig::default())
    }

    /// Check ssl from domain with custom configuration (non-blocking)
    pub fn from_domain_async_with_config(domain: String, config: CheckSSLConfig) -> Pin<Box<dyn Future<Output = Result<Cert, CheckSSLError>> + Send>> {
        Box::pin(async move {
            Self::check_cert_blocking(domain, config)
        })
    }

    fn check_cert_blocking(domain: String, config: CheckSSLConfig) -> Result<Cert, CheckSSLError> {

        let (sender, receiver) = mpsc::channel();
        let timeout = config.timeout;
        let port = config.port;
        let _t = thread::spawn(move || {
            let mut rustls_config = rustls::ClientConfig::new();
            rustls_config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    
            let rc_config = Arc::new(rustls_config);
            let dnn = domain.clone();
            let dnnn = dnn.as_str();
            let site = match webpki::DNSNameRef::try_from_ascii_str(dnnn) {
                Ok(val) => val,
                Err(e) => return Err(CheckSSLError::InvalidDomainError(e.to_string())),
            };
    
            match format!("{}:{}", domain.clone().as_str(), port).to_socket_addrs(){
                Ok(mut val) => {
                    match val.next(){
                        Some(connect_domain) => {
    
                            let mut sess = rustls::ClientSession::new(&rc_config, site);
                            let mut sock = TcpStream::connect_timeout(&connect_domain, timeout)?;
                            let mut tls = rustls::Stream::new(&mut sess, &mut sock);
                    
                            let req = format!("GET / HTTP/1.0\r\nHost: {}\r\nConnection: \
                                                   close\r\nAccept-Encoding: identity\r\n\r\n",
                                              domain.clone());
                            tls.write_all(req.as_bytes())?;
                    
                            let mut server_cert = ServerCert {
                                common_name: "".to_string(),
                                signature_algorithm: "".to_string(),
                                sans: Vec::new(),
                                country: "".to_string(),
                                state: "".to_string(),
                                locality: "".to_string(),
                                organization: "".to_string(),
                                organizational_unit: "".to_string(),
                                serial_number: "".to_string(),
                                version: 0,
                                not_after: 0,
                                not_before: 0,
                                issuer: "".to_string(),
                                issuer_cn: "".to_string(),
                                is_valid: false,
                                time_to_expiration: "".to_string(),
                                days_to_expiration: 0,
                                key_usage: Vec::new(),
                                extended_key_usage: Vec::new(),
                                public_key_algorithm: "".to_string(),
                                public_key_size: None,
                                fingerprint_sha256: "".to_string(),
                                fingerprint_sha1: "".to_string(),
                            };
                    
                            let mut intermediate_cert = IntermediateCert {
                                common_name: "".to_string(),
                                signature_algorithm: "".to_string(),
                                country: "".to_string(),
                                state: "".to_string(),
                                locality: "".to_string(),
                                organization: "".to_string(),
                                organizational_unit: "".to_string(),
                                serial_number: "".to_string(),
                                version: 0,
                                not_after: 0,
                                not_before: 0,
                                issuer: "".to_string(),
                                issuer_cn: "".to_string(),
                                is_valid: false,
                                time_to_expiration: "".to_string(),
                                days_to_expiration: 0,
                                key_usage: Vec::new(),
                                is_ca: false,
                                path_len_constraint: None,
                                public_key_algorithm: "".to_string(),
                                public_key_size: None,
                                fingerprint_sha256: "".to_string(),
                                fingerprint_sha1: "".to_string(),
                            };
                    
                            let protocol_version = format!("{:?}", tls.sess.get_protocol_version());
                            let chain_length = tls.sess.get_peer_certificates().map(|c| c.len()).unwrap_or(0);

                            if let Some(certificates) = tls.sess.get_peer_certificates() {
                                
                                for certificate in certificates.iter() {
    
                                    let x509cert = match parse_x509_der(certificate.as_ref()) {
                                        Ok((_, x509cert)) => x509cert,
                                        Err(e) => return Err(CheckSSLError::CertificateParseError(e.to_string())),
                                    };
                    
                                    let is_ca = match x509cert.tbs_certificate.basic_constraints() {
                                        Some((_, basic_constraints)) => basic_constraints.ca,
                                        None => false,
                                    };
                    
                                    // Calculate fingerprints
                                    let mut hasher_sha256 = Sha256::new();
                                    hasher_sha256.update(certificate.as_ref());
                                    let fingerprint_sha256 = format!("{:X}", hasher_sha256.finalize());
                                    
                                    let mut hasher_sha1 = Sha1::new();
                                    hasher_sha1.update(certificate.as_ref());
                                    let fingerprint_sha1 = format!("{:X}", hasher_sha1.finalize());

                                    //check if it's ca or not, if ca then insert to intermediate certificate
                                    if is_ca {
                                        intermediate_cert.is_ca = true;
                                        intermediate_cert.is_valid = x509cert.validity().is_valid();
                                        intermediate_cert.not_after = x509cert.tbs_certificate.validity.not_after.timestamp();
                                        intermediate_cert.not_before = x509cert.tbs_certificate.validity.not_before.timestamp();
                                        intermediate_cert.version = (x509cert.tbs_certificate.version + 1) as i32;
                                        intermediate_cert.serial_number = format!("{:X}", x509cert.tbs_certificate.serial);
                                        intermediate_cert.fingerprint_sha256 = fingerprint_sha256.clone();
                                        intermediate_cert.fingerprint_sha1 = fingerprint_sha1.clone();
                    
                                        match oid2sn(&x509cert.signature_algorithm.algorithm) {
                                            Ok(s) => {
                                                intermediate_cert.signature_algorithm = s.to_string();
                                            }
                                            Err(_e) =>  return Err(CheckSSLError::CertificateParseError("Error converting Oid to Nid".to_string())),
                                        }

                                        // Extract public key algorithm from the signature algorithm
                                        intermediate_cert.public_key_algorithm = extract_public_key_algorithm(&intermediate_cert.signature_algorithm);

                                        // Extract basic constraints path length
                                        if let Some((_, basic_constraints)) = x509cert.tbs_certificate.basic_constraints() {
                                            intermediate_cert.path_len_constraint = basic_constraints.path_len_constraint;
                                        }

                                        // Extract key usage
                                        if let Some((_, key_usage)) = x509cert.tbs_certificate.key_usage() {
                                            intermediate_cert.key_usage = extract_key_usage(key_usage);
                                        }
                    
                                        if let Some(time_to_expiration) = x509cert.tbs_certificate.validity.time_to_expiration() {
                                            let days = time_to_expiration.as_secs() / 60 / 60 / 24;
                                            intermediate_cert.time_to_expiration = format!("{} day(s)", days);
                                            intermediate_cert.days_to_expiration = days as i64;
                                        }
                    
                                        // Process issuer and subject
                                        let (issuer_full, issuer_cn) = process_certificate_names(&x509cert, true)?;
                                        intermediate_cert.issuer = issuer_full;
                                        intermediate_cert.issuer_cn = issuer_cn;
                                        
                                        let (common_name, country, state, locality, organization, organizational_unit) = 
                                            populate_subject_fields(&x509cert)?;
                                        intermediate_cert.common_name = common_name;
                                        intermediate_cert.country = country;
                                        intermediate_cert.state = state;
                                        intermediate_cert.locality = locality;
                                        intermediate_cert.organization = organization;
                                        intermediate_cert.organizational_unit = organizational_unit;
                                    } else {
                                        server_cert.is_valid = x509cert.validity().is_valid();
                                        server_cert.not_after = x509cert.tbs_certificate.validity.not_after.timestamp();
                                        server_cert.not_before = x509cert.tbs_certificate.validity.not_before.timestamp();
                                        server_cert.version = (x509cert.tbs_certificate.version + 1) as i32;
                                        server_cert.serial_number = format!("{:X}", x509cert.tbs_certificate.serial);
                                        server_cert.fingerprint_sha256 = fingerprint_sha256;
                                        server_cert.fingerprint_sha1 = fingerprint_sha1;
                    
                                        match oid2sn(&x509cert.signature_algorithm.algorithm) {
                                            Ok(s) => {
                                                server_cert.signature_algorithm = s.to_string();
                                            }
                                            Err(_e) =>  return Err(CheckSSLError::CertificateParseError("Error converting Oid to Nid".to_string())),
                                        }

                                        // Extract public key algorithm from the signature algorithm
                                        server_cert.public_key_algorithm = extract_public_key_algorithm(&server_cert.signature_algorithm);

                                        // Extract key usage
                                        if let Some((_, key_usage)) = x509cert.tbs_certificate.key_usage() {
                                            server_cert.key_usage = extract_key_usage(key_usage);
                                        }

                                        // Extract extended key usage
                                        if let Some((_, eku)) = x509cert.tbs_certificate.extended_key_usage() {
                                            let mut usage = Vec::new();
                                            if eku.any { usage.push("Any".to_string()); }
                                            if eku.server_auth { usage.push("Server Auth".to_string()); }
                                            if eku.client_auth { usage.push("Client Auth".to_string()); }
                                            if eku.code_signing { usage.push("Code Signing".to_string()); }
                                            if eku.email_protection { usage.push("Email Protection".to_string()); }
                                            if eku.time_stamping { usage.push("Time Stamping".to_string()); }
                                            if eku.ocscp_signing { usage.push("OCSP Signing".to_string()); }
                                            server_cert.extended_key_usage = usage;
                                        }
                    
                                        if let Some((_, san)) = x509cert.tbs_certificate.subject_alternative_name() {
                                            for name in san.general_names.iter() {
                                                match name {
                                                    GeneralName::DNSName(dns) => {
                                                        server_cert.sans.push(dns.to_string())
                                                    }
                                                    _ => {},
                                                }
                                            }
                                        }
                    
                                        if let Some(time_to_expiration) = x509cert.tbs_certificate.validity.time_to_expiration() {
                                            let days = time_to_expiration.as_secs() / 60 / 60 / 24;
                                            server_cert.time_to_expiration = format!("{} day(s)", days);
                                            server_cert.days_to_expiration = days as i64;
                                        }
                    
                                        // Process issuer and subject
                                        let (issuer_full, issuer_cn) = process_certificate_names(&x509cert, true)?;
                                        server_cert.issuer = issuer_full;
                                        server_cert.issuer_cn = issuer_cn;
                                        
                                        let (common_name, country, state, locality, organization, organizational_unit) = 
                                            populate_subject_fields(&x509cert)?;
                                        server_cert.common_name = common_name;
                                        server_cert.country = country;
                                        server_cert.state = state;
                                        server_cert.locality = locality;
                                        server_cert.organization = organization;
                                        server_cert.organizational_unit = organizational_unit;
                                    }
                                }
                    
                                let cert = Cert{
                                    server: server_cert,
                                    intermediate: intermediate_cert,
                                    chain_length,
                                    protocol_version,
                                };
                                match sender.send(cert.clone()) {
                                    Ok(()) => {

                                        return Ok(cert.clone());

                                    }, // everything good
                                    Err(_) => {
                                        return Err(CheckSSLError::NetworkError("Error sending message to main thread".to_string()));
                                    }, // we have been released, don't panic
                                }
                         
                            } else {
                                Err(CheckSSLError::CertificateParseError("certificate not found".to_string()))
                            }
                        },
                        None => return Err(CheckSSLError::DnsResolutionError("empty socket address".to_string()))
                    }
                },
                Err(e) => return Err(CheckSSLError::DnsResolutionError(e.to_string()))
            }
    









      
        });
        match receiver.recv_timeout(timeout){
            Ok(dat) => {
                return Ok(dat);
            },
            Err(_e) => return Err(CheckSSLError::TimeoutError("Certificate check timed out".to_string()))
        }

    }
}

mod tests;
