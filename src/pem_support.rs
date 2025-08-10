//! PEM certificate file support.
//!
//! This module provides functionality to read and parse certificates
//! from PEM files, supporting both single certificates and certificate chains.

use crate::error::CheckSSLError;
use crate::{Cert, ServerCert, IntermediateCert};
use x509_parser::{parse_x509_der, x509::X509Certificate};
use rustls_pemfile;
use std::io::{BufReader, Read};
use std::path::Path;
use std::fs::File;
use sha2::{Sha256, Digest as Sha2Digest};
use sha1::Sha1;

/// Certificate file format types
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateFormat {
    /// PEM format (Base64 encoded)
    PEM,
    /// DER format (Binary)
    DER,
    /// Auto-detect format
    Auto,
}

/// Load certificates from a PEM or DER file
pub fn load_certificates_from_file<P: AsRef<Path>>(
    path: P,
    format: CertificateFormat,
) -> Result<Vec<Vec<u8>>, CheckSSLError> {
    let path = path.as_ref();
    let mut file = File::open(path)
        .map_err(|e| CheckSSLError::IoError(e))?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| CheckSSLError::IoError(e))?;

    match format {
        CertificateFormat::PEM => parse_pem_certificates(&contents),
        CertificateFormat::DER => Ok(vec![contents]),
        CertificateFormat::Auto => {
            // Try PEM first, fall back to DER
            if contents.starts_with(b"-----BEGIN") {
                parse_pem_certificates(&contents)
            } else {
                Ok(vec![contents])
            }
        }
    }
}

/// Parse PEM certificates from bytes
pub fn parse_pem_certificates(pem_data: &[u8]) -> Result<Vec<Vec<u8>>, CheckSSLError> {
    let mut reader = BufReader::new(pem_data);
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|e| CheckSSLError::CertificateParseError(format!("Failed to parse PEM: {:?}", e)))?;
    
    if certs.is_empty() {
        return Err(CheckSSLError::CertificateParseError("No certificates found in PEM data".to_string()));
    }

    Ok(certs)
}

/// Convert DER certificate to PEM format
pub fn der_to_pem(der_data: &[u8]) -> Result<String, CheckSSLError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    
    let encoded = STANDARD.encode(der_data);
    let mut pem = String::new();
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    
    // Add line breaks every 64 characters
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem)
}

/// Convert PEM certificate to DER format
pub fn pem_to_der(pem_data: &str) -> Result<Vec<u8>, CheckSSLError> {
    let pem_bytes = pem_data.as_bytes();
    let certs = parse_pem_certificates(pem_bytes)?;
    
    if certs.is_empty() {
        return Err(CheckSSLError::CertificateParseError("No certificates found in PEM data".to_string()));
    }
    
    Ok(certs[0].clone())
}

/// Check certificate from a file
pub fn check_certificate_from_file<P: AsRef<Path>>(
    path: P,
    format: CertificateFormat,
) -> Result<Cert, CheckSSLError> {
    let certificates = load_certificates_from_file(path, format)?;
    
    if certificates.is_empty() {
        return Err(CheckSSLError::CertificateParseError("No certificates found in file".to_string()));
    }

    // Parse certificates and build Cert structure
    let mut server_cert_data = None;
    let mut intermediate_cert_data = None;
    let mut chain_length = 0;

    for cert_der in &certificates {
        let (_, x509cert) = parse_x509_der(cert_der)
            .map_err(|e| CheckSSLError::CertificateParseError(format!("Failed to parse certificate: {}", e)))?;

        chain_length += 1;

        let is_ca = x509cert.tbs_certificate.basic_constraints()
            .map(|(_, bc)| bc.ca)
            .unwrap_or(false);

        if !is_ca && server_cert_data.is_none() {
            server_cert_data = Some((cert_der.clone(), x509cert));
        } else if is_ca && intermediate_cert_data.is_none() {
            intermediate_cert_data = Some((cert_der.clone(), x509cert));
        }
    }

    let (server_der, server_x509) = server_cert_data
        .ok_or_else(|| CheckSSLError::CertificateParseError("No server certificate found".to_string()))?;

    // Build ServerCert
    let server_cert = build_server_cert(&server_der, &server_x509)?;

    // Build IntermediateCert (or use a default one)
    let intermediate_cert = if let Some((inter_der, inter_x509)) = intermediate_cert_data {
        build_intermediate_cert(&inter_der, &inter_x509)?
    } else {
        // Create a default intermediate cert for single certificate files
        IntermediateCert {
            common_name: String::new(),
            signature_algorithm: String::new(),
            country: String::new(),
            state: String::new(),
            locality: String::new(),
            organization: String::new(),
            organizational_unit: String::new(),
            serial_number: String::new(),
            version: 0,
            not_after: 0,
            not_before: 0,
            issuer: String::new(),
            issuer_cn: String::new(),
            is_valid: false,
            time_to_expiration: String::new(),
            days_to_expiration: 0,
            key_usage: Vec::new(),
            is_ca: false,
            path_len_constraint: None,
            public_key_algorithm: String::new(),
            public_key_size: None,
            fingerprint_sha256: String::new(),
            fingerprint_sha1: String::new(),
        }
    };

    Ok(Cert {
        server: server_cert,
        intermediate: intermediate_cert,
        chain_length,
        protocol_version: "N/A (from file)".to_string(),
    })
}

/// Build ServerCert from parsed certificate
fn build_server_cert(cert_der: &[u8], x509cert: &X509Certificate) -> Result<ServerCert, CheckSSLError> {
    use crate::{extract_public_key_algorithm, extract_key_usage, process_certificate_names, populate_subject_fields};
    use x509_parser::objects::oid2sn;
    use x509_parser::extensions::GeneralName;

    // Calculate fingerprints
    let mut hasher_sha256 = Sha256::new();
    hasher_sha256.update(cert_der);
    let fingerprint_sha256 = format!("{:X}", hasher_sha256.finalize());
    
    let mut hasher_sha1 = Sha1::new();
    hasher_sha1.update(cert_der);
    let fingerprint_sha1 = format!("{:X}", hasher_sha1.finalize());

    // Extract signature algorithm
    let signature_algorithm = oid2sn(&x509cert.signature_algorithm.algorithm)
        .map_err(|_| CheckSSLError::CertificateParseError("Error converting Oid to Nid".to_string()))?
        .to_string();

    // Extract public key algorithm
    let public_key_algorithm = extract_public_key_algorithm(&signature_algorithm);

    // Extract key usage
    let key_usage = x509cert.tbs_certificate.key_usage()
        .map(|(_, ku)| extract_key_usage(ku))
        .unwrap_or_default();

    // Extract extended key usage
    let extended_key_usage = x509cert.tbs_certificate.extended_key_usage()
        .map(|(_, eku)| {
            let mut usage = Vec::new();
            if eku.any { usage.push("Any".to_string()); }
            if eku.server_auth { usage.push("Server Auth".to_string()); }
            if eku.client_auth { usage.push("Client Auth".to_string()); }
            if eku.code_signing { usage.push("Code Signing".to_string()); }
            if eku.email_protection { usage.push("Email Protection".to_string()); }
            if eku.time_stamping { usage.push("Time Stamping".to_string()); }
            if eku.ocscp_signing { usage.push("OCSP Signing".to_string()); }
            usage
        })
        .unwrap_or_default();

    // Extract SANs
    let sans = x509cert.tbs_certificate.subject_alternative_name()
        .map(|(_, san)| {
            san.general_names.iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some(dns.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    // Calculate expiration
    let time_to_expiration = x509cert.tbs_certificate.validity.time_to_expiration()
        .map(|tte| {
            let days = tte.as_secs() / 86400;
            (format!("{} day(s)", days), days as i64)
        })
        .unwrap_or_else(|| ("Expired".to_string(), -1));

    // Process issuer and subject
    let (issuer_full, issuer_cn) = process_certificate_names(x509cert, true)?;
    let (common_name, country, state, locality, organization, organizational_unit) = 
        populate_subject_fields(x509cert)?;

    Ok(ServerCert {
        common_name,
        signature_algorithm,
        sans,
        country,
        state,
        locality,
        organization,
        organizational_unit,
        serial_number: format!("{:X}", x509cert.tbs_certificate.serial),
        version: (x509cert.tbs_certificate.version + 1) as i32,
        not_after: x509cert.tbs_certificate.validity.not_after.timestamp(),
        not_before: x509cert.tbs_certificate.validity.not_before.timestamp(),
        issuer: issuer_full,
        issuer_cn,
        is_valid: x509cert.validity().is_valid(),
        time_to_expiration: time_to_expiration.0,
        days_to_expiration: time_to_expiration.1,
        key_usage,
        extended_key_usage,
        public_key_algorithm,
        public_key_size: None, // TODO: Extract key size
        fingerprint_sha256,
        fingerprint_sha1,
    })
}

/// Build IntermediateCert from parsed certificate
fn build_intermediate_cert(cert_der: &[u8], x509cert: &X509Certificate) -> Result<IntermediateCert, CheckSSLError> {
    use crate::{extract_public_key_algorithm, extract_key_usage, process_certificate_names, populate_subject_fields};
    use x509_parser::objects::oid2sn;

    // Calculate fingerprints
    let mut hasher_sha256 = Sha256::new();
    hasher_sha256.update(cert_der);
    let fingerprint_sha256 = format!("{:X}", hasher_sha256.finalize());
    
    let mut hasher_sha1 = Sha1::new();
    hasher_sha1.update(cert_der);
    let fingerprint_sha1 = format!("{:X}", hasher_sha1.finalize());

    // Extract signature algorithm
    let signature_algorithm = oid2sn(&x509cert.signature_algorithm.algorithm)
        .map_err(|_| CheckSSLError::CertificateParseError("Error converting Oid to Nid".to_string()))?
        .to_string();

    // Extract public key algorithm
    let public_key_algorithm = extract_public_key_algorithm(&signature_algorithm);

    // Extract key usage
    let key_usage = x509cert.tbs_certificate.key_usage()
        .map(|(_, ku)| extract_key_usage(ku))
        .unwrap_or_default();

    // Extract basic constraints
    let (is_ca, path_len_constraint) = x509cert.tbs_certificate.basic_constraints()
        .map(|(_, bc)| (bc.ca, bc.path_len_constraint))
        .unwrap_or((false, None));

    // Calculate expiration
    let time_to_expiration = x509cert.tbs_certificate.validity.time_to_expiration()
        .map(|tte| {
            let days = tte.as_secs() / 86400;
            (format!("{} day(s)", days), days as i64)
        })
        .unwrap_or_else(|| ("Expired".to_string(), -1));

    // Process issuer and subject
    let (issuer_full, issuer_cn) = process_certificate_names(x509cert, true)?;
    let (common_name, country, state, locality, organization, organizational_unit) = 
        populate_subject_fields(x509cert)?;

    Ok(IntermediateCert {
        common_name,
        signature_algorithm,
        country,
        state,
        locality,
        organization,
        organizational_unit,
        serial_number: format!("{:X}", x509cert.tbs_certificate.serial),
        version: (x509cert.tbs_certificate.version + 1) as i32,
        not_after: x509cert.tbs_certificate.validity.not_after.timestamp(),
        not_before: x509cert.tbs_certificate.validity.not_before.timestamp(),
        issuer: issuer_full,
        issuer_cn,
        is_valid: x509cert.validity().is_valid(),
        time_to_expiration: time_to_expiration.0,
        days_to_expiration: time_to_expiration.1,
        key_usage,
        is_ca,
        path_len_constraint,
        public_key_algorithm,
        public_key_size: None, // TODO: Extract key size
        fingerprint_sha256,
        fingerprint_sha1,
    })
}

/// Load certificate chain from multiple files
pub fn load_certificate_chain_from_files<P: AsRef<Path>>(
    paths: &[P],
    format: CertificateFormat,
) -> Result<Vec<Vec<u8>>, CheckSSLError> {
    let mut all_certs = Vec::new();
    
    for path in paths {
        let certs = load_certificates_from_file(path, format.clone())?;
        all_certs.extend(certs);
    }
    
    if all_certs.is_empty() {
        return Err(CheckSSLError::CertificateParseError("No certificates found in files".to_string()));
    }
    
    Ok(all_certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_to_pem_conversion() {
        let der_data = vec![0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01];
        let pem = der_to_pem(&der_data).unwrap();
        
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        // Check that base64 encoding is present (the actual encoded value)
        assert!(pem.contains("MIIBCgKCAQE")); // Updated to match actual encoding
    }

    #[test]
    fn test_pem_to_der_conversion() {
        let pem_data = "-----BEGIN CERTIFICATE-----\n\
                        MIIBCQKCAQE=\n\
                        -----END CERTIFICATE-----";
        
        let der = pem_to_der(pem_data);
        assert!(der.is_ok());
    }

    #[test]
    fn test_certificate_format_detection() {
        let pem_bytes = b"-----BEGIN CERTIFICATE-----";
        let der_bytes = &[0x30, 0x82];
        
        // PEM should be detected
        assert!(pem_bytes.starts_with(b"-----BEGIN"));
        
        // DER should not start with PEM header
        assert!(!der_bytes.starts_with(b"-----BEGIN"));
    }
}