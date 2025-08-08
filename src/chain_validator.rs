use crate::error::CheckSSLError;
use x509_parser::{parse_x509_der, x509::X509Certificate};
use std::collections::HashSet;

pub struct ChainValidator {
    certificates: Vec<Vec<u8>>,
}

impl ChainValidator {
    pub fn new(certificates: Vec<Vec<u8>>) -> Self {
        ChainValidator { certificates }
    }

    pub fn validate_chain(&self) -> Result<ChainValidationResult, CheckSSLError> {
        if self.certificates.is_empty() {
            return Err(CheckSSLError::ChainValidationError(
                "Certificate chain is empty".to_string(),
            ));
        }

        let mut parsed_certs = Vec::new();
        for cert_der in &self.certificates {
            match parse_x509_der(cert_der) {
                Ok((_, cert)) => parsed_certs.push(cert),
                Err(e) => {
                    return Err(CheckSSLError::CertificateParseError(format!(
                        "Failed to parse certificate in chain: {}",
                        e
                    )))
                }
            }
        }

        let mut validation_result = ChainValidationResult {
            is_valid: true,
            chain_length: parsed_certs.len(),
            issues: Vec::new(),
            path: Vec::new(),
        };

        // Check each certificate's validity period
        for (i, cert) in parsed_certs.iter().enumerate() {
            validation_result.path.push(CertificateInfo {
                subject: cert.subject().to_string(),
                issuer: cert.issuer().to_string(),
                is_ca: self.is_ca_certificate(cert),
                position: i,
            });

            if !cert.validity().is_valid() {
                validation_result.issues.push(format!(
                    "Certificate at position {} is expired or not yet valid",
                    i
                ));
                validation_result.is_valid = false;
            }
        }

        // Validate chain relationships
        for i in 0..parsed_certs.len() - 1 {
            let cert = &parsed_certs[i];
            let issuer_cert = &parsed_certs[i + 1];

            // Check if the issuer of current cert matches the subject of next cert
            if cert.issuer() != issuer_cert.subject() {
                validation_result.issues.push(format!(
                    "Chain broken at position {}: issuer mismatch",
                    i
                ));
                validation_result.is_valid = false;
            }

            // Check if the issuer certificate is a CA
            if !self.is_ca_certificate(issuer_cert) {
                validation_result.issues.push(format!(
                    "Certificate at position {} is not a CA certificate but is used as issuer",
                    i + 1
                ));
                validation_result.is_valid = false;
            }

            // Check path length constraints
            if let Some(path_len) = self.get_path_length_constraint(issuer_cert) {
                let remaining_path = parsed_certs.len() - i - 2;
                if remaining_path > path_len as usize {
                    validation_result.issues.push(format!(
                        "Path length constraint violated at position {}: constraint is {} but {} certificates remain",
                        i + 1, path_len, remaining_path
                    ));
                    validation_result.is_valid = false;
                }
            }
        }

        // Check for self-signed root
        if let Some(last_cert) = parsed_certs.last() {
            if last_cert.issuer() == last_cert.subject() {
                validation_result.path.last_mut().unwrap().is_ca = true;
            } else {
                validation_result.issues.push(
                    "Chain does not end with a self-signed root certificate".to_string(),
                );
            }
        }

        // Check key usage
        self.validate_key_usage(&parsed_certs, &mut validation_result);

        // Check for duplicate certificates
        self.check_duplicates(&parsed_certs, &mut validation_result);

        Ok(validation_result)
    }

    fn is_ca_certificate(&self, cert: &X509Certificate) -> bool {
        cert.tbs_certificate
            .basic_constraints()
            .map(|(_, bc)| bc.ca)
            .unwrap_or(false)
    }

    fn get_path_length_constraint(&self, cert: &X509Certificate) -> Option<u32> {
        cert.tbs_certificate
            .basic_constraints()
            .and_then(|(_, bc)| bc.path_len_constraint)
    }

    fn validate_key_usage(
        &self,
        certs: &[X509Certificate],
        result: &mut ChainValidationResult,
    ) {
        // Check server certificate (first in chain)
        if let Some(server_cert) = certs.first() {
            if let Some((_, ku)) = server_cert.tbs_certificate.key_usage() {
                if !ku.digital_signature() && !ku.key_encipherment() && !ku.key_agreement() {
                    result.issues.push(
                        "Server certificate lacks required key usage for TLS".to_string(),
                    );
                    result.is_valid = false;
                }
            }
        }

        // Check CA certificates
        for (i, cert) in certs.iter().enumerate().skip(1) {
            if self.is_ca_certificate(cert) {
                if let Some((_, ku)) = cert.tbs_certificate.key_usage() {
                    if !ku.key_cert_sign() {
                        result.issues.push(format!(
                            "CA certificate at position {} lacks key_cert_sign usage",
                            i
                        ));
                        result.is_valid = false;
                    }
                }
            }
        }
    }

    fn check_duplicates(
        &self,
        certs: &[X509Certificate],
        result: &mut ChainValidationResult,
    ) {
        let mut seen_serials = HashSet::new();
        for (i, cert) in certs.iter().enumerate() {
            let serial = format!("{:X}", cert.tbs_certificate.serial);
            if !seen_serials.insert(serial.clone()) {
                result.issues.push(format!(
                    "Duplicate certificate found at position {} (serial: {})",
                    i, serial
                ));
                result.is_valid = false;
            }
        }
    }

    pub fn verify_hostname(&self, hostname: &str) -> Result<bool, CheckSSLError> {
        if self.certificates.is_empty() {
            return Err(CheckSSLError::ChainValidationError(
                "No certificates to verify".to_string(),
            ));
        }

        let cert_der = &self.certificates[0];
        let (_, cert) = parse_x509_der(cert_der).map_err(|e| {
            CheckSSLError::CertificateParseError(format!("Failed to parse certificate: {}", e))
        })?;

        // Check Common Name
        for rdn in &cert.subject().rdn_seq {
            for attr in &rdn.set {
                if let Ok(oid_str) = x509_parser::objects::oid2sn(&attr.attr_type) {
                    if oid_str == "CN" {
                        if let Ok(cn) = attr.attr_value.content.as_str() {
                            if self.matches_hostname(cn, hostname) {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        // Check Subject Alternative Names
        if let Some((_, san_ext)) = cert.tbs_certificate.subject_alternative_name() {
            for name in &san_ext.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns_name) = name {
                    if self.matches_hostname(dns_name, hostname) {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    fn matches_hostname(&self, pattern: &str, hostname: &str) -> bool {
        // Handle wildcard certificates
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            if let Some(hostname_suffix) = hostname.split('.').skip(1).next() {
                return suffix.eq_ignore_ascii_case(hostname_suffix);
            }
        }
        
        pattern.eq_ignore_ascii_case(hostname)
    }
}

#[derive(Debug, Clone)]
pub struct ChainValidationResult {
    pub is_valid: bool,
    pub chain_length: usize,
    pub issues: Vec<String>,
    pub path: Vec<CertificateInfo>,
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub is_ca: bool,
    pub position: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain_validation() {
        let validator = ChainValidator::new(vec![]);
        let result = validator.validate_chain();
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_matching() {
        let validator = ChainValidator::new(vec![]);
        
        assert!(validator.matches_hostname("example.com", "example.com"));
        assert!(validator.matches_hostname("EXAMPLE.COM", "example.com"));
        assert!(validator.matches_hostname("*.example.com", "www.example.com"));
        assert!(!validator.matches_hostname("*.example.com", "example.com"));
        assert!(!validator.matches_hostname("example.com", "notexample.com"));
        assert!(!validator.matches_hostname("*.example.com", "sub.www.example.com"));
    }
}