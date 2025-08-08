//! OCSP (Online Certificate Status Protocol) support.
//!
//! This module provides functionality to check certificate revocation status
//! using OCSP responders.

use crate::error::CheckSSLError;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use sha1::Digest;

/// OCSP response status
#[derive(Debug, Clone, PartialEq)]
pub enum OcspStatus {
    /// Certificate is valid and not revoked
    Good,
    /// Certificate has been revoked
    Revoked {
        revocation_time: i64,
        reason: RevocationReason,
    },
    /// Certificate status is unknown
    Unknown,
}

/// Reasons for certificate revocation
#[derive(Debug, Clone, PartialEq)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CACompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCRL,
    PrivilegeWithdrawn,
    AACompromise,
}

impl From<u8> for RevocationReason {
    fn from(value: u8) -> Self {
        match value {
            1 => RevocationReason::KeyCompromise,
            2 => RevocationReason::CACompromise,
            3 => RevocationReason::AffiliationChanged,
            4 => RevocationReason::Superseded,
            5 => RevocationReason::CessationOfOperation,
            6 => RevocationReason::CertificateHold,
            8 => RevocationReason::RemoveFromCRL,
            9 => RevocationReason::PrivilegeWithdrawn,
            10 => RevocationReason::AACompromise,
            _ => RevocationReason::Unspecified,
        }
    }
}

/// OCSP request builder
pub struct OcspRequest {
    cert_der: Vec<u8>,
    issuer_der: Vec<u8>,
    responder_url: Option<String>,
}

impl OcspRequest {
    /// Create a new OCSP request
    pub fn new(cert_der: Vec<u8>, issuer_der: Vec<u8>) -> Self {
        OcspRequest {
            cert_der,
            issuer_der,
            responder_url: None,
        }
    }

    /// Set the OCSP responder URL
    pub fn with_responder_url(mut self, url: String) -> Self {
        self.responder_url = Some(url);
        self
    }

    /// Extract OCSP responder URL from certificate
    pub fn extract_responder_url(&mut self) -> Result<String, CheckSSLError> {
        // Parse certificate to find OCSP responder URL in Authority Information Access extension
        let (_, cert) = x509_parser::parse_x509_der(&self.cert_der)
            .map_err(|e| CheckSSLError::CertificateParseError(format!("Failed to parse certificate: {}", e)))?;

        // Look for Authority Information Access extension
        for (oid, ext) in cert.tbs_certificate.extensions.iter() {
            // AIA OID is 1.3.6.1.5.5.7.1.1
            if oid.to_string() == "1.3.6.1.5.5.7.1.1" {
                // Parse the extension to find OCSP URL
                // This is a simplified version - real implementation would need proper ASN.1 parsing
                let data = String::from_utf8_lossy(&ext.value);
                if let Some(start) = data.find("http://") {
                    let url_bytes = &data.as_bytes()[start..];
                    if let Some(end) = url_bytes.iter().position(|&b| b < 32 || b > 126) {
                        let url = String::from_utf8_lossy(&url_bytes[..end]).to_string();
                        self.responder_url = Some(url.clone());
                        return Ok(url);
                    }
                } else if let Some(start) = data.find("https://") {
                    let url_bytes = &data.as_bytes()[start..];
                    if let Some(end) = url_bytes.iter().position(|&b| b < 32 || b > 126) {
                        let url = String::from_utf8_lossy(&url_bytes[..end]).to_string();
                        self.responder_url = Some(url.clone());
                        return Ok(url);
                    }
                }
            }
        }

        Err(CheckSSLError::ValidationError("No OCSP responder URL found in certificate".to_string()))
    }

    /// Build the OCSP request bytes
    fn build_request_bytes(&self) -> Result<Vec<u8>, CheckSSLError> {
        // This is a simplified OCSP request builder
        // A full implementation would use proper ASN.1 encoding
        
        // Parse certificates to get serial number and issuer info
        let (_, cert) = x509_parser::parse_x509_der(&self.cert_der)
            .map_err(|e| CheckSSLError::CertificateParseError(format!("Failed to parse certificate: {}", e)))?;
        
        let (_, issuer) = x509_parser::parse_x509_der(&self.issuer_der)
            .map_err(|e| CheckSSLError::CertificateParseError(format!("Failed to parse issuer: {}", e)))?;

        // Create a basic OCSP request structure
        // In production, use a proper ASN.1 library
        let mut request = Vec::new();
        
        // OCSP Request header (simplified)
        request.extend_from_slice(&[0x30, 0x82]); // SEQUENCE
        
        // Add placeholder length (will be updated later)
        let len_pos = request.len();
        request.extend_from_slice(&[0x00, 0x00]);
        
        // Version
        request.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x00]);
        
        // Request list
        request.extend_from_slice(&[0x30, 0x82]);
        let _req_len_pos = request.len();
        request.extend_from_slice(&[0x00, 0x00]);
        
        // Single request
        request.extend_from_slice(&[0x30, 0x82]);
        let _single_len_pos = request.len();
        request.extend_from_slice(&[0x00, 0x00]);
        
        // CertID
        request.extend_from_slice(&[0x30, 0x82]);
        let _certid_len_pos = request.len();
        request.extend_from_slice(&[0x00, 0x00]);
        
        // Hash algorithm (SHA-1)
        request.extend_from_slice(&[0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00]);
        
        // Issuer name hash (20 bytes for SHA-1)
        request.extend_from_slice(&[0x04, 0x14]);
        let issuer_name_hash = sha1::Sha1::digest(issuer.tbs_certificate.subject.as_raw());
        request.extend_from_slice(&issuer_name_hash);
        
        // Issuer key hash (20 bytes for SHA-1)
        request.extend_from_slice(&[0x04, 0x14]);
        let issuer_key = &issuer.tbs_certificate.subject_pki.subject_public_key.data;
        let issuer_key_hash = sha1::Sha1::digest(issuer_key);
        request.extend_from_slice(&issuer_key_hash);
        
        // Serial number
        let serial = cert.tbs_certificate.serial.to_bytes_be();
        request.extend_from_slice(&[0x02, serial.len() as u8]);
        request.extend_from_slice(&serial);
        
        // Update lengths
        let total_len = request.len() - 4;
        request[len_pos] = ((total_len >> 8) & 0xff) as u8;
        request[len_pos + 1] = (total_len & 0xff) as u8;
        
        Ok(request)
    }

    /// Send OCSP request and get response
    pub fn send_request(&self, timeout: Duration) -> Result<OcspResponse, CheckSSLError> {
        let url = self.responder_url.as_ref()
            .ok_or_else(|| CheckSSLError::ValidationError("No OCSP responder URL set".to_string()))?;

        let request_bytes = self.build_request_bytes()?;
        
        // Parse URL to get host and path
        let (host, path) = parse_url(url)?;
        
        // Create HTTP POST request
        let http_request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/ocsp-request\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            path, host, request_bytes.len()
        );

        // Connect to OCSP responder
        let mut stream = TcpStream::connect_timeout(
            &format!("{}:80", host).parse().map_err(|e| {
                CheckSSLError::NetworkError(format!("Invalid address: {}", e))
            })?,
            timeout
        ).map_err(|e| CheckSSLError::NetworkError(format!("Failed to connect to OCSP responder: {}", e)))?;

        // Send request
        stream.write_all(http_request.as_bytes())
            .map_err(|e| CheckSSLError::NetworkError(format!("Failed to send request: {}", e)))?;
        stream.write_all(&request_bytes)
            .map_err(|e| CheckSSLError::NetworkError(format!("Failed to send request body: {}", e)))?;

        // Read response
        let mut response = Vec::new();
        stream.read_to_end(&mut response)
            .map_err(|e| CheckSSLError::NetworkError(format!("Failed to read response: {}", e)))?;

        // Parse HTTP response to extract OCSP response
        let ocsp_response = extract_ocsp_response(&response)?;
        
        Ok(OcspResponse::new(ocsp_response))
    }
}

/// OCSP response wrapper
pub struct OcspResponse {
    data: Vec<u8>,
}

impl OcspResponse {
    /// Create new OCSP response from bytes
    pub fn new(data: Vec<u8>) -> Self {
        OcspResponse { data }
    }

    /// Parse the OCSP response to get certificate status
    pub fn get_status(&self) -> Result<OcspStatus, CheckSSLError> {
        // Simplified OCSP response parsing
        // In production, use proper ASN.1 parsing
        
        // Check for successful response (0x00)
        if self.data.len() < 10 {
            return Err(CheckSSLError::ValidationError("Invalid OCSP response".to_string()));
        }

        // Look for response status
        // This is a very simplified check - real implementation needs proper parsing
        let good_pattern = [0x80, 0x00];
        let revoked_pattern = [0x80, 0x01];
        
        if self.data.windows(2).any(|w| w == good_pattern) {
            // Good status
            Ok(OcspStatus::Good)
        } else if self.data.windows(2).any(|w| w == revoked_pattern) {
            // Revoked status
            Ok(OcspStatus::Revoked {
                revocation_time: 0, // Would need to parse actual time
                reason: RevocationReason::Unspecified,
            })
        } else {
            // Unknown status
            Ok(OcspStatus::Unknown)
        }
    }

    /// Get the raw response bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Parse URL to extract host and path
fn parse_url(url: &str) -> Result<(String, String), CheckSSLError> {
    let url = url.trim_start_matches("http://").trim_start_matches("https://");
    let parts: Vec<&str> = url.splitn(2, '/').collect();
    
    let host = parts[0].to_string();
    let path = if parts.len() > 1 {
        format!("/{}", parts[1])
    } else {
        "/".to_string()
    };
    
    Ok((host, path))
}

/// Extract OCSP response from HTTP response
fn extract_ocsp_response(http_response: &[u8]) -> Result<Vec<u8>, CheckSSLError> {
    // Find the end of HTTP headers
    let header_end = b"\r\n\r\n";
    if let Some(pos) = http_response.windows(4).position(|w| w == header_end) {
        Ok(http_response[pos + 4..].to_vec())
    } else {
        Err(CheckSSLError::ValidationError("Invalid HTTP response".to_string()))
    }
}

/// Check certificate revocation status using OCSP
pub fn check_ocsp_status(
    cert_der: Vec<u8>,
    issuer_der: Vec<u8>,
    timeout: Duration,
) -> Result<OcspStatus, CheckSSLError> {
    let mut request = OcspRequest::new(cert_der, issuer_der);
    
    // Try to extract OCSP URL from certificate
    request.extract_responder_url()?;
    
    // Send request and get response
    let response = request.send_request(timeout)?;
    
    // Parse response to get status
    response.get_status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_reason_from_u8() {
        assert_eq!(RevocationReason::from(1), RevocationReason::KeyCompromise);
        assert_eq!(RevocationReason::from(2), RevocationReason::CACompromise);
        assert_eq!(RevocationReason::from(99), RevocationReason::Unspecified);
    }

    #[test]
    fn test_parse_url() {
        let (host, path) = parse_url("http://ocsp.example.com/check").unwrap();
        assert_eq!(host, "ocsp.example.com");
        assert_eq!(path, "/check");

        let (host, path) = parse_url("https://ocsp.example.com").unwrap();
        assert_eq!(host, "ocsp.example.com");
        assert_eq!(path, "/");
    }

    #[test]
    fn test_ocsp_request_creation() {
        let cert_der = vec![0x30, 0x82]; // Dummy certificate
        let issuer_der = vec![0x30, 0x82]; // Dummy issuer
        
        let request = OcspRequest::new(cert_der, issuer_der);
        assert!(request.responder_url.is_none());
        
        let request = request.with_responder_url("http://ocsp.example.com".to_string());
        assert_eq!(request.responder_url, Some("http://ocsp.example.com".to_string()));
    }
}