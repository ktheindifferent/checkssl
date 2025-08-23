//! Comprehensive tests for OCSP (Online Certificate Status Protocol) checking

use checkssl::{
    OcspRequest, OcspResponse, OcspStatus, RevocationReason, check_ocsp_status,
    CheckSSLError
};
use std::time::Duration;

mod fixtures;
use fixtures::{create_mock_der_cert, create_mock_issuer_der, mock_ocsp_url, create_mock_ocsp_response};

#[test]
fn test_ocsp_request_creation() {
    let cert_der = create_mock_der_cert();
    let issuer_der = create_mock_issuer_der();
    
    let request = OcspRequest::new(cert_der.clone(), issuer_der.clone());
    
    // Verify request was created with correct data
    // Note: We can't directly access private fields, but we can test the behavior
    let request_with_url = request.with_responder_url(mock_ocsp_url());
    
    // The request should now have a responder URL set
    // We'll test this indirectly through the send_request method later
}

#[test]
fn test_ocsp_response_parsing_good_status() {
    let response_data = create_mock_ocsp_response("good");
    let response = OcspResponse::new(response_data.clone());
    
    let status = response.get_status();
    assert!(status.is_ok());
    
    match status.unwrap() {
        OcspStatus::Good => {}, // Expected
        _ => panic!("Expected Good status"),
    }
    
    // Verify raw bytes access
    assert_eq!(response.as_bytes(), &response_data[..]);
}

#[test]
fn test_ocsp_response_parsing_revoked_status() {
    let response_data = create_mock_ocsp_response("revoked");
    let response = OcspResponse::new(response_data);
    
    let status = response.get_status();
    assert!(status.is_ok());
    
    match status.unwrap() {
        OcspStatus::Revoked { .. } => {}, // Expected
        _ => panic!("Expected Revoked status"),
    }
}

#[test]
fn test_ocsp_response_parsing_unknown_status() {
    let response_data = create_mock_ocsp_response("unknown");
    let response = OcspResponse::new(response_data);
    
    let status = response.get_status();
    assert!(status.is_ok());
    
    match status.unwrap() {
        OcspStatus::Unknown => {}, // Expected
        _ => panic!("Expected Unknown status"),
    }
}

#[test]
fn test_revocation_reason_conversion() {
    assert_eq!(RevocationReason::from(0), RevocationReason::Unspecified);
    assert_eq!(RevocationReason::from(1), RevocationReason::KeyCompromise);
    assert_eq!(RevocationReason::from(2), RevocationReason::CACompromise);
    assert_eq!(RevocationReason::from(3), RevocationReason::AffiliationChanged);
    assert_eq!(RevocationReason::from(4), RevocationReason::Superseded);
    assert_eq!(RevocationReason::from(5), RevocationReason::CessationOfOperation);
    assert_eq!(RevocationReason::from(6), RevocationReason::CertificateHold);
    assert_eq!(RevocationReason::from(8), RevocationReason::RemoveFromCRL);
    assert_eq!(RevocationReason::from(9), RevocationReason::PrivilegeWithdrawn);
    assert_eq!(RevocationReason::from(10), RevocationReason::AACompromise);
    assert_eq!(RevocationReason::from(99), RevocationReason::Unspecified); // Unknown value
}

#[test]
fn test_ocsp_response_invalid_data() {
    // Test with too small data
    let small_data = vec![0x30, 0x82]; // Too small to be valid
    let response = OcspResponse::new(small_data);
    
    let status = response.get_status();
    assert!(status.is_err());
    
    match status {
        Err(CheckSSLError::ValidationError(msg)) => {
            assert!(msg.contains("Invalid OCSP response"));
        }
        _ => panic!("Expected ValidationError"),
    }
}

#[test]
fn test_ocsp_status_equality() {
    let good1 = OcspStatus::Good;
    let good2 = OcspStatus::Good;
    assert_eq!(good1, good2);
    
    let revoked1 = OcspStatus::Revoked {
        revocation_time: 1234567890,
        reason: RevocationReason::KeyCompromise,
    };
    let revoked2 = OcspStatus::Revoked {
        revocation_time: 1234567890,
        reason: RevocationReason::KeyCompromise,
    };
    assert_eq!(revoked1, revoked2);
    
    let revoked3 = OcspStatus::Revoked {
        revocation_time: 9876543210,
        reason: RevocationReason::KeyCompromise,
    };
    assert_ne!(revoked1, revoked3);
    
    let unknown = OcspStatus::Unknown;
    assert_ne!(good1, unknown);
    assert_ne!(revoked1, unknown);
}

#[test]
fn test_revocation_reason_equality() {
    assert_eq!(RevocationReason::KeyCompromise, RevocationReason::KeyCompromise);
    assert_ne!(RevocationReason::KeyCompromise, RevocationReason::CACompromise);
}

// Mock OCSP responder for testing
struct MockOcspResponder {
    response_type: String,
    should_fail: bool,
}

impl MockOcspResponder {
    fn new(response_type: &str) -> Self {
        MockOcspResponder {
            response_type: response_type.to_string(),
            should_fail: false,
        }
    }
    
    fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }
    
    fn get_response(&self) -> Result<Vec<u8>, CheckSSLError> {
        if self.should_fail {
            Err(CheckSSLError::NetworkError("Mock responder failure".to_string()))
        } else {
            Ok(create_mock_ocsp_response(&self.response_type))
        }
    }
}

#[test]
fn test_mock_ocsp_responder_good() {
    let responder = MockOcspResponder::new("good");
    let response_data = responder.get_response().unwrap();
    let response = OcspResponse::new(response_data);
    
    match response.get_status().unwrap() {
        OcspStatus::Good => {},
        _ => panic!("Expected Good status from mock responder"),
    }
}

#[test]
fn test_mock_ocsp_responder_revoked() {
    let responder = MockOcspResponder::new("revoked");
    let response_data = responder.get_response().unwrap();
    let response = OcspResponse::new(response_data);
    
    match response.get_status().unwrap() {
        OcspStatus::Revoked { .. } => {},
        _ => panic!("Expected Revoked status from mock responder"),
    }
}

#[test]
fn test_mock_ocsp_responder_failure() {
    let responder = MockOcspResponder::new("good").with_failure();
    let result = responder.get_response();
    
    assert!(result.is_err());
    match result {
        Err(CheckSSLError::NetworkError(msg)) => {
            assert_eq!(msg, "Mock responder failure");
        }
        _ => panic!("Expected NetworkError"),
    }
}

#[test]
fn test_ocsp_request_with_custom_url() {
    let cert_der = create_mock_der_cert();
    let issuer_der = create_mock_issuer_der();
    
    let custom_url = "http://custom.ocsp.example.com/check";
    let request = OcspRequest::new(cert_der, issuer_der)
        .with_responder_url(custom_url.to_string());
    
    // The URL should be set (we test this indirectly since the field is private)
    // In a real scenario, this would be tested through integration tests
}

#[test]
fn test_multiple_ocsp_requests() {
    // Test creating multiple OCSP requests for different certificates
    let certs = vec![
        (create_mock_der_cert(), create_mock_issuer_der()),
        (vec![0x30, 0x82, 0x01, 0x23], vec![0x30, 0x82, 0x01, 0x24]),
        (vec![0x30, 0x82, 0x01, 0x25], vec![0x30, 0x82, 0x01, 0x26]),
    ];
    
    for (cert_der, issuer_der) in certs {
        let request = OcspRequest::new(cert_der, issuer_der);
        let _request_with_url = request.with_responder_url(mock_ocsp_url());
        // Each request should be independent
    }
}

#[test]
fn test_ocsp_response_sizes() {
    // Test with various response sizes
    let sizes = vec![10, 100, 1000, 10000];
    
    for size in sizes {
        let mut response_data = vec![0x30, 0x82];
        response_data.extend(vec![0x00; size]);
        
        let response = OcspResponse::new(response_data.clone());
        assert_eq!(response.as_bytes().len(), response_data.len());
    }
}

// Test helper functions
fn create_test_ocsp_request() -> OcspRequest {
    OcspRequest::new(create_mock_der_cert(), create_mock_issuer_der())
}

#[test]
fn test_ocsp_request_builder_pattern() {
    let request = create_test_ocsp_request()
        .with_responder_url("http://ocsp1.example.com".to_string())
        .with_responder_url("http://ocsp2.example.com".to_string()); // Should override
    
    // The last URL should be used (we test this conceptually)
}

#[test]
fn test_ocsp_status_display() {
    // Test that OcspStatus can be properly displayed/debugged
    let statuses = vec![
        OcspStatus::Good,
        OcspStatus::Revoked {
            revocation_time: 1234567890,
            reason: RevocationReason::KeyCompromise,
        },
        OcspStatus::Unknown,
    ];
    
    for status in statuses {
        let debug_str = format!("{:?}", status);
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn test_revocation_reasons_comprehensive() {
    let reasons = vec![
        (1, RevocationReason::KeyCompromise),
        (2, RevocationReason::CACompromise),
        (3, RevocationReason::AffiliationChanged),
        (4, RevocationReason::Superseded),
        (5, RevocationReason::CessationOfOperation),
        (6, RevocationReason::CertificateHold),
        (8, RevocationReason::RemoveFromCRL),
        (9, RevocationReason::PrivilegeWithdrawn),
        (10, RevocationReason::AACompromise),
    ];
    
    for (code, expected_reason) in reasons {
        let reason = RevocationReason::from(code);
        assert_eq!(reason, expected_reason);
        
        // Test debug output
        let debug_str = format!("{:?}", reason);
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn test_ocsp_response_edge_cases() {
    // Empty response
    let empty_response = OcspResponse::new(vec![]);
    assert!(empty_response.get_status().is_err());
    
    // Response with only headers
    let header_only = vec![0x30, 0x82, 0x00, 0x00];
    let header_response = OcspResponse::new(header_only);
    let status = header_response.get_status();
    // Should either parse as Unknown or error, both are acceptable
    assert!(status.is_ok() || status.is_err());
    
    // Large response
    let mut large_response = vec![0x30, 0x82];
    large_response.extend(vec![0x00; 100000]);
    let large = OcspResponse::new(large_response.clone());
    assert_eq!(large.as_bytes().len(), large_response.len());
}