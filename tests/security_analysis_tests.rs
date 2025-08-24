//! Comprehensive tests for security analysis and weak cipher detection

use checkssl::{
    analyze_certificate, generate_security_report, CryptoAnalysis,
    SecurityLevel, SecurityIssue, IssueCategory,
    Cert, ServerCert, IntermediateCert
};

mod fixtures;
use fixtures::{create_mock_cert, create_weak_cert, create_cert_with_algorithm};

#[test]
fn test_weak_cipher_detection_md5() {
    let cert = create_cert_with_algorithm("MD5withRSA", 2048);
    let analysis = analyze_certificate(&cert);
    
    assert_eq!(analysis.security_level, SecurityLevel::Critical);
    assert!(analysis.issues.iter().any(|issue| {
        issue.category == IssueCategory::WeakSignatureAlgorithm &&
        issue.severity == SecurityLevel::Critical
    }));
    
    // Should recommend SHA256
    assert!(analysis.recommendations.iter().any(|rec| rec.contains("SHA256")));
}

#[test]
fn test_weak_cipher_detection_sha1() {
    let cert = create_cert_with_algorithm("SHA1withRSA", 2048);
    let analysis = analyze_certificate(&cert);
    
    assert!(analysis.security_level <= SecurityLevel::Weak);
    assert!(analysis.issues.iter().any(|issue| {
        issue.category == IssueCategory::WeakSignatureAlgorithm &&
        issue.severity == SecurityLevel::Weak
    }));
}

#[test]
fn test_protocol_version_checks() {
    // Test various protocol versions
    let mut cert = create_mock_cert("example.com", 90, true);
    
    // Test TLS 1.0 (should be considered weak)
    cert.protocol_version = "TLSv1.0".to_string();
    cert.server.signature_algorithm = "SHA1withRSA".to_string();
    let analysis = analyze_certificate(&cert);
    assert!(analysis.security_level <= SecurityLevel::Weak);
    
    // Test TLS 1.3 (should be strong)
    cert.protocol_version = "TLSv1.3".to_string();
    cert.server.signature_algorithm = "SHA384withECDSA".to_string();
    cert.server.public_key_algorithm = "EC".to_string();
    cert.server.public_key_size = Some(384);
    let analysis = analyze_certificate(&cert);
    assert!(analysis.details.signature_algorithm.security_level >= SecurityLevel::Strong);
}

#[test]
fn test_certificate_chain_validation() {
    let mut cert = create_mock_cert("example.com", 90, true);
    
    // Test chain with weak intermediate
    cert.intermediate.signature_algorithm = "MD5withRSA".to_string();
    let analysis = analyze_certificate(&cert);
    
    assert!(analysis.details.chain_analysis.weakest_link.is_some());
    assert!(analysis.details.chain_analysis.weakest_link.as_ref().unwrap().contains("MD5"));
    
    // Test chain with strong algorithms
    cert.server.signature_algorithm = "SHA256withRSA".to_string();
    cert.intermediate.signature_algorithm = "SHA256withRSA".to_string();
    let analysis = analyze_certificate(&cert);
    
    assert!(analysis.details.chain_analysis.weakest_link.is_none());
}

#[test]
fn test_small_key_size_detection() {
    // Test RSA with small key
    let cert = create_cert_with_algorithm("SHA256withRSA", 1024);
    let analysis = analyze_certificate(&cert);
    
    assert!(analysis.security_level <= SecurityLevel::Weak);
    assert!(analysis.issues.iter().any(|issue| {
        issue.category == IssueCategory::SmallKeySize
    }));
    
    // Test RSA with adequate key
    let cert = create_cert_with_algorithm("SHA256withRSA", 2048);
    let analysis = analyze_certificate(&cert);
    
    assert!(!analysis.issues.iter().any(|issue| {
        issue.category == IssueCategory::SmallKeySize
    }));
    
    // Test RSA with strong key
    let cert = create_cert_with_algorithm("SHA256withRSA", 4096);
    let analysis = analyze_certificate(&cert);
    
    assert_eq!(analysis.details.key_analysis.security_level, SecurityLevel::Strong);
}

#[test]
fn test_elliptic_curve_key_analysis() {
    // Test EC with various key sizes
    let mut cert = create_cert_with_algorithm("SHA256withECDSA", 224);
    cert.server.public_key_algorithm = "EC".to_string();
    let analysis = analyze_certificate(&cert);
    assert!(analysis.details.key_analysis.security_level <= SecurityLevel::Legacy);
    
    cert.server.public_key_size = Some(256);
    let analysis = analyze_certificate(&cert);
    assert_eq!(analysis.details.key_analysis.security_level, SecurityLevel::Acceptable);
    
    cert.server.public_key_size = Some(384);
    let analysis = analyze_certificate(&cert);
    assert_eq!(analysis.details.key_analysis.security_level, SecurityLevel::Strong);
}

#[test]
fn test_certificate_expiration_detection() {
    // Test expired certificate
    let mut cert = create_mock_cert("example.com", -5, false);
    let analysis = analyze_certificate(&cert);
    
    assert!(analysis.issues.iter().any(|issue| {
        issue.category == IssueCategory::ExpiredCertificate &&
        issue.severity == SecurityLevel::Critical
    }));
    
    // Test certificate expiring soon
    cert = create_mock_cert("example.com", 15, true);
    let analysis = analyze_certificate(&cert);
    
    assert!(analysis.issues.iter().any(|issue| {
        issue.category == IssueCategory::ShortValidityPeriod &&
        issue.description.contains("expires in 15 days")
    }));
    
    // Test certificate with long validity period
    cert.server.not_before = 0;
    cert.server.not_after = 86400 * 1000; // 1000 days
    let analysis = analyze_certificate(&cert);
    
    assert!(analysis.issues.iter().any(|issue| {
        issue.description.contains("unusually long validity period")
    }));
}

#[test]
fn test_missing_extensions_detection() {
    let mut cert = create_mock_cert("example.com", 90, true);
    
    // Remove all extensions
    cert.server.key_usage.clear();
    cert.server.extended_key_usage.clear();
    cert.server.sans.clear();
    
    let analysis = analyze_certificate(&cert);
    
    assert!(analysis.issues.iter().any(|issue| {
        issue.category == IssueCategory::MissingExtensions
    }));
    
    assert!(analysis.details.extension_analysis.missing_critical_extensions.contains(&"Key Usage".to_string()));
    assert!(analysis.details.extension_analysis.missing_critical_extensions.contains(&"Extended Key Usage".to_string()));
    assert!(analysis.details.extension_analysis.missing_critical_extensions.contains(&"Subject Alternative Name".to_string()));
}

#[test]
fn test_security_report_generation() {
    let weak_cert = create_weak_cert("vulnerable.com");
    let analysis = analyze_certificate(&weak_cert);
    let report = generate_security_report(&analysis);
    
    // Verify report contains expected sections
    assert!(report.contains("SSL/TLS Certificate Security Analysis"));
    assert!(report.contains("Overall Security Level"));
    assert!(report.contains("Security Issues Found"));
    assert!(report.contains("Detailed Analysis"));
    assert!(report.contains("Recommendations"));
    
    // Verify specific issues are mentioned
    assert!(report.contains("SHA1") || report.contains("weak"));
    assert!(report.contains("1024") || report.contains("Key size"));
}

#[test]
fn test_strong_certificate_analysis() {
    let mut cert = create_cert_with_algorithm("SHA384withECDSA", 384);
    cert.server.public_key_algorithm = "EC".to_string();
    cert.server.sans = vec!["secure.example.com".to_string()];
    cert.server.key_usage = vec!["Digital Signature".to_string(), "Key Agreement".to_string()];
    cert.server.extended_key_usage = vec!["Server Auth".to_string()];
    
    let analysis = analyze_certificate(&cert);
    
    assert_eq!(analysis.security_level, SecurityLevel::Strong);
    assert!(analysis.issues.is_empty());
    
    let report = generate_security_report(&analysis);
    assert!(report.contains("No security issues found"));
}

#[test]
fn test_dsa_key_analysis() {
    let mut cert = create_cert_with_algorithm("SHA256withDSA", 1024);
    cert.server.public_key_algorithm = "DSA".to_string();
    
    let analysis = analyze_certificate(&cert);
    assert_eq!(analysis.details.key_analysis.security_level, SecurityLevel::Weak);
    
    cert.server.public_key_size = Some(2048);
    let analysis = analyze_certificate(&cert);
    assert_eq!(analysis.details.key_analysis.security_level, SecurityLevel::Legacy);
    
    cert.server.public_key_size = Some(3072);
    let analysis = analyze_certificate(&cert);
    assert_eq!(analysis.details.key_analysis.security_level, SecurityLevel::Acceptable);
}

#[test]
fn test_comprehensive_weak_certificate() {
    // Create a certificate with multiple weaknesses
    let mut cert = Cert {
        server: ServerCert {
            common_name: "weak.example.com".to_string(),
            is_valid: true,
            days_to_expiration: 5, // Expiring soon
            signature_algorithm: "MD5withRSA".to_string(), // Critical weakness
            public_key_algorithm: "RSA".to_string(),
            public_key_size: Some(512), // Critically small
            sans: vec![], // Missing SAN
            key_usage: vec![], // Missing key usage
            extended_key_usage: vec![], // Missing extended key usage
            not_before: 0,
            not_after: 86400 * 5,
            ..Default::default()
        },
        intermediate: IntermediateCert {
            signature_algorithm: "SHA1withRSA".to_string(), // Weak
            is_ca: true,
            is_valid: true,
            ..Default::default()
        },
        chain_length: 2,
        protocol_version: "TLSv1.0".to_string(),
    };
    
    let analysis = analyze_certificate(&cert);
    
    // Should have critical security level due to MD5 and 512-bit key
    assert_eq!(analysis.security_level, SecurityLevel::Critical);
    
    // Should have multiple issues
    assert!(analysis.issues.len() >= 4);
    
    // Check for specific issues
    let issue_categories: Vec<IssueCategory> = analysis.issues.iter()
        .map(|i| i.category.clone())
        .collect();
    
    assert!(issue_categories.contains(&IssueCategory::WeakSignatureAlgorithm));
    assert!(issue_categories.contains(&IssueCategory::SmallKeySize));
    assert!(issue_categories.contains(&IssueCategory::ShortValidityPeriod));
    assert!(issue_categories.contains(&IssueCategory::MissingExtensions));
}

#[test]
fn test_security_level_ordering() {
    // Test that security levels are properly ordered
    assert!(SecurityLevel::Critical < SecurityLevel::Weak);
    assert!(SecurityLevel::Weak < SecurityLevel::Legacy);
    assert!(SecurityLevel::Legacy < SecurityLevel::Acceptable);
    assert!(SecurityLevel::Acceptable < SecurityLevel::Strong);
}

#[test]
fn test_issue_category_equality() {
    assert_eq!(IssueCategory::WeakSignatureAlgorithm, IssueCategory::WeakSignatureAlgorithm);
    assert_ne!(IssueCategory::WeakSignatureAlgorithm, IssueCategory::SmallKeySize);
}

#[test]
fn test_sha224_legacy_detection() {
    let cert = create_cert_with_algorithm("SHA224withRSA", 2048);
    let analysis = analyze_certificate(&cert);
    
    assert_eq!(analysis.details.signature_algorithm.security_level, SecurityLevel::Legacy);
    assert!(!analysis.details.signature_algorithm.is_deprecated);
}

#[test]
fn test_unknown_algorithm_handling() {
    let cert = create_cert_with_algorithm("UnknownAlgorithm", 2048);
    let analysis = analyze_certificate(&cert);
    
    assert_eq!(analysis.details.signature_algorithm.security_level, SecurityLevel::Legacy);
    assert!(analysis.details.signature_algorithm.recommended_alternative.is_some());
}