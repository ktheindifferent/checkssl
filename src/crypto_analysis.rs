//! Cryptographic analysis and weak algorithm detection.
//!
//! This module provides functionality to analyze certificates for
//! weak cryptographic algorithms and security issues.

use crate::Cert;

/// Security level of cryptographic algorithms
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Critical security issue, should not be used
    Critical,
    /// Weak security, deprecated
    Weak,
    /// Legacy algorithms, use with caution
    Legacy,
    /// Acceptable for current use
    Acceptable,
    /// Strong security
    Strong,
}

/// Result of cryptographic analysis
#[derive(Debug, Clone)]
pub struct CryptoAnalysis {
    /// Overall security level
    pub security_level: SecurityLevel,
    /// List of security issues found
    pub issues: Vec<SecurityIssue>,
    /// Recommendations for improvement
    pub recommendations: Vec<String>,
    /// Detailed analysis results
    pub details: AnalysisDetails,
}

/// Security issue found during analysis
#[derive(Debug, Clone)]
pub struct SecurityIssue {
    /// Severity of the issue
    pub severity: SecurityLevel,
    /// Category of the issue
    pub category: IssueCategory,
    /// Description of the issue
    pub description: String,
    /// Recommended action
    pub recommendation: String,
}

/// Categories of security issues
#[derive(Debug, Clone, PartialEq)]
pub enum IssueCategory {
    WeakSignatureAlgorithm,
    SmallKeySize,
    ShortValidityPeriod,
    ExpiredCertificate,
    SelfSigned,
    WeakHash,
    MissingExtensions,
    InsecureProtocol,
    WeakCipher,
}

/// Detailed analysis results
#[derive(Debug, Clone)]
pub struct AnalysisDetails {
    pub signature_algorithm: SignatureAnalysis,
    pub key_analysis: KeyAnalysis,
    pub validity_analysis: ValidityAnalysis,
    pub extension_analysis: ExtensionAnalysis,
    pub chain_analysis: ChainAnalysis,
}

/// Analysis of signature algorithm
#[derive(Debug, Clone)]
pub struct SignatureAnalysis {
    pub algorithm: String,
    pub security_level: SecurityLevel,
    pub is_deprecated: bool,
    pub recommended_alternative: Option<String>,
}

/// Analysis of public key
#[derive(Debug, Clone)]
pub struct KeyAnalysis {
    pub algorithm: String,
    pub key_size: Option<usize>,
    pub security_level: SecurityLevel,
    pub minimum_recommended_size: usize,
}

/// Analysis of certificate validity
#[derive(Debug, Clone)]
pub struct ValidityAnalysis {
    pub is_valid: bool,
    pub days_valid: i64,
    pub validity_period_days: i64,
    pub is_expired: bool,
    pub expires_soon: bool,
}

/// Analysis of certificate extensions
#[derive(Debug, Clone)]
pub struct ExtensionAnalysis {
    pub has_key_usage: bool,
    pub has_extended_key_usage: bool,
    pub has_san: bool,
    pub has_basic_constraints: bool,
    pub missing_critical_extensions: Vec<String>,
}

/// Analysis of certificate chain
#[derive(Debug, Clone)]
pub struct ChainAnalysis {
    pub chain_length: usize,
    pub has_intermediate: bool,
    pub all_valid: bool,
    pub weakest_link: Option<String>,
}

/// Analyze a certificate for cryptographic weaknesses
pub fn analyze_certificate(cert: &Cert) -> CryptoAnalysis {
    let mut issues = Vec::new();
    let mut recommendations = Vec::new();

    // Analyze signature algorithm
    let sig_analysis = analyze_signature_algorithm(&cert.server.signature_algorithm);
    if sig_analysis.security_level <= SecurityLevel::Weak {
        issues.push(SecurityIssue {
            severity: sig_analysis.security_level.clone(),
            category: IssueCategory::WeakSignatureAlgorithm,
            description: format!(
                "Certificate uses weak signature algorithm: {}",
                sig_analysis.algorithm
            ),
            recommendation: sig_analysis.recommended_alternative
                .clone()
                .unwrap_or_else(|| "Use SHA256 or SHA384 with RSA/ECDSA".to_string()),
        });
        recommendations.push(format!(
            "Replace {} with {}",
            sig_analysis.algorithm,
            sig_analysis.recommended_alternative
                .clone()
                .unwrap_or_else(|| "SHA256withRSA or SHA384withECDSA".to_string())
        ));
    }

    // Analyze key size
    let key_analysis = analyze_key(&cert.server.public_key_algorithm, cert.server.public_key_size);
    if key_analysis.security_level <= SecurityLevel::Weak {
        issues.push(SecurityIssue {
            severity: key_analysis.security_level.clone(),
            category: IssueCategory::SmallKeySize,
            description: format!(
                "Key size {} bits is below recommended minimum of {} bits for {}",
                key_analysis.key_size.unwrap_or(0),
                key_analysis.minimum_recommended_size,
                key_analysis.algorithm
            ),
            recommendation: format!(
                "Use at least {}-bit keys for {}",
                key_analysis.minimum_recommended_size,
                key_analysis.algorithm
            ),
        });
    }

    // Analyze validity period
    let validity_analysis = analyze_validity(
        cert.server.is_valid,
        cert.server.days_to_expiration,
        cert.server.not_before,
        cert.server.not_after,
    );
    
    if validity_analysis.is_expired {
        issues.push(SecurityIssue {
            severity: SecurityLevel::Critical,
            category: IssueCategory::ExpiredCertificate,
            description: "Certificate has expired".to_string(),
            recommendation: "Renew the certificate immediately".to_string(),
        });
    } else if validity_analysis.expires_soon {
        issues.push(SecurityIssue {
            severity: SecurityLevel::Weak,
            category: IssueCategory::ShortValidityPeriod,
            description: format!(
                "Certificate expires in {} days",
                validity_analysis.days_valid
            ),
            recommendation: "Plan certificate renewal soon".to_string(),
        });
    }

    // Check for long validity periods (potential security risk)
    if validity_analysis.validity_period_days > 825 {
        issues.push(SecurityIssue {
            severity: SecurityLevel::Legacy,
            category: IssueCategory::ShortValidityPeriod,
            description: format!(
                "Certificate has unusually long validity period of {} days",
                validity_analysis.validity_period_days
            ),
            recommendation: "Consider using shorter validity periods (max 398 days for public certificates)".to_string(),
        });
    }

    // Analyze extensions
    let extension_analysis = analyze_extensions(cert);
    if !extension_analysis.missing_critical_extensions.is_empty() {
        for ext in &extension_analysis.missing_critical_extensions {
            issues.push(SecurityIssue {
                severity: SecurityLevel::Legacy,
                category: IssueCategory::MissingExtensions,
                description: format!("Missing recommended extension: {}", ext),
                recommendation: format!("Add {} extension to the certificate", ext),
            });
        }
    }

    // Analyze certificate chain
    let chain_analysis = analyze_chain(cert);
    if let Some(ref weak_link) = chain_analysis.weakest_link {
        issues.push(SecurityIssue {
            severity: SecurityLevel::Weak,
            category: IssueCategory::WeakSignatureAlgorithm,
            description: format!("Weak algorithm in certificate chain: {}", weak_link),
            recommendation: "Update entire certificate chain to use strong algorithms".to_string(),
        });
    }

    // Determine overall security level
    let overall_security = if issues.is_empty() {
        SecurityLevel::Strong
    } else {
        issues.iter()
            .map(|i| i.severity.clone())
            .min()
            .unwrap_or(SecurityLevel::Acceptable)
    };

    // Add general recommendations
    if cert.server.sans.is_empty() && !cert.server.common_name.is_empty() {
        recommendations.push("Add Subject Alternative Names (SAN) extension".to_string());
    }

    CryptoAnalysis {
        security_level: overall_security,
        issues,
        recommendations,
        details: AnalysisDetails {
            signature_algorithm: sig_analysis,
            key_analysis,
            validity_analysis,
            extension_analysis,
            chain_analysis,
        },
    }
}

/// Analyze signature algorithm strength
fn analyze_signature_algorithm(algorithm: &str) -> SignatureAnalysis {
    let algorithm_lower = algorithm.to_lowercase();
    
    let (security_level, is_deprecated, recommended) = if algorithm_lower.contains("md5") {
        (SecurityLevel::Critical, true, Some("SHA256withRSA".to_string()))
    } else if algorithm_lower.contains("sha1") {
        (SecurityLevel::Weak, true, Some("SHA256withRSA".to_string()))
    } else if algorithm_lower.contains("sha224") {
        (SecurityLevel::Legacy, false, Some("SHA256withRSA".to_string()))
    } else if algorithm_lower.contains("sha256") {
        (SecurityLevel::Acceptable, false, None)
    } else if algorithm_lower.contains("sha384") || algorithm_lower.contains("sha512") {
        (SecurityLevel::Strong, false, None)
    } else if algorithm_lower.contains("ecdsa") {
        if algorithm_lower.contains("sha256") || algorithm_lower.contains("sha384") {
            (SecurityLevel::Strong, false, None)
        } else {
            (SecurityLevel::Acceptable, false, None)
        }
    } else {
        (SecurityLevel::Legacy, false, Some("SHA256withRSA or ECDSA".to_string()))
    };

    SignatureAnalysis {
        algorithm: algorithm.to_string(),
        security_level,
        is_deprecated,
        recommended_alternative: recommended,
    }
}

/// Analyze key strength
fn analyze_key(algorithm: &str, key_size: Option<usize>) -> KeyAnalysis {
    let algorithm_lower = algorithm.to_lowercase();
    
    let (minimum_size, security_level) = if algorithm_lower.contains("rsa") {
        let size = key_size.unwrap_or(0);
        let min_recommended = 2048;
        let level = if size < 1024 {
            SecurityLevel::Critical
        } else if size < 2048 {
            SecurityLevel::Weak
        } else if size < 3072 {
            SecurityLevel::Acceptable
        } else {
            SecurityLevel::Strong
        };
        (min_recommended, level)
    } else if algorithm_lower.contains("ec") || algorithm_lower.contains("ecdsa") {
        let size = key_size.unwrap_or(256);
        let min_recommended = 256;
        let level = if size < 224 {
            SecurityLevel::Weak
        } else if size < 256 {
            SecurityLevel::Legacy
        } else if size < 384 {
            SecurityLevel::Acceptable
        } else {
            SecurityLevel::Strong
        };
        (min_recommended, level)
    } else if algorithm_lower.contains("dsa") {
        let size = key_size.unwrap_or(0);
        let min_recommended = 2048;
        let level = if size < 2048 {
            SecurityLevel::Weak
        } else if size < 3072 {
            SecurityLevel::Legacy
        } else {
            SecurityLevel::Acceptable
        };
        (min_recommended, level)
    } else {
        (2048, SecurityLevel::Legacy)
    };

    KeyAnalysis {
        algorithm: algorithm.to_string(),
        key_size,
        security_level,
        minimum_recommended_size: minimum_size,
    }
}

/// Analyze certificate validity
fn analyze_validity(is_valid: bool, days_to_expiration: i64, not_before: i64, not_after: i64) -> ValidityAnalysis {
    let validity_period_days = (not_after - not_before) / 86400;
    let is_expired = !is_valid || days_to_expiration < 0;
    let expires_soon = days_to_expiration < 30 && days_to_expiration >= 0;

    ValidityAnalysis {
        is_valid,
        days_valid: days_to_expiration,
        validity_period_days,
        is_expired,
        expires_soon,
    }
}

/// Analyze certificate extensions
fn analyze_extensions(cert: &Cert) -> ExtensionAnalysis {
    let mut missing_critical = Vec::new();
    
    let has_key_usage = !cert.server.key_usage.is_empty();
    let has_extended_key_usage = !cert.server.extended_key_usage.is_empty();
    let has_san = !cert.server.sans.is_empty();
    let has_basic_constraints = cert.intermediate.is_ca; // Simplified check
    
    if !has_key_usage {
        missing_critical.push("Key Usage".to_string());
    }
    if !has_extended_key_usage {
        missing_critical.push("Extended Key Usage".to_string());
    }
    if !has_san && !cert.server.common_name.is_empty() {
        missing_critical.push("Subject Alternative Name".to_string());
    }

    ExtensionAnalysis {
        has_key_usage,
        has_extended_key_usage,
        has_san,
        has_basic_constraints,
        missing_critical_extensions: missing_critical,
    }
}

/// Analyze certificate chain
fn analyze_chain(cert: &Cert) -> ChainAnalysis {
    let mut weakest_link = None;
    
    // Check intermediate certificate
    if !cert.intermediate.signature_algorithm.is_empty() {
        let inter_sig = analyze_signature_algorithm(&cert.intermediate.signature_algorithm);
        if inter_sig.security_level <= SecurityLevel::Weak {
            weakest_link = Some(format!("Intermediate: {}", cert.intermediate.signature_algorithm));
        }
    }
    
    // Check server certificate if no weak intermediate
    if weakest_link.is_none() {
        let server_sig = analyze_signature_algorithm(&cert.server.signature_algorithm);
        if server_sig.security_level <= SecurityLevel::Weak {
            weakest_link = Some(format!("Server: {}", cert.server.signature_algorithm));
        }
    }

    ChainAnalysis {
        chain_length: cert.chain_length,
        has_intermediate: cert.intermediate.is_ca,
        all_valid: cert.server.is_valid && cert.intermediate.is_valid,
        weakest_link,
    }
}

/// Generate a security report from analysis
pub fn generate_security_report(analysis: &CryptoAnalysis) -> String {
    let mut report = String::new();
    
    report.push_str("=== SSL/TLS Certificate Security Analysis ===\n\n");
    
    report.push_str(&format!("Overall Security Level: {:?}\n\n", analysis.security_level));
    
    if !analysis.issues.is_empty() {
        report.push_str("Security Issues Found:\n");
        report.push_str("-".repeat(40).as_str());
        report.push('\n');
        
        for issue in &analysis.issues {
            report.push_str(&format!("• [{:?}] {}\n", issue.severity, issue.description));
            report.push_str(&format!("  Recommendation: {}\n\n", issue.recommendation));
        }
    } else {
        report.push_str("✓ No security issues found\n\n");
    }
    
    report.push_str("Detailed Analysis:\n");
    report.push_str("-".repeat(40).as_str());
    report.push('\n');
    
    report.push_str(&format!("Signature Algorithm: {} ({:?})\n",
        analysis.details.signature_algorithm.algorithm,
        analysis.details.signature_algorithm.security_level
    ));
    
    report.push_str(&format!("Key Algorithm: {} ({:?})\n",
        analysis.details.key_analysis.algorithm,
        analysis.details.key_analysis.security_level
    ));
    
    if let Some(size) = analysis.details.key_analysis.key_size {
        report.push_str(&format!("Key Size: {} bits\n", size));
    }
    
    report.push_str(&format!("Certificate Valid: {}\n", analysis.details.validity_analysis.is_valid));
    report.push_str(&format!("Days to Expiration: {}\n", analysis.details.validity_analysis.days_valid));
    
    if !analysis.recommendations.is_empty() {
        report.push_str("\nRecommendations:\n");
        report.push_str("-".repeat(40).as_str());
        report.push('\n');
        for rec in &analysis.recommendations {
            report.push_str(&format!("• {}\n", rec));
        }
    }
    
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServerCert, IntermediateCert};

    fn create_test_cert(sig_algo: &str, key_algo: &str, key_size: Option<usize>) -> Cert {
        Cert {
            server: ServerCert {
                signature_algorithm: sig_algo.to_string(),
                public_key_algorithm: key_algo.to_string(),
                public_key_size: key_size,
                is_valid: true,
                days_to_expiration: 90,
                not_before: 0,
                not_after: 86400 * 365,
                ..Default::default()
            },
            intermediate: IntermediateCert {
                signature_algorithm: "SHA256withRSA".to_string(),
                is_ca: true,
                is_valid: true,
                ..Default::default()
            },
            chain_length: 2,
            protocol_version: "TLSv1.3".to_string(),
        }
    }

    #[test]
    fn test_weak_signature_detection() {
        let cert = create_test_cert("MD5withRSA", "RSA", Some(2048));
        let analysis = analyze_certificate(&cert);
        
        assert_eq!(analysis.security_level, SecurityLevel::Critical);
        assert!(analysis.issues.iter().any(|i| i.category == IssueCategory::WeakSignatureAlgorithm));
    }

    #[test]
    fn test_small_key_size_detection() {
        let cert = create_test_cert("SHA256withRSA", "RSA", Some(1024));
        let analysis = analyze_certificate(&cert);
        
        assert!(analysis.security_level <= SecurityLevel::Weak);
        assert!(analysis.issues.iter().any(|i| i.category == IssueCategory::SmallKeySize));
    }

    #[test]
    fn test_strong_certificate() {
        let mut cert = create_test_cert("SHA384withECDSA", "EC", Some(384));
        // Add required extensions to make it strong
        cert.server.sans = vec!["example.com".to_string()];
        cert.server.key_usage = vec!["Digital Signature".to_string()];
        cert.server.extended_key_usage = vec!["Server Auth".to_string()];
        let analysis = analyze_certificate(&cert);
        
        assert_eq!(analysis.security_level, SecurityLevel::Strong);
        assert!(analysis.issues.is_empty());
    }

    #[test]
    fn test_signature_algorithm_analysis() {
        let md5 = analyze_signature_algorithm("MD5withRSA");
        assert_eq!(md5.security_level, SecurityLevel::Critical);
        assert!(md5.is_deprecated);
        
        let sha1 = analyze_signature_algorithm("SHA1withRSA");
        assert_eq!(sha1.security_level, SecurityLevel::Weak);
        assert!(sha1.is_deprecated);
        
        let sha256 = analyze_signature_algorithm("SHA256withRSA");
        assert_eq!(sha256.security_level, SecurityLevel::Acceptable);
        assert!(!sha256.is_deprecated);
        
        let sha384 = analyze_signature_algorithm("SHA384withECDSA");
        assert_eq!(sha384.security_level, SecurityLevel::Strong);
        assert!(!sha384.is_deprecated);
    }

    #[test]
    fn test_key_analysis() {
        let rsa_weak = analyze_key("RSA", Some(1024));
        assert_eq!(rsa_weak.security_level, SecurityLevel::Weak);
        
        let rsa_good = analyze_key("RSA", Some(2048));
        assert_eq!(rsa_good.security_level, SecurityLevel::Acceptable);
        
        let rsa_strong = analyze_key("RSA", Some(4096));
        assert_eq!(rsa_strong.security_level, SecurityLevel::Strong);
        
        let ec_good = analyze_key("ECDSA", Some(256));
        assert_eq!(ec_good.security_level, SecurityLevel::Acceptable);
        
        let ec_strong = analyze_key("ECDSA", Some(384));
        assert_eq!(ec_strong.security_level, SecurityLevel::Strong);
    }
}