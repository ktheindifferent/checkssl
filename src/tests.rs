#[cfg(test)]
mod tests {
    use crate::{CheckSSL, CheckSSLConfig, CheckSSLError};
    use std::time::Duration;

    #[test]
    fn test_valid_certificate() {
        let result = CheckSSL::from_domain("rust-lang.org".to_string());
        assert!(result.is_ok());
        let cert = result.unwrap();
        assert!(cert.server.is_valid);
        assert!(!cert.server.common_name.is_empty());
        assert!(!cert.server.issuer.is_empty());
        assert!(!cert.server.fingerprint_sha256.is_empty());
        assert!(!cert.server.fingerprint_sha1.is_empty());
        assert!(cert.server.days_to_expiration > 0);
    }

    #[test]
    fn test_invalid_domain() {
        let result = CheckSSL::from_domain("this-is-not-a-valid-domain-12345.com".to_string());
        assert!(result.is_err());
        match result.unwrap_err() {
            CheckSSLError::DnsResolutionError(_) | 
            CheckSSLError::NetworkError(_) |
            CheckSSLError::TimeoutError(_) => {},
            _ => panic!("Expected DNS resolution or network error"),
        }
    }

    #[test]
    fn test_expired_certificate() {
        let result = CheckSSL::from_domain("expired.badssl.com".to_string());
        assert!(result.is_err() || !result.unwrap().server.is_valid);
    }

    #[test]
    fn test_custom_config() {
        let config = CheckSSLConfig {
            timeout: Duration::from_secs(10),
            port: 443,
        };
        let result = CheckSSL::from_domain_with_config("github.com".to_string(), config);
        assert!(result.is_ok());
        let cert = result.unwrap();
        assert!(cert.server.is_valid);
        assert_eq!(cert.chain_length, 3);
    }

    #[test]
    fn test_certificate_fields() {
        let result = CheckSSL::from_domain("github.com".to_string());
        assert!(result.is_ok());
        let cert = result.unwrap();
        
        assert!(!cert.server.signature_algorithm.is_empty());
        assert!(!cert.server.public_key_algorithm.is_empty());
        assert!(cert.server.version > 0);
        assert!(!cert.server.serial_number.is_empty());
        assert!(cert.server.not_before < cert.server.not_after);
        
        assert!(!cert.server.sans.is_empty());
        assert!(cert.server.sans.contains(&"github.com".to_string()) || 
                cert.server.sans.contains(&"*.github.com".to_string()));
        
        if !cert.server.key_usage.is_empty() {
            assert!(cert.server.key_usage.contains(&"Digital Signature".to_string()) ||
                    cert.server.key_usage.contains(&"Key Encipherment".to_string()));
        }
        
        if !cert.server.extended_key_usage.is_empty() {
            assert!(cert.server.extended_key_usage.contains(&"Server Auth".to_string()));
        }
    }

    #[test]
    fn test_intermediate_certificate() {
        let result = CheckSSL::from_domain("rust-lang.org".to_string());
        assert!(result.is_ok());
        let cert = result.unwrap();
        
        assert!(cert.intermediate.is_ca);
        assert!(!cert.intermediate.common_name.is_empty());
        assert!(!cert.intermediate.issuer.is_empty());
        assert!(!cert.intermediate.fingerprint_sha256.is_empty());
        
        if !cert.intermediate.key_usage.is_empty() {
            assert!(cert.intermediate.key_usage.contains(&"Key Cert Sign".to_string()));
        }
    }

    #[test]
    fn test_certificate_chain() {
        let result = CheckSSL::from_domain("github.com".to_string());
        assert!(result.is_ok());
        let cert = result.unwrap();
        
        assert!(cert.chain_length >= 2);
        assert!(!cert.protocol_version.is_empty());
        assert!(cert.protocol_version.contains("TLS"));
    }

    #[test]
    fn test_timeout_handling() {
        let config = CheckSSLConfig {
            timeout: Duration::from_millis(1),
            port: 443,
        };
        let result = CheckSSL::from_domain_with_config("google.com".to_string(), config);
        assert!(result.is_err());
        match result.unwrap_err() {
            CheckSSLError::TimeoutError(_) => {},
            _ => panic!("Expected timeout error"),
        }
    }

    #[test]
    fn test_non_standard_port() {
        let config = CheckSSLConfig {
            timeout: Duration::from_secs(5),
            port: 8443,
        };
        let result = CheckSSL::from_domain_with_config("localhost".to_string(), config);
        assert!(result.is_err());
    }

    #[test]
    fn test_fingerprint_format() {
        let result = CheckSSL::from_domain("rust-lang.org".to_string());
        assert!(result.is_ok());
        let cert = result.unwrap();
        
        assert_eq!(cert.server.fingerprint_sha256.len(), 64);
        assert!(cert.server.fingerprint_sha256.chars().all(|c| c.is_ascii_hexdigit()));
        
        assert_eq!(cert.server.fingerprint_sha1.len(), 40);
        assert!(cert.server.fingerprint_sha1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_certificate_expiration_time() {
        let result = CheckSSL::from_domain("rust-lang.org".to_string());
        assert!(result.is_ok());
        let cert = result.unwrap();
        
        assert!(cert.server.days_to_expiration > 0);
        assert!(cert.server.time_to_expiration.contains("day"));
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        assert!(cert.server.not_before < current_time);
        assert!(cert.server.not_after > current_time);
    }

    #[test]
    fn test_sans_wildcard() {
        let result = CheckSSL::from_domain("www.github.com".to_string());
        if result.is_ok() {
            let cert = result.unwrap();
            let has_wildcard = cert.server.sans.iter()
                .any(|san| san.starts_with("*."));
            let has_specific = cert.server.sans.iter()
                .any(|san| san == "www.github.com" || san == "github.com");
            assert!(has_wildcard || has_specific);
        }
    }

    #[test]
    fn test_certificate_version() {
        let result = CheckSSL::from_domain("rust-lang.org".to_string());
        assert!(result.is_ok());
        let cert = result.unwrap();
        assert_eq!(cert.server.version, 3);
    }

    #[test]
    fn test_issuer_parsing() {
        let result = CheckSSL::from_domain("rust-lang.org".to_string());
        assert!(result.is_ok());
        let cert = result.unwrap();
        
        assert!(cert.server.issuer.contains("CN="));
        assert!(!cert.server.issuer_cn.is_empty());
        
        assert!(cert.intermediate.issuer.contains("CN="));
        assert!(!cert.intermediate.issuer_cn.is_empty());
    }

    #[test]
    fn test_subject_fields() {
        let result = CheckSSL::from_domain("rust-lang.org".to_string());
        if result.is_ok() {
            let cert = result.unwrap();
            assert_eq!(cert.server.common_name, "rust-lang.org");
        }
    }

    #[test]
    fn test_error_display() {
        let err = CheckSSLError::TimeoutError("Connection timed out".to_string());
        assert_eq!(format!("{}", err), "Timeout error: Connection timed out");
        
        let err = CheckSSLError::CertificateExpired {
            common_name: "example.com".to_string(),
            expired_since: 30,
        };
        assert_eq!(format!("{}", err), "Certificate for 'example.com' expired 30 days ago");
    }

    #[test]
    fn test_multiple_domains_sequential() {
        let domains = vec!["rust-lang.org", "github.com"];
        for domain in domains {
            let result = CheckSSL::from_domain(domain.to_string());
            assert!(result.is_ok(), "Failed for domain: {}", domain);
        }
    }
}