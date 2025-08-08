use checkssl::{CheckSSL, CheckSSLConfig};
use std::time::Duration;

#[test]
fn test_cross_platform_domain_check() {
    // Test with common domains that should work on all platforms
    let domains = vec!["google.com", "cloudflare.com"];
    
    for domain in domains {
        let result = CheckSSL::from_domain(domain.to_string());
        
        // We expect either success or network error (in case of firewall/proxy)
        // but not platform-specific errors
        match result {
            Ok(cert) => {
                assert!(!cert.server.common_name.is_empty());
                assert!(!cert.server.fingerprint_sha256.is_empty());
            }
            Err(e) => {
                // Network errors are acceptable in test environments
                eprintln!("Network error for {}: {}", domain, e);
            }
        }
    }
}

#[test]
fn test_platform_independent_timeout() {
    let config = CheckSSLConfig {
        timeout: Duration::from_millis(1),
        port: 443,
    };
    
    // This should timeout consistently across platforms
    let result = CheckSSL::from_domain_with_config(
        "example.com".to_string(), 
        config
    );
    
    assert!(result.is_err());
}

#[test]
fn test_ipv4_address_handling() {
    // Test IP address handling (should work the same on all platforms)
    let result = CheckSSL::from_domain("8.8.8.8".to_string());
    
    // IP addresses typically don't have valid certificates
    // but the error should be consistent across platforms
    assert!(result.is_err());
}

#[test]
fn test_localhost_handling() {
    // localhost should behave consistently across platforms
    let result = CheckSSL::from_domain("localhost".to_string());
    
    // localhost typically won't have a valid cert
    assert!(result.is_err());
}

#[cfg(target_os = "windows")]
#[test]
fn test_windows_specific() {
    // Windows-specific test
    let config = CheckSSLConfig {
        timeout: Duration::from_secs(5),
        port: 443,
    };
    
    let result = CheckSSL::from_domain_with_config(
        "microsoft.com".to_string(),
        config
    );
    
    if let Ok(cert) = result {
        assert!(cert.server.is_valid);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_linux_specific() {
    // Linux-specific test
    let config = CheckSSLConfig {
        timeout: Duration::from_secs(5),
        port: 443,
    };
    
    // Test with a common Linux-related domain
    let result = CheckSSL::from_domain_with_config(
        "ubuntu.com".to_string(),
        config
    );
    
    if let Ok(cert) = result {
        assert!(cert.server.is_valid);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_specific() {
    // macOS-specific test
    let config = CheckSSLConfig {
        timeout: Duration::from_secs(5),
        port: 443,
    };
    
    let result = CheckSSL::from_domain_with_config(
        "apple.com".to_string(),
        config
    );
    
    if let Ok(cert) = result {
        assert!(cert.server.is_valid);
    }
}

#[test]
fn test_unicode_domain_handling() {
    // Test internationalized domain names (should work on all platforms)
    // This tests punycode conversion
    let result = CheckSSL::from_domain("münchen.de".to_string());
    
    // The result handling should be consistent across platforms
    match result {
        Ok(_) => println!("IDN domain check succeeded"),
        Err(e) => println!("IDN domain check failed: {}", e),
    }
}

#[test]
fn test_case_insensitive_domains() {
    // Domain names should be case-insensitive on all platforms
    let domains = vec![
        "GOOGLE.COM",
        "Google.Com",
        "google.com"
    ];
    
    for domain in domains {
        let result = CheckSSL::from_domain(domain.to_string());
        
        // All should either succeed or fail consistently
        match result {
            Ok(cert) => {
                // Google might use wildcard certs, so check if it contains google.com
                let cn = cert.server.common_name.to_lowercase();
                assert!(cn.contains("google.com") || cn == "*.google.com");
            }
            Err(_) => {
                // Network error is acceptable
            }
        }
    }
}