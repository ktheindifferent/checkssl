use checkssl::{
    RetryConfig, retry_with_backoff, RetryableError,
    pem_to_der, der_to_pem,
    BatchConfig, BatchStatistics,
    CertificateCache, CacheConfig, EvictionStrategy,
    analyze_certificate, SecurityLevel, generate_security_report,
    CheckSSLError, IntermediateCert,
};
use std::time::Duration;

#[test]
fn test_retry_with_exponential_backoff() {
    let mut attempt = 0;
    let config = RetryConfig {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_secs(1),
        backoff_multiplier: 2.0,
        jitter: false,
    };

    let result = retry_with_backoff(&config, || -> Result<i32, CheckSSLError> {
        attempt += 1;
        if attempt < 3 {
            Err(CheckSSLError::NetworkError("Temporary failure".to_string()))
        } else {
            Ok(42)
        }
    });

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_pem_der_conversion() {
    let test_der = vec![0x30, 0x82, 0x01, 0x0a];
    
    // Test DER to PEM
    let pem = der_to_pem(&test_der).unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    
    // Test PEM to DER
    let der_result = pem_to_der(&pem);
    assert!(der_result.is_ok());
}

#[test]
fn test_certificate_cache_operations() {
    let config = CacheConfig {
        max_entries: 100,
        ttl: Duration::from_secs(3600),
        track_access: true,
        eviction_strategy: EvictionStrategy::LRU,
    };
    
    let cache = CertificateCache::with_config(config);
    
    // Test key generation
    let key1 = CertificateCache::generate_key("example.com", 443);
    let key2 = CertificateCache::generate_key("EXAMPLE.COM", 443);
    assert_eq!(key1, key2); // Should be case-insensitive
    
    // Test cache statistics
    let stats = cache.statistics();
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
}

#[test]
fn test_batch_configuration() {
    let config = BatchConfig {
        max_concurrent: 10,
        check_config: Default::default(),
        continue_on_error: true,
        delay_between_checks: Some(Duration::from_millis(100)),
    };
    
    assert_eq!(config.max_concurrent, 10);
    assert!(config.continue_on_error);
    assert!(config.delay_between_checks.is_some());
}

#[test]
fn test_security_analysis_levels() {
    use checkssl::{Cert, ServerCert};
    
    // Create a test certificate with weak algorithm
    let weak_cert = Cert {
        server: ServerCert {
            signature_algorithm: "SHA1withRSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            public_key_size: Some(1024),
            is_valid: true,
            days_to_expiration: 90,
            not_before: 0,
            not_after: 86400 * 365,
            ..Default::default()
        },
        intermediate: IntermediateCert::default(),
        chain_length: 2,
        protocol_version: "TLSv1.2".to_string(),
    };
    
    let analysis = analyze_certificate(&weak_cert);
    assert!(analysis.security_level <= SecurityLevel::Weak);
    assert!(!analysis.issues.is_empty());
    
    // Create a test certificate with strong algorithm
    let strong_cert = Cert {
        server: ServerCert {
            signature_algorithm: "SHA384withECDSA".to_string(),
            public_key_algorithm: "ECDSA".to_string(),
            public_key_size: Some(384),
            is_valid: true,
            days_to_expiration: 90,
            not_before: 0,
            not_after: 86400 * 365,
            sans: vec!["example.com".to_string()],
            key_usage: vec!["Digital Signature".to_string()],
            extended_key_usage: vec!["Server Auth".to_string()],
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
    };
    
    let analysis = analyze_certificate(&strong_cert);
    assert_eq!(analysis.security_level, SecurityLevel::Strong);
    assert!(analysis.issues.is_empty());
}

#[test]
fn test_security_report_generation() {
    use checkssl::{Cert, ServerCert};
    
    let cert = Cert {
        server: ServerCert {
            signature_algorithm: "MD5withRSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            public_key_size: Some(1024),
            is_valid: true,
            days_to_expiration: 10,
            not_before: 0,
            not_after: 86400 * 365,
            ..Default::default()
        },
        intermediate: IntermediateCert::default(),
        chain_length: 2,
        protocol_version: "TLSv1.2".to_string(),
    };
    
    let analysis = analyze_certificate(&cert);
    let report = generate_security_report(&analysis);
    
    assert!(report.contains("Security Issues Found"));
    assert!(report.contains("MD5withRSA"));
    assert!(report.contains("Critical"));
    assert!(report.contains("Recommendations"));
}

#[test]
fn test_cache_eviction_strategies() {
    use checkssl::{Cert, ServerCert};
    
    // Test LRU eviction
    let config = CacheConfig {
        max_entries: 2,
        ttl: Duration::from_secs(3600),
        track_access: true,
        eviction_strategy: EvictionStrategy::LRU,
    };
    
    let cache = CertificateCache::with_config(config);
    
    let cert1 = Cert {
        server: ServerCert {
            common_name: "domain1.com".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    
    let cert2 = Cert {
        server: ServerCert {
            common_name: "domain2.com".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    
    let cert3 = Cert {
        server: ServerCert {
            common_name: "domain3.com".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    
    cache.put("key1".to_string(), cert1);
    cache.put("key2".to_string(), cert2);
    
    // Access key1 to make it more recently used
    let _ = cache.get("key1");
    
    // Adding key3 should evict key2 (least recently used)
    cache.put("key3".to_string(), cert3);
    
    assert!(cache.contains("key1"));
    assert!(!cache.contains("key2"));
    assert!(cache.contains("key3"));
}

#[test]
fn test_batch_statistics_calculation() {
    use checkssl::{BatchCheckResult, Cert, ServerCert};
    use std::time::Instant;
    
    let results = vec![
        BatchCheckResult {
            domain: "example1.com".to_string(),
            result: Ok(Cert {
                server: ServerCert {
                    is_valid: true,
                    days_to_expiration: 90,
                    ..Default::default()
                },
                ..Default::default()
            }),
            duration: Duration::from_millis(100),
            checked_at: Instant::now(),
        },
        BatchCheckResult {
            domain: "example2.com".to_string(),
            result: Ok(Cert {
                server: ServerCert {
                    is_valid: true,
                    days_to_expiration: 20,
                    ..Default::default()
                },
                ..Default::default()
            }),
            duration: Duration::from_millis(150),
            checked_at: Instant::now(),
        },
        BatchCheckResult {
            domain: "example3.com".to_string(),
            result: Err("Connection failed".to_string()),
            duration: Duration::from_millis(50),
            checked_at: Instant::now(),
        },
    ];
    
    let stats = BatchStatistics::from_results(&results, 30);
    
    assert_eq!(stats.total_checked, 3);
    assert_eq!(stats.successful, 2);
    assert_eq!(stats.failed, 1);
    assert_eq!(stats.expiring_soon, 1);
    assert_eq!(stats.expired, 0);
}

#[test]
fn test_retryable_error_detection() {
    assert!(CheckSSLError::NetworkError("test".to_string()).is_retryable());
    assert!(CheckSSLError::TimeoutError("test".to_string()).is_retryable());
    assert!(CheckSSLError::DnsResolutionError("test".to_string()).is_retryable());
    assert!(CheckSSLError::TlsHandshakeError("test".to_string()).is_retryable());
    assert!(CheckSSLError::OcspError("test".to_string()).is_retryable());
    
    assert!(!CheckSSLError::CertificateParseError("test".to_string()).is_retryable());
    assert!(!CheckSSLError::ValidationError("test".to_string()).is_retryable());
    assert!(!CheckSSLError::InvalidDomainError("test".to_string()).is_retryable());
}

#[test]
fn test_certificate_format_detection() {
    let pem_data = b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----";
    let der_data = &[0x30, 0x82, 0x01, 0x0a];
    
    // PEM format should be detected
    assert!(pem_data.starts_with(b"-----BEGIN"));
    
    // DER format should not start with PEM header
    assert!(!der_data.starts_with(b"-----BEGIN"));
}

#[test]
#[ignore] // Requires actual certificate files
fn test_load_certificates_from_file() {
    
    // This test would require actual certificate files
    // Uncomment and adjust path when testing with real certificates
    /*
    let path = Path::new("test_cert.pem");
    let result = load_certificates_from_file(path, CertificateFormat::Auto);
    assert!(result.is_ok());
    
    let certs = result.unwrap();
    assert!(!certs.is_empty());
    */
}

#[test]
fn test_cache_ttl_expiration() {
    use checkssl::{Cert, ServerCert};
    
    let config = CacheConfig {
        max_entries: 100,
        ttl: Duration::from_millis(50), // Very short TTL for testing
        track_access: true,
        eviction_strategy: EvictionStrategy::LRU,
    };
    
    let cache = CertificateCache::with_config(config);
    
    let cert = Cert {
        server: ServerCert {
            common_name: "example.com".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    
    cache.put("test_key".to_string(), cert);
    assert!(cache.contains("test_key"));
    
    // Wait for TTL to expire
    std::thread::sleep(Duration::from_millis(60));
    
    assert!(!cache.contains("test_key"));
    assert!(cache.get("test_key").is_none());
}