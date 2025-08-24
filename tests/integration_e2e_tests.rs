//! End-to-end integration tests for comprehensive SSL checking scenarios

use checkssl::{
    CheckSSL, Cert, CheckSSLError,
    retry_with_backoff, RetryConfig,
    CertificateCache, CacheConfig, EvictionStrategy, check_with_cache,
    OcspStatus,
    analyze_certificate, SecurityLevel
};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

mod fixtures;
use fixtures::{create_mock_cert, create_weak_cert};

#[test]
#[ignore] // This test requires network access
fn test_real_world_certificate_check() {
    // Test with a well-known domain
    let result = CheckSSL::from_domain("google.com".to_string());
    
    match result {
        Ok(cert) => {
            assert!(cert.server.is_valid);
            assert!(cert.server.days_to_expiration > 0);
            assert!(!cert.server.common_name.is_empty());
            assert!(cert.server.sans.len() > 0);
            
            // Analyze security
            let analysis = analyze_certificate(&cert);
            assert!(analysis.security_level >= SecurityLevel::Acceptable);
        },
        Err(e) => {
            // Network issues are acceptable in tests
            match e {
                CheckSSLError::NetworkError(_) |
                CheckSSLError::DnsResolutionError(_) => {},
                _ => panic!("Unexpected error: {:?}", e)
            }
        }
    }
}

#[test]
fn test_retry_with_cache_integration() {
    let cache = Arc::new(CertificateCache::new());
    let call_count = Arc::new(Mutex::new(0));
    
    // Simulate a service that fails twice then succeeds
    let simulate_check = |attempt: i32| -> Result<Cert, CheckSSLError> {
        if attempt < 3 {
            Err(CheckSSLError::NetworkError("Temporary failure".to_string()))
        } else {
            Ok(create_mock_cert("retry-test.com", 90, true))
        }
    };
    
    // First attempt with retry
    let retry_config = RetryConfig {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(100),
        backoff_multiplier: 2.0,
        jitter: false,
    };
    
    let cache_clone = cache.clone();
    let count_clone = call_count.clone();
    
    let result = retry_with_backoff(&retry_config, || {
        let mut count = count_clone.lock().unwrap();
        *count += 1;
        
        check_with_cache(
            &*cache_clone,
            "retry-test.com",
            443,
            || simulate_check(*count)
        )
    });
    
    assert!(result.is_ok());
    assert_eq!(*call_count.lock().unwrap(), 3); // Failed twice, succeeded on third
    
    // Second attempt should use cache
    let count_before = *call_count.lock().unwrap();
    let cached_result = check_with_cache(
        &*cache,
        "retry-test.com",
        443,
        || panic!("Should not be called - should use cache")
    );
    
    assert!(cached_result.is_ok());
    assert_eq!(*call_count.lock().unwrap(), count_before); // No new calls
}

#[test]
fn test_concurrent_certificate_checks_with_cache() {
    let cache = Arc::new(CertificateCache::with_config(CacheConfig {
        max_entries: 100,
        ttl: Duration::from_secs(60),
        track_access: true,
        eviction_strategy: EvictionStrategy::LRU,
    }));
    
    let domains = vec![
        "test1.example.com",
        "test2.example.com",
        "test3.example.com",
        "test4.example.com",
        "test5.example.com",
    ];
    
    // Spawn multiple threads to check certificates concurrently
    let handles: Vec<_> = domains.iter().map(|&domain| {
        let cache = cache.clone();
        thread::spawn(move || {
            // Each thread checks the same domain multiple times
            for i in 0..5 {
                let result = check_with_cache(
                    &*cache,
                    domain,
                    443,
                    || Ok(create_mock_cert(domain, 90 + i, true))
                );
                assert!(result.is_ok());
                
                // Small delay to simulate real-world timing
                thread::sleep(Duration::from_millis(10));
            }
        })
    }).collect();
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Verify cache statistics
    let stats = cache.statistics();
    assert!(stats.hits > 0); // Should have cache hits
    assert_eq!(stats.hit_rate() > 0.0, true);
    
    // Verify all domains are cached
    for domain in &domains {
        let key = CertificateCache::generate_key(domain, 443);
        assert!(cache.contains(&key));
    }
}

#[test]
fn test_security_analysis_pipeline() {
    // Create certificates with varying security levels
    let certificates = vec![
        ("strong.example.com", create_mock_cert("strong.example.com", 90, true)),
        ("weak.example.com", create_weak_cert("weak.example.com")),
    ];
    
    for (name, cert) in certificates {
        let analysis = analyze_certificate(&cert);
        
        match name {
            "strong.example.com" => {
                assert!(analysis.security_level >= SecurityLevel::Acceptable);
                assert!(analysis.issues.len() <= 3); // May have minor issues
            },
            "weak.example.com" => {
                assert!(analysis.security_level <= SecurityLevel::Weak);
                assert!(!analysis.issues.is_empty());
                assert!(!analysis.recommendations.is_empty());
            },
            _ => {}
        }
    }
}

#[test]
fn test_cache_eviction_under_load() {
    let config = CacheConfig {
        max_entries: 10,
        ttl: Duration::from_secs(60),
        track_access: true,
        eviction_strategy: EvictionStrategy::LRU,
    };
    
    let cache = CertificateCache::with_config(config);
    
    // Add many entries rapidly
    for i in 0..100 {
        let cert = create_mock_cert(&format!("load-test-{}.com", i), 90, true);
        let key = format!("load-key-{}", i);
        cache.put(key, cert);
    }
    
    // Cache should respect max_entries limit
    assert!(cache.size() <= 10);
    
    // Most recent entries should be in cache
    for i in 90..100 {
        let key = format!("load-key-{}", i);
        assert!(cache.contains(&key), "Recent entry {} should be in cache", i);
    }
    
    // Older entries should be evicted
    for i in 0..10 {
        let key = format!("load-key-{}", i);
        assert!(!cache.contains(&key), "Old entry {} should be evicted", i);
    }
}

#[test]
fn test_retry_with_different_error_types() {
    let retry_config = RetryConfig {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(100),
        backoff_multiplier: 2.0,
        jitter: false,
    };
    
    // Test retryable errors
    let retryable_errors = vec![
        CheckSSLError::NetworkError("Network issue".to_string()),
        CheckSSLError::TimeoutError("Timeout".to_string()),
        CheckSSLError::DnsResolutionError("DNS failed".to_string()),
    ];
    
    for error in retryable_errors {
        let mut attempt = 0;
        let error_clone = error.clone();
        
        let result = retry_with_backoff(&retry_config, || -> Result<(), CheckSSLError> {
            attempt += 1;
            if attempt < 3 {
                Err(error_clone.clone())
            } else {
                Ok(())
            }
        });
        
        assert!(result.is_ok());
        assert_eq!(attempt, 3);
    }
    
    // Test non-retryable errors
    let non_retryable_errors = vec![
        CheckSSLError::CertificateParseError("Parse failed".to_string()),
        CheckSSLError::ValidationError("Invalid cert".to_string()),
    ];
    
    for error in non_retryable_errors {
        let mut attempt = 0;
        
        let result = retry_with_backoff(&retry_config, || -> Result<(), CheckSSLError> {
            attempt += 1;
            Err(error.clone())
        });
        
        assert!(result.is_err());
        assert_eq!(attempt, 1); // Should not retry
    }
}

#[test]
fn test_complete_certificate_validation_flow() {
    // Simulate a complete certificate validation flow
    let cert = create_mock_cert("complete-test.com", 90, true);
    
    // Step 1: Basic validation
    assert!(cert.server.is_valid);
    assert!(cert.server.days_to_expiration > 0);
    
    // Step 2: Security analysis
    let analysis = analyze_certificate(&cert);
    assert!(analysis.security_level >= SecurityLevel::Acceptable);
    
    // Step 3: Cache the result
    let cache = CertificateCache::new();
    let key = CertificateCache::generate_key("complete-test.com", 443);
    cache.put(key.clone(), cert.clone());
    
    // Step 4: Retrieve from cache
    let cached = cache.get(&key);
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().server.common_name, cert.server.common_name);
    
    // Step 5: Verify cache statistics
    let stats = cache.statistics();
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 0);
}

#[test]
fn test_expired_certificate_handling() {
    let expired_cert = create_mock_cert("expired.com", -10, false);
    
    // Analyze the expired certificate
    let analysis = analyze_certificate(&expired_cert);
    
    // Should detect expiration
    assert_eq!(analysis.security_level, SecurityLevel::Critical);
    assert!(analysis.issues.iter().any(|issue| {
        issue.description.contains("expired")
    }));
    
    // Cache should still work with expired certificates
    let cache = CertificateCache::new();
    let key = CertificateCache::generate_key("expired.com", 443);
    cache.put(key.clone(), expired_cert.clone());
    
    let cached = cache.get(&key);
    assert!(cached.is_some());
    assert!(!cached.unwrap().server.is_valid);
}

#[test]
fn test_certificate_chain_depth_analysis() {
    let mut cert = create_mock_cert("chain-test.com", 90, true);
    
    // Test different chain lengths
    for chain_length in 1..=5 {
        cert.chain_length = chain_length;
        
        // For chain_length == 1, there should be no intermediate
        if chain_length == 1 {
            cert.intermediate.is_ca = false;
        } else {
            cert.intermediate.is_ca = true;
        }
        
        let analysis = analyze_certificate(&cert);
        assert_eq!(analysis.details.chain_analysis.chain_length, chain_length);
        
        if chain_length == 1 {
            assert!(!analysis.details.chain_analysis.has_intermediate);
        } else {
            assert!(analysis.details.chain_analysis.has_intermediate);
        }
    }
}

#[test]
fn test_mixed_security_certificate_chain() {
    // Create a certificate with mixed security levels in the chain
    let mut cert = create_mock_cert("mixed-security.com", 90, true);
    
    // Strong server certificate
    cert.server.signature_algorithm = "SHA384withECDSA".to_string();
    cert.server.public_key_algorithm = "EC".to_string();
    cert.server.public_key_size = Some(384);
    
    // Weak intermediate certificate
    cert.intermediate.signature_algorithm = "SHA1withRSA".to_string();
    
    let analysis = analyze_certificate(&cert);
    
    // Overall security should be limited by weakest link
    assert!(analysis.security_level <= SecurityLevel::Weak);
    assert!(analysis.details.chain_analysis.weakest_link.is_some());
    assert!(analysis.details.chain_analysis.weakest_link.as_ref().unwrap().contains("SHA1"));
}

// Mock implementation for testing OCSP with retry
struct MockOcspChecker {
    attempts: Arc<Mutex<i32>>,
    success_after: i32,
}

impl MockOcspChecker {
    fn new(success_after: i32) -> Self {
        MockOcspChecker {
            attempts: Arc::new(Mutex::new(0)),
            success_after,
        }
    }
    
    fn check(&self) -> Result<OcspStatus, CheckSSLError> {
        let mut attempts = self.attempts.lock().unwrap();
        *attempts += 1;
        
        if *attempts < self.success_after {
            Err(CheckSSLError::OcspError("OCSP check failed".to_string()))
        } else {
            Ok(OcspStatus::Good)
        }
    }
}

#[test]
fn test_ocsp_with_retry_integration() {
    let ocsp_checker = MockOcspChecker::new(3);
    let retry_config = RetryConfig {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
        backoff_multiplier: 2.0,
        jitter: false,
    };
    
    let result = retry_with_backoff(&retry_config, || ocsp_checker.check());
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), OcspStatus::Good);
    assert_eq!(*ocsp_checker.attempts.lock().unwrap(), 3);
}