use checkssl::{CheckSSL, CheckSSLConfig, CheckSSLError};
use std::time::Duration;

#[test]
#[ignore]
fn test_multiple_valid_domains() {
    let domains = vec![
        "google.com",
        "github.com",
        "rust-lang.org",
        "stackoverflow.com",
        "mozilla.org",
    ];
    
    for domain in domains {
        let result = CheckSSL::from_domain(domain.to_string());
        assert!(result.is_ok(), "Failed to check certificate for {}", domain);
        let cert = result.unwrap();
        assert!(cert.server.is_valid, "Certificate invalid for {}", domain);
        assert!(cert.server.days_to_expiration > 0, "Certificate expired for {}", domain);
    }
}

#[test]
#[ignore]
fn test_badssl_certificates() {
    struct TestCase {
        domain: &'static str,
        should_fail: bool,
    }
    
    let test_cases = vec![
        TestCase { domain: "expired.badssl.com", should_fail: true },
        TestCase { domain: "wrong.host.badssl.com", should_fail: true },
        TestCase { domain: "self-signed.badssl.com", should_fail: true },
        TestCase { domain: "untrusted-root.badssl.com", should_fail: true },
        TestCase { domain: "sha256.badssl.com", should_fail: false },
    ];
    
    for tc in test_cases {
        let result = CheckSSL::from_domain(tc.domain.to_string());
        if tc.should_fail {
            assert!(result.is_err() || !result.as_ref().unwrap().server.is_valid,
                    "Expected failure for {}, but got success", tc.domain);
        } else {
            assert!(result.is_ok(), "Expected success for {}, but got error: {:?}", 
                    tc.domain, result.err());
            if let Ok(cert) = result {
                assert!(cert.server.is_valid, "Certificate should be valid for {}", tc.domain);
            }
        }
    }
}

#[test]
fn test_async_certificate_check() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    let future = CheckSSL::from_domain_async("rust-lang.org".to_string());
    
    runtime.block_on(async {
        let result = future.await;
        assert!(result.is_ok());
        let cert = result.unwrap();
        assert!(cert.server.is_valid);
    });
}

#[test]
fn test_concurrent_checks() {
    use std::thread;
    use std::sync::Arc;
    use std::sync::Mutex;
    
    let domains = vec![
        "google.com",
        "github.com",
        "rust-lang.org",
    ];
    
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];
    
    for domain in domains {
        let results_clone = Arc::clone(&results);
        let handle = thread::spawn(move || {
            let result = CheckSSL::from_domain(domain.to_string());
            let mut results = results_clone.lock().unwrap();
            results.push((domain, result));
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let results = results.lock().unwrap();
    assert_eq!(results.len(), 3);
    
    for (domain, result) in results.iter() {
        assert!(result.is_ok(), "Failed for domain: {}", domain);
    }
}

#[test]
fn test_various_tls_versions() {
    let domains_with_modern_tls = vec![
        "google.com",
        "cloudflare.com",
    ];
    
    for domain in domains_with_modern_tls {
        let result = CheckSSL::from_domain(domain.to_string());
        if let Ok(cert) = result {
            assert!(cert.protocol_version.contains("TLS"));
            println!("Domain {} uses {}", domain, cert.protocol_version);
        }
    }
}

#[test]
fn test_certificate_chain_depth() {
    let test_cases = vec![
        ("google.com", 2, 4),
        ("github.com", 2, 4),
        ("rust-lang.org", 2, 4),
    ];
    
    for (domain, min_depth, max_depth) in test_cases {
        let result = CheckSSL::from_domain(domain.to_string());
        if let Ok(cert) = result {
            assert!(cert.chain_length >= min_depth && cert.chain_length <= max_depth,
                    "Chain length {} for {} is outside expected range [{}, {}]",
                    cert.chain_length, domain, min_depth, max_depth);
        }
    }
}

#[test]
fn test_san_validation() {
    let result = CheckSSL::from_domain("www.github.com".to_string());
    if let Ok(cert) = result {
        let has_matching_san = cert.server.sans.iter().any(|san| {
            san == "www.github.com" || 
            san == "github.com" || 
            san == "*.github.com"
        });
        assert!(has_matching_san, "No matching SAN found for www.github.com");
    }
}

#[test]
fn test_certificate_algorithms() {
    let domains = vec!["google.com", "github.com"];
    
    for domain in domains {
        let result = CheckSSL::from_domain(domain.to_string());
        if let Ok(cert) = result {
            assert!(!cert.server.signature_algorithm.is_empty());
            assert!(!cert.server.public_key_algorithm.is_empty());
            
            let valid_sig_algos = vec!["SHA256WithRSAEncryption", "SHA384WithRSAEncryption", 
                                       "SHA256WithECDSA", "SHA384WithECDSA",
                                       "RSA-SHA256", "RSA-SHA384", "ECDSA-SHA256", "ECDSA-SHA384"];
            let has_valid_algo = valid_sig_algos.iter()
                .any(|algo| cert.server.signature_algorithm.contains(algo));
            assert!(has_valid_algo, "Unexpected signature algorithm: {}", 
                    cert.server.signature_algorithm);
        }
    }
}

#[test]
fn test_expiration_warning_threshold() {
    let result = CheckSSL::from_domain("google.com".to_string());
    if let Ok(cert) = result {
        if cert.server.days_to_expiration < 30 {
            println!("WARNING: Certificate for google.com expires in {} days", 
                     cert.server.days_to_expiration);
        }
        
        assert!(cert.server.days_to_expiration > 7, 
                "Certificate expires too soon: {} days", 
                cert.server.days_to_expiration);
    }
}

#[test]
fn test_custom_port_scenarios() {
    struct PortTest {
        domain: &'static str,
        port: u16,
        should_succeed: bool,
    }
    
    let tests = vec![
        PortTest { domain: "google.com", port: 443, should_succeed: true },
        PortTest { domain: "google.com", port: 80, should_succeed: false },
        PortTest { domain: "localhost", port: 8443, should_succeed: false },
    ];
    
    for test in tests {
        let config = CheckSSLConfig {
            timeout: Duration::from_secs(3),
            port: test.port,
        };
        
        let result = CheckSSL::from_domain_with_config(test.domain.to_string(), config);
        
        if test.should_succeed {
            assert!(result.is_ok(), "Expected success for {}:{}", test.domain, test.port);
        } else {
            assert!(result.is_err(), "Expected failure for {}:{}", test.domain, test.port);
        }
    }
}

#[test]
fn test_fingerprint_uniqueness() {
    use std::collections::HashSet;
    
    let domains = vec!["google.com", "github.com", "rust-lang.org"];
    let mut fingerprints = HashSet::new();
    
    for domain in domains {
        let result = CheckSSL::from_domain(domain.to_string());
        if let Ok(cert) = result {
            assert!(fingerprints.insert(cert.server.fingerprint_sha256.clone()),
                    "Duplicate fingerprint found for {}", domain);
        }
    }
}

#[test]
fn test_error_handling_scenarios() {
    let test_cases = vec![
        ("", "empty domain"),
        ("not-a-valid-domain-xyz123.invalid", "invalid domain"),
        ("192.168.1.1", "IP address without cert"),
        ("::::1", "invalid format"),
    ];
    
    for (domain, description) in test_cases {
        let result = CheckSSL::from_domain(domain.to_string());
        assert!(result.is_err(), "Expected error for {}: {}", description, domain);
        
        match result.unwrap_err() {
            CheckSSLError::InvalidDomainError(_) |
            CheckSSLError::DnsResolutionError(_) |
            CheckSSLError::NetworkError(_) |
            CheckSSLError::TimeoutError(_) => {},
            err => panic!("Unexpected error type for {}: {:?}", description, err),
        }
    }
}

#[test]
#[ignore]
fn test_performance_benchmark() {
    use std::time::Instant;
    
    let domain = "google.com";
    let iterations = 10;
    let mut durations = Vec::new();
    
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = CheckSSL::from_domain(domain.to_string());
        let duration = start.elapsed();
        durations.push(duration);
    }
    
    let total: Duration = durations.iter().sum();
    let avg = total / iterations as u32;
    
    println!("Average time for {}: {:?}", domain, avg);
    assert!(avg < Duration::from_secs(5), "Check taking too long: {:?}", avg);
    
    let min = durations.iter().min().unwrap();
    let max = durations.iter().max().unwrap();
    println!("Min: {:?}, Max: {:?}", min, max);
}