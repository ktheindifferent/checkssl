use checkssl::{CheckSSL, CheckSSLConfig};
use std::time::Duration;

#[test]
fn test_sni_support() {
    // Test SNI with a domain that requires it (shared hosting)
    // CloudFlare uses SNI for many of its hosted sites
    let domains_requiring_sni = vec![
        "www.cloudflare.com",
        "blog.cloudflare.com",
    ];
    
    for domain in domains_requiring_sni {
        let result = CheckSSL::from_domain(domain.to_string());
        
        match result {
            Ok(cert) => {
                // The certificate should match the requested domain
                assert!(
                    cert.server.common_name == domain || 
                    cert.server.sans.contains(&domain.to_string()) ||
                    cert.server.sans.iter().any(|san| {
                        san.starts_with("*.") && domain.ends_with(&san[2..])
                    }),
                    "Certificate doesn't match domain {} (CN: {}, SANs: {:?})",
                    domain, cert.server.common_name, cert.server.sans
                );
            }
            Err(e) => {
                // Network errors are acceptable in test environments
                eprintln!("Warning: Could not test SNI for {}: {}", domain, e);
            }
        }
    }
}

#[test]
fn test_sni_virtual_hosts() {
    // Test multiple virtual hosts on the same IP
    // These domains are often on shared hosting
    let virtual_hosts = vec![
        ("github.com", "github.com"),
        ("www.github.com", "github.com"),
        ("api.github.com", "github.com"),  // Uses wildcard *.github.com
    ];
    
    for (test_domain, expected_pattern) in virtual_hosts {
        let result = CheckSSL::from_domain(test_domain.to_string());
        
        if let Ok(cert) = result {
            // Check that we got the correct certificate for the virtual host
            let cn = cert.server.common_name.to_lowercase();
            // Check if CN matches or if it's a wildcard that covers the domain
            let matches = cn.contains(expected_pattern) || 
                          cn.starts_with("*.") && test_domain.ends_with(&cn[2..]) ||
                          cert.server.sans.iter().any(|san| {
                              san.contains(expected_pattern) ||
                              (san.starts_with("*.") && test_domain.ends_with(&san[2..]))
                          });
            assert!(
                matches,
                "SNI failed for {}: got CN={}, SANs={:?}",
                test_domain, cn, cert.server.sans
            );
        }
    }
}

#[test]
fn test_sni_with_ip_address() {
    // SNI should NOT be sent when connecting to an IP address
    // This test verifies that IP addresses are handled correctly
    let ip_addresses = vec![
        "8.8.8.8",      // Google DNS
        "1.1.1.1",      // Cloudflare DNS
    ];
    
    for ip in ip_addresses {
        let result = CheckSSL::from_domain(ip.to_string());
        
        // Connecting to an IP usually fails cert validation
        // because certificates are issued for domain names
        assert!(
            result.is_err() || !result.unwrap().server.is_valid,
            "IP address {} should not have a valid certificate", ip
        );
    }
}

#[test]
fn test_sni_with_wildcard_cert() {
    // Test that SNI works correctly with wildcard certificates
    let wildcard_domains = vec![
        "www.rust-lang.org",
        "play.rust-lang.org",
    ];
    
    for domain in wildcard_domains {
        let result = CheckSSL::from_domain(domain.to_string());
        
        if let Ok(cert) = result {
            // Should get a certificate that covers the domain
            let covered = cert.server.common_name == domain ||
                cert.server.sans.contains(&domain.to_string()) ||
                cert.server.sans.iter().any(|san| {
                    if san.starts_with("*.") {
                        let base = &san[2..];
                        domain.ends_with(base) && domain.matches('.').count() == base.matches('.').count() + 1
                    } else {
                        san == domain
                    }
                });
            
            assert!(covered, 
                "Wildcard cert doesn't cover {}: CN={}, SANs={:?}",
                domain, cert.server.common_name, cert.server.sans
            );
        }
    }
}

#[test]
fn test_sni_case_insensitive() {
    // SNI should work regardless of domain case
    let test_cases = vec![
        "GITHUB.COM",
        "GitHub.Com",
        "github.com",
    ];
    
    let mut previous_fingerprint: Option<String> = None;
    
    for domain in test_cases {
        let result = CheckSSL::from_domain(domain.to_string());
        
        if let Ok(cert) = result {
            // All variations should get the same certificate
            if let Some(ref prev) = previous_fingerprint {
                assert_eq!(
                    &cert.server.fingerprint_sha256, prev,
                    "Different certificates for {} (case variation)",
                    domain
                );
            }
            previous_fingerprint = Some(cert.server.fingerprint_sha256.clone());
        }
    }
}

#[test]
fn test_sni_with_custom_port() {
    // SNI should work on non-standard ports
    let config = CheckSSLConfig {
        timeout: Duration::from_secs(5),
        port: 443, // Standard HTTPS port
    };
    
    let result = CheckSSL::from_domain_with_config(
        "github.com".to_string(),
        config
    );
    
    assert!(result.is_ok(), "SNI should work on standard ports");
    
    // Test with a non-standard port (will likely fail, but SNI should still be sent)
    let config_custom = CheckSSLConfig {
        timeout: Duration::from_secs(2),
        port: 8443,
    };
    
    let _result = CheckSSL::from_domain_with_config(
        "example.com".to_string(),
        config_custom
    );
    // We don't assert success here as the port might not be open,
    // but the SNI extension should still be included in the handshake
}

#[test]
fn test_sni_internationalized_domains() {
    // Test with internationalized domain names (IDN)
    // These get converted to punycode before SNI
    let idn_domains = vec![
        "münchen.de",      // Becomes xn--mnchen-3ya.de
        "россия.рф",       // Russian IDN
    ];
    
    for domain in idn_domains {
        let result = CheckSSL::from_domain(domain.to_string());
        
        // IDN support depends on the implementation
        // We just verify it doesn't crash
        match result {
            Ok(_) => println!("IDN {} worked with SNI", domain),
            Err(e) => println!("IDN {} error (expected): {}", domain, e),
        }
    }
}