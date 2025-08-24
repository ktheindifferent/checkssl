//! Comprehensive tests for cache implementation

use checkssl::{
    CertificateCache, CacheConfig, EvictionStrategy, check_with_cache, global_cache,
    Cert, ServerCert, IntermediateCert, CheckSSLError
};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

mod fixtures;
use fixtures::create_mock_cert;

#[test]
fn test_ttl_expiration() {
    let config = CacheConfig {
        max_entries: 10,
        ttl: Duration::from_millis(100),
        track_access: true,
        eviction_strategy: EvictionStrategy::LRU,
    };
    
    let cache = CertificateCache::with_config(config);
    let cert = create_mock_cert("example.com", 90, true);
    
    // Add to cache
    let key = CertificateCache::generate_key("example.com", 443);
    cache.put(key.clone(), cert.clone());
    
    // Should be in cache immediately
    assert!(cache.contains(&key));
    let retrieved = cache.get(&key);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().server.common_name, "example.com");
    
    // Wait for TTL to expire
    thread::sleep(Duration::from_millis(150));
    
    // Should no longer be in cache
    assert!(!cache.contains(&key));
    assert!(cache.get(&key).is_none());
    
    // Check statistics
    let stats = cache.statistics();
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.evictions, 1);
}

#[test]
fn test_cache_eviction_lru() {
    let config = CacheConfig {
        max_entries: 3,
        ttl: Duration::from_secs(3600),
        track_access: true,
        eviction_strategy: EvictionStrategy::LRU,
    };
    
    let cache = CertificateCache::with_config(config);
    
    // Add 3 entries
    for i in 1..=3 {
        let cert = create_mock_cert(&format!("domain{}.com", i), 90, true);
        cache.put(format!("key{}", i), cert);
        thread::sleep(Duration::from_millis(10)); // Ensure different access times
    }
    
    // Access key1 and key2 to make them more recently used
    cache.get("key1");
    thread::sleep(Duration::from_millis(10));
    cache.get("key2");
    thread::sleep(Duration::from_millis(10));
    
    // Add a 4th entry, should evict key3 (least recently used)
    let cert4 = create_mock_cert("domain4.com", 90, true);
    cache.put("key4".to_string(), cert4);
    
    assert!(cache.contains("key1"));
    assert!(cache.contains("key2"));
    assert!(!cache.contains("key3")); // Should be evicted
    assert!(cache.contains("key4"));
}

#[test]
fn test_cache_eviction_lfu() {
    let config = CacheConfig {
        max_entries: 3,
        ttl: Duration::from_secs(3600),
        track_access: true,
        eviction_strategy: EvictionStrategy::LFU,
    };
    
    let cache = CertificateCache::with_config(config);
    
    // Add 3 entries
    for i in 1..=3 {
        let cert = create_mock_cert(&format!("domain{}.com", i), 90, true);
        cache.put(format!("key{}", i), cert);
    }
    
    // Access key1 three times, key2 twice, key3 once (initial get counts as access)
    for _ in 0..3 {
        cache.get("key1");
    }
    for _ in 0..2 {
        cache.get("key2");
    }
    cache.get("key3");
    
    // Add a 4th entry, should evict key3 (least frequently used)
    let cert4 = create_mock_cert("domain4.com", 90, true);
    cache.put("key4".to_string(), cert4);
    
    assert!(cache.contains("key1"));
    assert!(cache.contains("key2"));
    assert!(!cache.contains("key3")); // Should be evicted
    assert!(cache.contains("key4"));
}

#[test]
fn test_cache_eviction_fifo() {
    let config = CacheConfig {
        max_entries: 3,
        ttl: Duration::from_secs(3600),
        track_access: true,
        eviction_strategy: EvictionStrategy::FIFO,
    };
    
    let cache = CertificateCache::with_config(config);
    
    // Add 3 entries with delays to ensure order
    for i in 1..=3 {
        let cert = create_mock_cert(&format!("domain{}.com", i), 90, true);
        cache.put(format!("key{}", i), cert);
        thread::sleep(Duration::from_millis(10));
    }
    
    // Access patterns shouldn't matter for FIFO
    cache.get("key1");
    cache.get("key1");
    cache.get("key2");
    
    // Add a 4th entry, should evict key1 (first in)
    let cert4 = create_mock_cert("domain4.com", 90, true);
    cache.put("key4".to_string(), cert4);
    
    assert!(!cache.contains("key1")); // Should be evicted (first in)
    assert!(cache.contains("key2"));
    assert!(cache.contains("key3"));
    assert!(cache.contains("key4"));
}

#[test]
fn test_concurrent_cache_access() {
    let cache = Arc::new(CertificateCache::new());
    let barrier = Arc::new(Barrier::new(10));
    
    let handles: Vec<_> = (0..10).map(|i| {
        let cache = cache.clone();
        let barrier = barrier.clone();
        
        thread::spawn(move || {
            barrier.wait();
            
            // Each thread performs multiple operations
            for j in 0..10 {
                let key = format!("key_{}_{}", i, j);
                let cert = create_mock_cert(&format!("domain{}.com", i), 90, true);
                
                // Put
                cache.put(key.clone(), cert.clone());
                
                // Get
                let retrieved = cache.get(&key);
                assert!(retrieved.is_some());
                assert_eq!(retrieved.unwrap().server.common_name, format!("domain{}.com", i));
                
                // Check contains
                assert!(cache.contains(&key));
            }
        })
    }).collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Verify cache state
    assert!(cache.size() > 0);
    let stats = cache.statistics();
    assert_eq!(stats.hits, 100); // 10 threads * 10 gets each
}

#[test]
fn test_cache_size_limits() {
    let config = CacheConfig {
        max_entries: 100,
        ttl: Duration::from_secs(3600),
        track_access: false,
        eviction_strategy: EvictionStrategy::LRU,
    };
    
    let cache = CertificateCache::with_config(config);
    
    // Add 150 entries (exceeds max_entries)
    for i in 0..150 {
        let cert = create_mock_cert(&format!("domain{}.com", i), 90, true);
        cache.put(format!("key{}", i), cert);
    }
    
    // Cache should not exceed max_entries
    assert!(cache.size() <= 100);
    
    let stats = cache.statistics();
    assert!(stats.evictions >= 50); // At least 50 evictions should have occurred
}

#[test]
fn test_cache_key_generation() {
    // Test basic key generation
    let key1 = CertificateCache::generate_key("Example.COM", 443);
    let key2 = CertificateCache::generate_key("example.com", 443);
    assert_eq!(key1, key2); // Should be case-insensitive
    
    let key3 = CertificateCache::generate_key("example.com", 8443);
    assert_ne!(key1, key3); // Different port
    
    // Test key with hash
    let data1 = b"additional data";
    let data2 = b"different data";
    let hash_key1 = CertificateCache::generate_key_with_hash("example.com", 443, data1);
    let hash_key2 = CertificateCache::generate_key_with_hash("example.com", 443, data2);
    assert_ne!(hash_key1, hash_key2); // Different additional data
    
    let hash_key3 = CertificateCache::generate_key_with_hash("example.com", 443, data1);
    assert_eq!(hash_key1, hash_key3); // Same inputs should produce same key
}

#[test]
fn test_cache_statistics() {
    let cache = CertificateCache::new();
    
    // Initial stats should be zero
    let stats = cache.statistics();
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
    assert_eq!(stats.evictions, 0);
    assert_eq!(stats.hit_rate(), 0.0);
    
    // Add and retrieve entries
    let cert1 = create_mock_cert("domain1.com", 90, true);
    cache.put("key1".to_string(), cert1);
    
    cache.get("key1"); // Hit
    cache.get("key2"); // Miss
    cache.get("key1"); // Hit
    cache.get("key3"); // Miss
    
    let stats = cache.statistics();
    assert_eq!(stats.hits, 2);
    assert_eq!(stats.misses, 2);
    assert_eq!(stats.hit_rate(), 0.5);
}

#[test]
fn test_cache_clear() {
    let cache = CertificateCache::new();
    
    // Add multiple entries
    for i in 0..10 {
        let cert = create_mock_cert(&format!("domain{}.com", i), 90, true);
        cache.put(format!("key{}", i), cert);
    }
    
    assert_eq!(cache.size(), 10);
    
    // Clear cache
    cache.clear();
    
    assert_eq!(cache.size(), 0);
    for i in 0..10 {
        assert!(!cache.contains(&format!("key{}", i)));
    }
    
    let stats = cache.statistics();
    assert_eq!(stats.evictions, 10);
}

#[test]
fn test_remove_expired_entries() {
    let config = CacheConfig {
        max_entries: 100,
        ttl: Duration::from_millis(100),
        track_access: false,
        eviction_strategy: EvictionStrategy::TimeBasedOnly,
    };
    
    let cache = CertificateCache::with_config(config);
    
    // Add entries at different times
    for i in 0..5 {
        let cert = create_mock_cert(&format!("domain{}.com", i), 90, true);
        cache.put(format!("key{}", i), cert);
        thread::sleep(Duration::from_millis(30));
    }
    
    // Some entries should still be valid
    assert!(cache.size() > 0);
    
    // Wait for all to expire
    thread::sleep(Duration::from_millis(150));
    
    // Remove expired entries
    let removed = cache.remove_expired();
    assert_eq!(removed, 5);
    assert_eq!(cache.size(), 0);
}

#[test]
fn test_cache_with_wrapper_function() {
    let cache = CertificateCache::new();
    let mut call_count = 0;
    
    // First call should execute the check function
    let result = check_with_cache(
        &cache,
        "example.com",
        443,
        || -> Result<Cert, CheckSSLError> {
            call_count += 1;
            Ok(create_mock_cert("example.com", 90, true))
        }
    );
    
    assert!(result.is_ok());
    assert_eq!(call_count, 1);
    
    // Second call should use cached value
    let result2 = check_with_cache(
        &cache,
        "example.com",
        443,
        || -> Result<Cert, CheckSSLError> {
            call_count += 1;
            Ok(create_mock_cert("example.com", 90, true))
        }
    );
    
    assert!(result2.is_ok());
    assert_eq!(call_count, 1); // Should not have called the function again
}

#[test]
fn test_global_cache_instance() {
    let cache = global_cache();
    
    // Should be able to use the global cache
    let cert = create_mock_cert("global.com", 90, true);
    let key = CertificateCache::generate_key("global.com", 443);
    
    cache.put(key.clone(), cert.clone());
    
    let retrieved = cache.get(&key);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().server.common_name, "global.com");
}

#[test]
fn test_cache_entry_details() {
    let cache = CertificateCache::new();
    let cert = create_mock_cert("example.com", 90, true);
    let key = "test_key".to_string();
    
    cache.put(key.clone(), cert);
    
    // Get entry details
    let details = cache.get_entry_details(&key);
    assert!(details.is_some());
    
    let details = details.unwrap();
    assert_eq!(details.domain, key);
    assert_eq!(details.access_count, 0); // Haven't accessed yet
    assert!(details.age < Duration::from_secs(1));
    assert!(details.ttl_remaining > Duration::from_secs(3500)); // Default TTL is 1 hour
}

#[test]
fn test_get_cached_domains() {
    let cache = CertificateCache::new();
    
    // Add multiple domains
    let domains = vec!["example.com", "test.com", "demo.org"];
    for domain in &domains {
        let cert = create_mock_cert(domain, 90, true);
        let key = CertificateCache::generate_key(domain, 443);
        cache.put(key, cert);
    }
    
    let cached_domains = cache.get_cached_domains();
    assert_eq!(cached_domains.len(), 3);
    
    // Verify all domains are present (order may vary)
    for domain in domains {
        let key = CertificateCache::generate_key(domain, 443);
        assert!(cached_domains.contains(&key));
    }
}

#[test]
fn test_time_based_only_eviction() {
    let config = CacheConfig {
        max_entries: 1000,
        ttl: Duration::from_millis(100),
        track_access: false,
        eviction_strategy: EvictionStrategy::TimeBasedOnly,
    };
    
    let cache = CertificateCache::with_config(config);
    
    // Add many entries (would exceed normal limits)
    for i in 0..200 {
        let cert = create_mock_cert(&format!("domain{}.com", i), 90, true);
        cache.put(format!("key{}", i), cert);
    }
    
    // Should accept all entries (no size-based eviction)
    assert_eq!(cache.size(), 200);
    
    // Wait for TTL
    thread::sleep(Duration::from_millis(150));
    
    // All should be expired now
    for i in 0..200 {
        assert!(!cache.contains(&format!("key{}", i)));
    }
}