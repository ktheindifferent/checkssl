//! Certificate caching functionality.
//!
//! This module provides in-memory caching of certificate data
//! to improve performance for repeated certificate checks.

use crate::{Cert, CheckSSLError};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use sha2::{Sha256, Digest};

/// Entry in the certificate cache
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The cached certificate data
    pub cert: Cert,
    /// When this entry was cached
    pub cached_at: Instant,
    /// How many times this entry has been accessed
    pub access_count: usize,
    /// Last time this entry was accessed
    pub last_accessed: Instant,
}

/// Configuration for the certificate cache
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries in the cache
    pub max_entries: usize,
    /// Time-to-live for cache entries
    pub ttl: Duration,
    /// Whether to update access time on cache hits
    pub track_access: bool,
    /// Cache eviction strategy
    pub eviction_strategy: EvictionStrategy,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_entries: 1000,
            ttl: Duration::from_secs(3600), // 1 hour
            track_access: true,
            eviction_strategy: EvictionStrategy::LRU,
        }
    }
}

/// Cache eviction strategies
#[derive(Debug, Clone, PartialEq)]
pub enum EvictionStrategy {
    /// Least Recently Used
    LRU,
    /// Least Frequently Used
    LFU,
    /// First In First Out
    FIFO,
    /// Time-based only (no size limit)
    TimeBasedOnly,
}

/// Thread-safe certificate cache
pub struct CertificateCache {
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    config: CacheConfig,
    stats: Arc<RwLock<CacheStatistics>>,
}

/// Statistics about cache usage
#[derive(Debug, Default, Clone)]
pub struct CacheStatistics {
    pub hits: usize,
    pub misses: usize,
    pub evictions: usize,
    pub total_entries: usize,
    pub total_size_bytes: usize,
}

impl CacheStatistics {
    /// Calculate cache hit rate
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

impl CertificateCache {
    /// Create a new certificate cache with default configuration
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Create a new certificate cache with custom configuration
    pub fn with_config(config: CacheConfig) -> Self {
        CertificateCache {
            cache: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(CacheStatistics::default())),
        }
    }

    /// Generate cache key from domain and port
    pub fn generate_key(domain: &str, port: u16) -> String {
        format!("{}:{}", domain.to_lowercase(), port)
    }

    /// Generate cache key with hash for complex queries
    pub fn generate_key_with_hash(domain: &str, port: u16, additional_data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update(port.to_be_bytes());
        hasher.update(additional_data);
        let hash = hasher.finalize();
        format!("{}:{}:{:x}", domain.to_lowercase(), port, hash)
    }

    /// Get a certificate from the cache
    pub fn get(&self, key: &str) -> Result<Option<Cert>, CheckSSLError> {
        let mut cache = self.cache.write().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire write lock on cache: {}", e)))?;
        let mut stats = self.stats.write().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire write lock on stats: {}", e)))?;

        if let Some(entry) = cache.get_mut(key) {
            // Check if entry has expired
            if entry.cached_at.elapsed() > self.config.ttl {
                cache.remove(key);
                stats.evictions += 1;
                stats.misses += 1;
                return Ok(None);
            }

            // Update access tracking
            if self.config.track_access {
                entry.access_count += 1;
                entry.last_accessed = Instant::now();
            }

            stats.hits += 1;
            Ok(Some(entry.cert.clone()))
        } else {
            stats.misses += 1;
            Ok(None)
        }
    }

    /// Put a certificate into the cache
    pub fn put(&self, key: String, cert: Cert) -> Result<(), CheckSSLError> {
        let mut cache = self.cache.write().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire write lock on cache: {}", e)))?;
        let mut stats = self.stats.write().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire write lock on stats: {}", e)))?;

        // Check if we need to evict entries
        if self.config.eviction_strategy != EvictionStrategy::TimeBasedOnly {
            while cache.len() >= self.config.max_entries {
                self.evict_one(&mut cache, &mut stats);
            }
        }

        // Add new entry
        let entry = CacheEntry {
            cert,
            cached_at: Instant::now(),
            access_count: 0,
            last_accessed: Instant::now(),
        };

        cache.insert(key, entry);
        stats.total_entries = cache.len();
        Ok(())
    }

    /// Evict one entry based on the configured strategy
    fn evict_one(&self, cache: &mut HashMap<String, CacheEntry>, stats: &mut CacheStatistics) {
        let key_to_evict = match self.config.eviction_strategy {
            EvictionStrategy::LRU => {
                // Find least recently used
                cache.iter()
                    .min_by_key(|(_, entry)| entry.last_accessed)
                    .map(|(key, _)| key.clone())
            }
            EvictionStrategy::LFU => {
                // Find least frequently used
                cache.iter()
                    .min_by_key(|(_, entry)| entry.access_count)
                    .map(|(key, _)| key.clone())
            }
            EvictionStrategy::FIFO => {
                // Find oldest entry
                cache.iter()
                    .min_by_key(|(_, entry)| entry.cached_at)
                    .map(|(key, _)| key.clone())
            }
            EvictionStrategy::TimeBasedOnly => None,
        };

        if let Some(key) = key_to_evict {
            cache.remove(&key);
            stats.evictions += 1;
        }
    }

    /// Clear all entries from the cache
    pub fn clear(&self) -> Result<(), CheckSSLError> {
        let mut cache = self.cache.write().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire write lock on cache: {}", e)))?;
        let mut stats = self.stats.write().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire write lock on stats: {}", e)))?;
        
        let count = cache.len();
        cache.clear();
        stats.evictions += count;
        stats.total_entries = 0;
        Ok(())
    }

    /// Remove expired entries from the cache
    pub fn remove_expired(&self) -> Result<usize, CheckSSLError> {
        let mut cache = self.cache.write().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire write lock on cache: {}", e)))?;
        let mut stats = self.stats.write().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire write lock on stats: {}", e)))?;
        
        let now = Instant::now();
        let expired_keys: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.cached_at) > self.config.ttl)
            .map(|(key, _)| key.clone())
            .collect();

        let count = expired_keys.len();
        for key in expired_keys {
            cache.remove(&key);
        }
        
        stats.evictions += count;
        stats.total_entries = cache.len();
        Ok(count)
    }

    /// Get cache statistics
    pub fn statistics(&self) -> Result<CacheStatistics, CheckSSLError> {
        Ok(self.stats.read().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire read lock on stats: {}", e)))?.clone())
    }

    /// Get the current size of the cache
    pub fn size(&self) -> Result<usize, CheckSSLError> {
        Ok(self.cache.read().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire read lock on cache: {}", e)))?.len())
    }

    /// Check if a key exists in the cache (without updating access)
    pub fn contains(&self, key: &str) -> Result<bool, CheckSSLError> {
        let cache = self.cache.read().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire read lock on cache: {}", e)))?;
        if let Some(entry) = cache.get(key) {
            Ok(entry.cached_at.elapsed() <= self.config.ttl)
        } else {
            Ok(false)
        }
    }

    /// Get all cached domains
    pub fn get_cached_domains(&self) -> Result<Vec<String>, CheckSSLError> {
        Ok(self.cache.read().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire read lock on cache: {}", e)))?.keys().cloned().collect())
    }

    /// Get cache entry details for debugging
    pub fn get_entry_details(&self, key: &str) -> Result<Option<CacheEntryDetails>, CheckSSLError> {
        let cache = self.cache.read().map_err(|e| CheckSSLError::LockError(format!("Failed to acquire read lock on cache: {}", e)))?;
        Ok(cache.get(key).map(|entry| CacheEntryDetails {
            domain: key.to_string(),
            cached_at: entry.cached_at,
            access_count: entry.access_count,
            last_accessed: entry.last_accessed,
            age: entry.cached_at.elapsed(),
            ttl_remaining: self.config.ttl.saturating_sub(entry.cached_at.elapsed()),
        }))
    }
}

/// Detailed information about a cache entry
#[derive(Debug)]
pub struct CacheEntryDetails {
    pub domain: String,
    pub cached_at: Instant,
    pub access_count: usize,
    pub last_accessed: Instant,
    pub age: Duration,
    pub ttl_remaining: Duration,
}

lazy_static::lazy_static! {
    // Global cache instance (optional, for convenience)  
    static ref GLOBAL_CACHE: CertificateCache = CertificateCache::new();
}

/// Get the global cache instance
pub fn global_cache() -> &'static CertificateCache {
    &GLOBAL_CACHE
}

/// Wrapper for certificate checking with caching
pub fn check_with_cache<F>(
    cache: &CertificateCache,
    domain: &str,
    port: u16,
    check_fn: F,
) -> Result<Cert, CheckSSLError>
where
    F: FnOnce() -> Result<Cert, CheckSSLError>,
{
    let key = CertificateCache::generate_key(domain, port);
    
    // Try to get from cache first
    if let Some(cert) = cache.get(&key)? {
        return Ok(cert);
    }
    
    // Not in cache, perform the check
    let cert = check_fn()?;
    
    // Store in cache
    cache.put(key, cert.clone())?;
    
    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServerCert, IntermediateCert};

    fn create_test_cert(domain: &str) -> Cert {
        Cert {
            server: ServerCert {
                common_name: domain.to_string(),
                is_valid: true,
                days_to_expiration: 90,
                ..Default::default()
            },
            intermediate: IntermediateCert::default(),
            chain_length: 2,
            protocol_version: "TLSv1.3".to_string(),
        }
    }

    #[test]
    fn test_cache_basic_operations() {
        let cache = CertificateCache::new();
        let key = CertificateCache::generate_key("example.com", 443);
        let cert = create_test_cert("example.com");
        
        // Put and get
        cache.put(key.clone(), cert.clone()).unwrap();
        assert!(cache.contains(&key).unwrap());
        
        let retrieved = cache.get(&key).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().server.common_name, "example.com");
        
        // Check statistics
        let stats = cache.statistics().unwrap();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn test_cache_expiration() {
        let config = CacheConfig {
            ttl: Duration::from_millis(50),
            ..Default::default()
        };
        let cache = CertificateCache::with_config(config);
        let key = CertificateCache::generate_key("example.com", 443);
        let cert = create_test_cert("example.com");
        
        cache.put(key.clone(), cert).unwrap();
        assert!(cache.contains(&key).unwrap());
        
        // Wait for expiration
        std::thread::sleep(Duration::from_millis(60));
        
        assert!(!cache.contains(&key).unwrap());
        assert!(cache.get(&key).unwrap().is_none());
    }

    #[test]
    fn test_cache_eviction_lru() {
        let config = CacheConfig {
            max_entries: 2,
            eviction_strategy: EvictionStrategy::LRU,
            ..Default::default()
        };
        let cache = CertificateCache::with_config(config);
        
        // Add 3 entries to a cache with max 2
        cache.put("key1".to_string(), create_test_cert("domain1.com")).unwrap();
        cache.put("key2".to_string(), create_test_cert("domain2.com")).unwrap();
        
        // Access key1 to make it more recently used
        cache.get("key1").unwrap();
        
        // Add a third entry, should evict key2 (least recently used)
        cache.put("key3".to_string(), create_test_cert("domain3.com")).unwrap();
        
        assert!(cache.contains("key1").unwrap());
        assert!(!cache.contains("key2").unwrap());
        assert!(cache.contains("key3").unwrap());
    }

    #[test]
    fn test_cache_key_generation() {
        let key1 = CertificateCache::generate_key("Example.COM", 443);
        let key2 = CertificateCache::generate_key("example.com", 443);
        assert_eq!(key1, key2); // Should be case-insensitive
        
        let key3 = CertificateCache::generate_key("example.com", 8443);
        assert_ne!(key1, key3); // Different port
    }

    #[test]
    fn test_cache_statistics() {
        let cache = CertificateCache::new();
        
        cache.put("key1".to_string(), create_test_cert("domain1.com")).unwrap();
        cache.get("key1").unwrap();
        cache.get("key2").unwrap(); // Miss
        
        let stats = cache.statistics().unwrap();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate(), 0.5);
    }

    #[test]
    fn test_lock_poisoning_handling() {
        use std::panic;
        use std::thread;

        let cache = Arc::new(CertificateCache::new());
        let cache_clone = Arc::clone(&cache);
        
        // Spawn a thread that will panic while holding the lock
        let handle = thread::spawn(move || {
            // Acquire write lock and panic
            let _guard = cache_clone.cache.write().unwrap();
            panic!("Intentional panic to poison the lock");
        });
        
        // Wait for the thread to panic
        let _ = handle.join();
        
        // Now the lock is poisoned, operations should return LockError
        let result = cache.get("test_key");
        assert!(result.is_err());
        if let Err(CheckSSLError::LockError(msg)) = result {
            assert!(msg.contains("Failed to acquire write lock"));
        } else {
            panic!("Expected LockError");
        }
    }

    #[test]
    fn test_all_methods_handle_lock_errors() {
        use std::panic;
        use std::thread;

        // Test for cache lock poisoning
        {
            let cache = Arc::new(CertificateCache::new());
            let cache_clone = Arc::clone(&cache);
            
            let handle = thread::spawn(move || {
                let _guard = cache_clone.cache.write().unwrap();
                panic!("Poison cache lock");
            });
            let _ = handle.join();
            
            // Test all methods that access cache
            assert!(cache.get("key").is_err());
            assert!(cache.put("key".to_string(), create_test_cert("test.com")).is_err());
            assert!(cache.clear().is_err());
            assert!(cache.remove_expired().is_err());
            assert!(cache.size().is_err());
            assert!(cache.contains("key").is_err());
            assert!(cache.get_cached_domains().is_err());
            assert!(cache.get_entry_details("key").is_err());
        }

        // Test for stats lock poisoning
        {
            let cache = Arc::new(CertificateCache::new());
            let cache_clone = Arc::clone(&cache);
            
            let handle = thread::spawn(move || {
                let _guard = cache_clone.stats.write().unwrap();
                panic!("Poison stats lock");
            });
            let _ = handle.join();
            
            // Test methods that access stats
            assert!(cache.statistics().is_err());
            // get and put also access stats
            assert!(cache.get("key").is_err());
            assert!(cache.put("key".to_string(), create_test_cert("test.com")).is_err());
        }
    }

    #[test]
    fn test_error_propagation_in_check_with_cache() {
        use std::panic;
        use std::thread;

        let cache = Arc::new(CertificateCache::new());
        let cache_clone = Arc::clone(&cache);
        
        // Poison the lock
        let handle = thread::spawn(move || {
            let _guard = cache_clone.cache.write().unwrap();
            panic!("Poison lock for check_with_cache test");
        });
        let _ = handle.join();
        
        // check_with_cache should propagate the lock error
        let result = check_with_cache(
            &cache,
            "example.com",
            443,
            || Ok(create_test_cert("example.com"))
        );
        
        assert!(result.is_err());
        if let Err(CheckSSLError::LockError(_)) = result {
            // Expected
        } else {
            panic!("Expected LockError from check_with_cache");
        }
    }
}