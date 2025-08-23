//! Batch certificate checking functionality.
//!
//! This module provides functionality to check multiple domains
//! in parallel or sequentially with configurable concurrency.

use crate::{CheckSSL, CheckSSLConfig, Cert};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::TryLockError;

/// Result of a batch certificate check
#[derive(Debug, Clone)]
pub struct BatchCheckResult {
    /// Domain that was checked
    pub domain: String,
    /// Result of the certificate check
    pub result: Result<Cert, String>,
    /// Time taken to check this domain
    pub duration: Duration,
    /// Timestamp when the check was performed
    pub checked_at: Instant,
}

/// Configuration for batch certificate checking
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of concurrent checks
    pub max_concurrent: usize,
    /// Configuration for individual certificate checks
    pub check_config: CheckSSLConfig,
    /// Continue on error or stop at first failure
    pub continue_on_error: bool,
    /// Delay between checks (rate limiting)
    pub delay_between_checks: Option<Duration>,
}

impl Default for BatchConfig {
    fn default() -> Self {
        BatchConfig {
            max_concurrent: 5,
            check_config: CheckSSLConfig::default(),
            continue_on_error: true,
            delay_between_checks: None,
        }
    }
}

/// Helper function to safely acquire a mutex lock with timeout
fn acquire_lock_with_timeout<T>(
    mutex: &Arc<Mutex<T>>,
    timeout: Duration,
) -> Result<MutexGuard<'_, T>, String> {
    let start = Instant::now();
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::WouldBlock) => {
                if start.elapsed() > timeout {
                    return Err("Lock acquisition timed out".to_string());
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::Poisoned(_)) => {
                // Attempt to recover from poisoned mutex
                // In production, you might want to handle this differently
                return Err("Mutex is poisoned".to_string());
            }
        }
    }
}

/// Check multiple domains in batch
pub fn batch_check_domains(
    domains: Vec<String>,
    config: BatchConfig,
) -> Vec<BatchCheckResult> {
    let results = Arc::new(Mutex::new(Vec::new()));
    let domains = Arc::new(domains);
    let config = Arc::new(config);
    
    let mut handles = vec![];
    let semaphore = Arc::new(Mutex::new(0usize));
    let lock_timeout = Duration::from_secs(5);
    
    for (index, domain) in domains.iter().enumerate() {
        let domain = domain.clone();
        let results_clone = Arc::clone(&results);
        let config_clone = Arc::clone(&config);
        let semaphore_clone = Arc::clone(&semaphore);
        
        // Wait if we've reached max concurrent checks
        loop {
            match acquire_lock_with_timeout(&semaphore, lock_timeout) {
                Ok(mut count) => {
                    if *count < config.max_concurrent {
                        *count += 1;
                        break;
                    }
                    drop(count);
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    eprintln!("Warning: Failed to acquire semaphore lock: {}", e);
                    // Add failed result for this domain
                    if let Ok(mut results_guard) = results.try_lock() {
                        results_guard.push(BatchCheckResult {
                            domain: domain.clone(),
                            result: Err(format!("Failed to acquire lock: {}", e)),
                            duration: Duration::ZERO,
                            checked_at: Instant::now(),
                        });
                    }
                    continue;
                }
            }
        }
        
        // Apply rate limiting delay if configured
        if let Some(delay) = config.delay_between_checks {
            if index > 0 {
                thread::sleep(delay);
            }
        }
        
        let handle = thread::spawn(move || {
            let start = Instant::now();
            let result = CheckSSL::from_domain_with_config(
                domain.clone(),
                config_clone.check_config.clone(),
            );
            let duration = start.elapsed();
            
            let batch_result = BatchCheckResult {
                domain: domain.clone(),
                result: result.map_err(|e| e.to_string()),
                duration,
                checked_at: Instant::now(),
            };
            
            // Try to store result with timeout
            let lock_timeout = Duration::from_secs(5);
            match acquire_lock_with_timeout(&results_clone, lock_timeout) {
                Ok(mut guard) => {
                    guard.push(batch_result);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to store result for {}: {}", domain, e);
                }
            }
            
            // Release semaphore
            match acquire_lock_with_timeout(&semaphore_clone, lock_timeout) {
                Ok(mut count) => {
                    *count = count.saturating_sub(1);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to release semaphore: {}", e);
                }
            }
        });
        
        handles.push(handle);
        
        // Check if we should continue on error
        if !config.continue_on_error {
            // Wait for this thread to complete and check result
            if let Some(handle) = handles.pop() {
                // Handle thread join failure gracefully
                match handle.join() {
                    Ok(_) => {
                        // Check if last result was an error
                        match acquire_lock_with_timeout(&results, lock_timeout) {
                            Ok(results_guard) => {
                                if let Some(last_result) = results_guard.last() {
                                    if last_result.result.is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Warning: Failed to check results: {}", e);
                            }
                        }
                    }
                    Err(_) => {
                        eprintln!("Warning: Thread panicked while checking domain");
                        // Continue processing other domains
                    }
                }
            }
        }
    }
    
    // Wait for all remaining threads to complete
    for handle in handles {
        // Handle thread join failures gracefully
        match handle.join() {
            Ok(_) => {},
            Err(_) => {
                eprintln!("Warning: A thread panicked during batch processing");
                // Continue to process results from successful threads
            }
        }
    }
    
    // Try to get final results with timeout
    let mut final_results = match acquire_lock_with_timeout(&results, Duration::from_secs(10)) {
        Ok(guard) => guard.clone(),
        Err(e) => {
            eprintln!("Error: Failed to retrieve final results: {}", e);
            Vec::new() // Return empty results if we can't get the lock
        }
    };
    
    // Sort results by domain name for consistent output
    final_results.sort_by(|a, b| a.domain.cmp(&b.domain));
    
    final_results
}

/// Check domains in groups with different configurations.
///
/// This function allows checking multiple groups of domains, where each group
/// can have its own configuration (timeout, port, etc.). This is useful when
/// checking different types of services that may require different settings.
///
/// # Arguments
///
/// * `domain_groups` - A HashMap where:
///   - Key: Group name (e.g., "production", "staging", "external_apis")
///   - Value: Tuple of (list of domains, configuration for this group)
/// * `max_concurrent` - Maximum number of concurrent checks per group
///
/// # Returns
///
/// Returns a HashMap where:
/// - Key: Group name
/// - Value: Vector of BatchCheckResult for all domains in that group
///
/// # Example
///
/// ```no_run
/// use checkssl::{batch_check_domains_grouped, CheckSSLConfig};
/// use std::collections::HashMap;
/// use std::time::Duration;
///
/// let mut groups = HashMap::new();
///
/// // Production servers with standard timeout
/// let prod_domains = vec!["api.example.com".to_string(), "www.example.com".to_string()];
/// let prod_config = CheckSSLConfig {
///     timeout: Duration::from_secs(5),
///     port: 443,
/// };
/// groups.insert("production".to_string(), (prod_domains, prod_config));
///
/// // Internal services on custom port with longer timeout
/// let internal_domains = vec!["service1.internal".to_string(), "service2.internal".to_string()];
/// let internal_config = CheckSSLConfig {
///     timeout: Duration::from_secs(10),
///     port: 8443,
/// };
/// groups.insert("internal".to_string(), (internal_domains, internal_config));
///
/// // Check all groups with max 5 concurrent checks per group
/// let results = batch_check_domains_grouped(groups, 5);
///
/// for (group_name, group_results) in results {
///     println!("Group {}: {} domains checked", group_name, group_results.len());
///     for result in group_results {
///         match result.result {
///             Ok(cert) => println!("  {} - Valid: {}", result.domain, cert.server.is_valid),
///             Err(e) => println!("  {} - Error: {}", result.domain, e),
///         }
///     }
/// }
/// ```
///
/// # Use Cases
///
/// - Monitoring different environments (production, staging, development)
/// - Checking services with different port configurations
/// - Grouping domains by criticality with different timeout settings
/// - Organizing certificate checks by team or service ownership
/// - Generating grouped reports for different stakeholders
pub fn batch_check_domains_grouped(
    domain_groups: HashMap<String, (Vec<String>, CheckSSLConfig)>,
    max_concurrent: usize,
) -> HashMap<String, Vec<BatchCheckResult>> {
    let mut all_results = HashMap::new();
    
    for (group_name, (domains, config)) in domain_groups {
        let batch_config = BatchConfig {
            max_concurrent,
            check_config: config,
            continue_on_error: true,
            delay_between_checks: None,
        };
        
        let results = batch_check_domains(domains, batch_config);
        all_results.insert(group_name, results);
    }
    
    all_results
}

/// Check domains and return statistics
pub struct BatchStatistics {
    pub total_checked: usize,
    pub successful: usize,
    pub failed: usize,
    pub expired: usize,
    pub expiring_soon: usize,
    pub average_check_time: Duration,
    pub total_time: Duration,
}

impl BatchStatistics {
    /// Calculate statistics from batch results
    pub fn from_results(results: &[BatchCheckResult], expiry_threshold_days: i64) -> Self {
        let start = Instant::now();
        let total_checked = results.len();
        let mut successful = 0;
        let mut failed = 0;
        let mut expired = 0;
        let mut expiring_soon = 0;
        let mut total_duration = Duration::ZERO;
        
        for result in results {
            total_duration += result.duration;
            
            match &result.result {
                Ok(cert) => {
                    successful += 1;
                    
                    if !cert.server.is_valid {
                        expired += 1;
                    } else if cert.server.days_to_expiration < expiry_threshold_days {
                        expiring_soon += 1;
                    }
                }
                Err(_) => {
                    failed += 1;
                }
            }
        }
        
        let average_check_time = if total_checked > 0 {
            total_duration / total_checked as u32
        } else {
            Duration::ZERO
        };
        
        BatchStatistics {
            total_checked,
            successful,
            failed,
            expired,
            expiring_soon,
            average_check_time,
            total_time: start.elapsed(),
        }
    }
    
    /// Print statistics summary
    pub fn print_summary(&self) {
        println!("Batch Check Statistics:");
        println!("  Total domains checked: {}", self.total_checked);
        println!("  Successful: {}", self.successful);
        println!("  Failed: {}", self.failed);
        println!("  Expired certificates: {}", self.expired);
        println!("  Expiring soon: {}", self.expiring_soon);
        println!("  Average check time: {:?}", self.average_check_time);
        println!("  Total time: {:?}", self.total_time);
    }
}

/// Export batch results to JSON
pub fn export_batch_results_json(results: &[BatchCheckResult]) -> Result<String, serde_json::Error> {
    #[derive(serde::Serialize)]
    struct JsonBatchResult {
        domain: String,
        success: bool,
        error: Option<String>,
        certificate: Option<Cert>,
        duration_ms: u64,
        checked_at: String,
    }
    
    let json_results: Vec<JsonBatchResult> = results.iter().map(|r| {
        let (success, error, certificate) = match &r.result {
            Ok(cert) => (true, None, Some(cert.clone())),
            Err(e) => (false, Some(e.clone()), None),
        };
        
        JsonBatchResult {
            domain: r.domain.clone(),
            success,
            error,
            certificate,
            duration_ms: r.duration.as_millis() as u64,
            checked_at: format!("{:?}", r.checked_at),
        }
    }).collect();
    
    serde_json::to_string_pretty(&json_results)
}

/// Export batch results to CSV
pub fn export_batch_results_csv(results: &[BatchCheckResult]) -> String {
    let mut csv = String::new();
    csv.push_str("Domain,Success,Error,Days to Expiration,Common Name,Issuer,Duration (ms)\n");
    
    for result in results {
        let domain = &result.domain;
        let duration_ms = result.duration.as_millis();
        
        match &result.result {
            Ok(cert) => {
                csv.push_str(&format!(
                    "{},true,,{},{},{},{}\n",
                    domain,
                    cert.server.days_to_expiration,
                    cert.server.common_name,
                    cert.server.issuer_cn,
                    duration_ms
                ));
            }
            Err(e) => {
                csv.push_str(&format!(
                    "{},false,\"{}\",,,,{}\n",
                    domain,
                    e.replace('"', "\"\""),
                    duration_ms
                ));
            }
        }
    }
    
    csv
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_batch_config_default() {
        let config = BatchConfig::default();
        assert_eq!(config.max_concurrent, 5);
        assert!(config.continue_on_error);
        assert!(config.delay_between_checks.is_none());
    }

    #[test]
    fn test_stress_many_concurrent_threads() {
        // Test with a large number of domains and high concurrency
        let domains: Vec<String> = (0..100)
            .map(|i| format!("test-domain-{}.com", i))
            .collect();
        
        let config = BatchConfig {
            max_concurrent: 20, // High concurrency
            check_config: CheckSSLConfig {
                timeout: Duration::from_millis(100), // Short timeout to speed up test
                port: 443,
            },
            continue_on_error: true,
            delay_between_checks: None,
        };
        
        let results = batch_check_domains(domains.clone(), config);
        
        // Verify all domains were processed
        assert_eq!(results.len(), domains.len());
        
        // Verify results are sorted
        let mut sorted_domains = domains.clone();
        sorted_domains.sort();
        let result_domains: Vec<String> = results.iter().map(|r| r.domain.clone()).collect();
        assert_eq!(result_domains, sorted_domains);
    }

    #[test]
    fn test_timeout_handling() {
        // Test domains that will timeout
        let domains = vec![
            "192.0.2.1".to_string(), // TEST-NET-1, likely to timeout
            "198.51.100.1".to_string(), // TEST-NET-2
            "203.0.113.1".to_string(), // TEST-NET-3
        ];
        
        let config = BatchConfig {
            max_concurrent: 3,
            check_config: CheckSSLConfig {
                timeout: Duration::from_millis(100), // Very short timeout
                port: 443,
            },
            continue_on_error: true,
            delay_between_checks: None,
        };
        
        let start = Instant::now();
        let results = batch_check_domains(domains.clone(), config);
        let elapsed = start.elapsed();
        
        // Should complete quickly despite timeouts
        assert!(elapsed < Duration::from_secs(5));
        
        // All domains should have results (even if failed)
        assert_eq!(results.len(), domains.len());
        
        // All results should be errors due to timeout
        for result in &results {
            assert!(result.result.is_err());
        }
    }

    #[test]
    fn test_partial_failure_handling() {
        // Mix of valid and invalid domains
        let domains = vec![
            "google.com".to_string(), // Valid
            "invalid-domain-12345.test".to_string(), // Invalid
            "github.com".to_string(), // Valid
            "another-invalid-98765.test".to_string(), // Invalid
        ];
        
        let config = BatchConfig {
            max_concurrent: 2,
            check_config: CheckSSLConfig::default(),
            continue_on_error: true, // Should continue despite failures
            delay_between_checks: None,
        };
        
        let results = batch_check_domains(domains.clone(), config);
        
        // All domains should have results
        assert_eq!(results.len(), domains.len());
        
        // Check that we have both successes and failures
        let successes = results.iter().filter(|r| r.result.is_ok()).count();
        let failures = results.iter().filter(|r| r.result.is_err()).count();
        
        assert!(successes > 0, "Should have some successful checks");
        assert!(failures > 0, "Should have some failed checks");
    }

    #[test]
    fn test_stop_on_first_error() {
        let domains = vec![
            "google.com".to_string(),
            "invalid-domain-will-fail.test".to_string(),
            "github.com".to_string(), // Should not be checked if stop on error works
        ];
        
        let config = BatchConfig {
            max_concurrent: 1, // Sequential processing
            check_config: CheckSSLConfig::default(),
            continue_on_error: false, // Stop on first error
            delay_between_checks: None,
        };
        
        let results = batch_check_domains(domains, config);
        
        // Should have stopped after the second domain failed
        assert!(results.len() <= 2, "Should stop after first error");
    }

    #[test]
    fn test_concurrent_access_safety() {
        // Test thread safety with many concurrent operations
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];
        
        for i in 0..10 {
            let counter_clone = Arc::clone(&counter);
            let handle = thread::spawn(move || {
                let domains: Vec<String> = (0..10)
                    .map(|j| format!("thread-{}-domain-{}.test", i, j))
                    .collect();
                
                let config = BatchConfig {
                    max_concurrent: 5,
                    check_config: CheckSSLConfig {
                        timeout: Duration::from_millis(50),
                        port: 443,
                    },
                    continue_on_error: true,
                    delay_between_checks: None,
                };
                
                let results = batch_check_domains(domains, config);
                counter_clone.fetch_add(results.len(), Ordering::SeqCst);
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete");
        }
        
        // Verify all domains were processed
        assert_eq!(counter.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn test_rate_limiting() {
        let domains = vec![
            "example1.com".to_string(),
            "example2.com".to_string(),
            "example3.com".to_string(),
        ];
        
        let delay = Duration::from_millis(100);
        let config = BatchConfig {
            max_concurrent: 1, // Sequential to measure delays accurately
            check_config: CheckSSLConfig {
                timeout: Duration::from_millis(50),
                port: 443,
            },
            continue_on_error: true,
            delay_between_checks: Some(delay),
        };
        
        let start = Instant::now();
        let results = batch_check_domains(domains.clone(), config);
        let elapsed = start.elapsed();
        
        // Should have delays between checks (2 delays for 3 domains)
        assert!(elapsed >= delay * 2);
        assert_eq!(results.len(), domains.len());
    }

    #[test]
    fn test_acquire_lock_with_timeout() {
        let mutex = Arc::new(Mutex::new(42));
        
        // Test successful lock acquisition
        let result = acquire_lock_with_timeout(&mutex, Duration::from_secs(1));
        assert!(result.is_ok());
        let guard = result.unwrap();
        assert_eq!(*guard, 42);
        drop(guard);
        
        // Test lock acquisition with contention
        let mutex_clone = Arc::clone(&mutex);
        let handle = thread::spawn(move || {
            let _guard = mutex_clone.lock().unwrap();
            thread::sleep(Duration::from_millis(50));
        });
        
        // Try to acquire while another thread holds it
        thread::sleep(Duration::from_millis(10)); // Let other thread acquire first
        let result = acquire_lock_with_timeout(&mutex, Duration::from_millis(100));
        assert!(result.is_ok()); // Should succeed after other thread releases
        
        handle.join().unwrap();
    }

    #[test]
    fn test_batch_statistics_calculation() {
        let results = vec![
            BatchCheckResult {
                domain: "example1.com".to_string(),
                result: Ok(Cert {
                    server: crate::ServerCert {
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
                result: Err("Connection failed".to_string()),
                duration: Duration::from_millis(50),
                checked_at: Instant::now(),
            },
        ];
        
        let stats = BatchStatistics::from_results(&results, 30);
        assert_eq!(stats.total_checked, 2);
        assert_eq!(stats.successful, 1);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.expired, 0);
        assert_eq!(stats.expiring_soon, 0);
    }

    #[test]
    fn test_export_csv_format() {
        let results = vec![
            BatchCheckResult {
                domain: "example.com".to_string(),
                result: Ok(Cert {
                    server: crate::ServerCert {
                        common_name: "example.com".to_string(),
                        issuer_cn: "Test CA".to_string(),
                        days_to_expiration: 90,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                duration: Duration::from_millis(100),
                checked_at: Instant::now(),
            },
        ];
        
        let csv = export_batch_results_csv(&results);
        assert!(csv.contains("example.com,true,,90,example.com,Test CA,100"));
    }

    #[test]
    fn test_batch_check_domains_grouped() {
        use std::collections::HashMap;
        use crate::CheckSSLConfig;
        use std::time::Duration;
        
        // Create test domain groups
        let mut domain_groups = HashMap::new();
        
        // Group 1: Search engines
        let search_domains = vec![
            "google.com".to_string(),
            "bing.com".to_string(),
        ];
        let search_config = CheckSSLConfig {
            timeout: Duration::from_secs(5),
            port: 443,
        };
        domain_groups.insert("search_engines".to_string(), (search_domains, search_config));
        
        // Group 2: Code repositories
        let repo_domains = vec![
            "github.com".to_string(),
            "gitlab.com".to_string(),
        ];
        let repo_config = CheckSSLConfig {
            timeout: Duration::from_secs(10),
            port: 443,
        };
        domain_groups.insert("repositories".to_string(), (repo_domains, repo_config));
        
        // Test grouped batch checking
        let results = batch_check_domains_grouped(domain_groups, 2);
        
        // Verify we have results for both groups
        assert_eq!(results.len(), 2);
        assert!(results.contains_key("search_engines"));
        assert!(results.contains_key("repositories"));
        
        // Verify each group has results
        if let Some(search_results) = results.get("search_engines") {
            assert_eq!(search_results.len(), 2);
        }
        if let Some(repo_results) = results.get("repositories") {
            assert_eq!(repo_results.len(), 2);
        }
    }
}