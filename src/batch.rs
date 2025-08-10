//! Batch certificate checking functionality.
//!
//! This module provides functionality to check multiple domains
//! in parallel or sequentially with configurable concurrency.

use crate::{CheckSSL, CheckSSLConfig, Cert};
use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::HashMap;
use std::time::{Duration, Instant};

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
    
    for (index, domain) in domains.iter().enumerate() {
        let domain = domain.clone();
        let results_clone = Arc::clone(&results);
        let config_clone = Arc::clone(&config);
        let semaphore_clone = Arc::clone(&semaphore);
        
        // Wait if we've reached max concurrent checks
        loop {
            let mut count = semaphore.lock().unwrap();
            if *count < config.max_concurrent {
                *count += 1;
                break;
            }
            drop(count);
            thread::sleep(Duration::from_millis(10));
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
            
            results_clone.lock().unwrap().push(batch_result);
            
            // Release semaphore
            let mut count = semaphore_clone.lock().unwrap();
            *count -= 1;
        });
        
        handles.push(handle);
        
        // Check if we should continue on error
        if !config.continue_on_error {
            // Wait for this thread to complete and check result
            if let Some(handle) = handles.pop() {
                handle.join().unwrap();
                let results_guard = results.lock().unwrap();
                if let Some(last_result) = results_guard.last() {
                    if last_result.result.is_err() {
                        break;
                    }
                }
            }
        }
    }
    
    // Wait for all remaining threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    let mut final_results = results.lock().unwrap().clone();
    
    // Sort results by domain name for consistent output
    final_results.sort_by(|a, b| a.domain.cmp(&b.domain));
    
    final_results
}

/// Check domains in groups with different configurations
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

    #[test]
    fn test_batch_config_default() {
        let config = BatchConfig::default();
        assert_eq!(config.max_concurrent, 5);
        assert!(config.continue_on_error);
        assert!(config.delay_between_checks.is_none());
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