use checkssl::{batch_check_domains_grouped, CheckSSLConfig, BatchStatistics};
use std::collections::HashMap;
use std::time::{Duration, Instant};

fn main() {
    println!("=== Batch SSL Certificate Checking with Groups ===\n");
    
    // Example 1: Check different environments
    demo_environment_groups();
    
    // Example 2: Check services with different configurations
    demo_service_groups();
    
    // Example 3: Generate grouped statistics
    demo_grouped_statistics();
}

fn demo_environment_groups() {
    println!("Example 1: Checking different environments");
    println!("{}", "-".repeat(50));
    
    let mut environment_groups = HashMap::new();
    
    // Production environment - critical services with standard timeout
    let production_domains = vec![
        "google.com".to_string(),
        "github.com".to_string(),
        "stackoverflow.com".to_string(),
    ];
    let production_config = CheckSSLConfig {
        timeout: Duration::from_secs(5),
        port: 443,
    };
    environment_groups.insert("production".to_string(), (production_domains, production_config));
    
    // Staging environment - test services with longer timeout
    let staging_domains = vec![
        "rust-lang.org".to_string(),
        "crates.io".to_string(),
    ];
    let staging_config = CheckSSLConfig {
        timeout: Duration::from_secs(10),
        port: 443,
    };
    environment_groups.insert("staging".to_string(), (staging_domains, staging_config));
    
    // External APIs - third-party services
    let api_domains = vec![
        "api.github.com".to_string(),
        "www.cloudflare.com".to_string(),
    ];
    let api_config = CheckSSLConfig {
        timeout: Duration::from_secs(8),
        port: 443,
    };
    environment_groups.insert("external_apis".to_string(), (api_domains, api_config));
    
    println!("Checking certificates for multiple environments...\n");
    let start = Instant::now();
    
    // Check all groups with max 3 concurrent checks per group
    let results = batch_check_domains_grouped(environment_groups, 3);
    
    let elapsed = start.elapsed();
    
    // Display results by environment
    for (env_name, env_results) in &results {
        println!("Environment: {}", env_name);
        println!("  Domains checked: {}", env_results.len());
        
        let successful = env_results.iter()
            .filter(|r| r.result.is_ok())
            .count();
        let failed = env_results.len() - successful;
        
        println!("  Successful: {}", successful);
        println!("  Failed: {}", failed);
        
        // Show details for each domain
        for result in env_results {
            match &result.result {
                Ok(cert) => {
                    println!("    ✓ {} - Valid: {}, Days to expiration: {}", 
                        result.domain, 
                        cert.server.is_valid,
                        cert.server.days_to_expiration
                    );
                }
                Err(e) => {
                    println!("    ✗ {} - Error: {}", result.domain, e);
                }
            }
        }
        println!();
    }
    
    println!("Total time for all groups: {:?}\n", elapsed);
}

fn demo_service_groups() {
    println!("Example 2: Checking services with different configurations");
    println!("{}", "-".repeat(50));
    
    let mut service_groups = HashMap::new();
    
    // Web services on standard HTTPS port
    let web_services = vec![
        "www.rust-lang.org".to_string(),
        "www.github.com".to_string(),
    ];
    let web_config = CheckSSLConfig {
        timeout: Duration::from_secs(5),
        port: 443,
    };
    service_groups.insert("web_services".to_string(), (web_services, web_config));
    
    // API services (also on 443, but with different timeout requirements)
    let api_services = vec![
        "api.github.com".to_string(),
        "crates.io".to_string(),
    ];
    let api_config = CheckSSLConfig {
        timeout: Duration::from_secs(10),
        port: 443,
    };
    service_groups.insert("api_services".to_string(), (api_services, api_config));
    
    // Note: In a real scenario, you might have internal services on custom ports
    // For example:
    // let internal_services = vec!["internal-api.company.local".to_string()];
    // let internal_config = CheckSSLConfig {
    //     timeout: Duration::from_secs(15),
    //     port: 8443,  // Custom port
    // };
    // service_groups.insert("internal".to_string(), (internal_services, internal_config));
    
    println!("Checking different service types...\n");
    
    let results = batch_check_domains_grouped(service_groups, 2);
    
    // Process results by service type
    for (service_type, service_results) in results {
        println!("Service Type: {}", service_type);
        
        // Find certificates expiring soon (within 30 days)
        let expiring_soon: Vec<_> = service_results.iter()
            .filter_map(|r| {
                r.result.as_ref().ok().filter(|cert| {
                    cert.server.is_valid && cert.server.days_to_expiration < 30
                })
                .map(|cert| (r.domain.clone(), cert.server.days_to_expiration))
            })
            .collect();
        
        if !expiring_soon.is_empty() {
            println!("  ⚠ Certificates expiring soon:");
            for (domain, days) in expiring_soon {
                println!("    - {} expires in {} days", domain, days);
            }
        } else {
            println!("  ✓ All certificates have > 30 days validity");
        }
        println!();
    }
}

fn demo_grouped_statistics() {
    println!("Example 3: Generating grouped statistics");
    println!("{}", "-".repeat(50));
    
    let mut monitoring_groups = HashMap::new();
    
    // Critical infrastructure
    let critical_domains = vec![
        "github.com".to_string(),
        "google.com".to_string(),
        "cloudflare.com".to_string(),
    ];
    let critical_config = CheckSSLConfig {
        timeout: Duration::from_secs(3),
        port: 443,
    };
    monitoring_groups.insert("critical".to_string(), (critical_domains, critical_config));
    
    // Standard services
    let standard_domains = vec![
        "rust-lang.org".to_string(),
        "crates.io".to_string(),
        "docs.rs".to_string(),
    ];
    let standard_config = CheckSSLConfig {
        timeout: Duration::from_secs(5),
        port: 443,
    };
    monitoring_groups.insert("standard".to_string(), (standard_domains, standard_config));
    
    println!("Running grouped certificate checks for monitoring...\n");
    
    let results = batch_check_domains_grouped(monitoring_groups, 4);
    
    // Generate statistics for each group
    println!("Statistics by Group:\n");
    
    for (group_name, group_results) in results {
        println!("Group: {} (Priority Level)", group_name);
        
        // Calculate statistics using BatchStatistics
        let stats = BatchStatistics::from_results(&group_results, 30);
        
        println!("  Total checked: {}", stats.total_checked);
        println!("  Successful: {}", stats.successful);
        println!("  Failed: {}", stats.failed);
        println!("  Expired: {}", stats.expired);
        println!("  Expiring within 30 days: {}", stats.expiring_soon);
        println!("  Average check time: {:?}", stats.average_check_time);
        
        // Calculate success rate
        let success_rate = if stats.total_checked > 0 {
            (stats.successful as f64 / stats.total_checked as f64) * 100.0
        } else {
            0.0
        };
        println!("  Success rate: {:.1}%", success_rate);
        
        // Determine health status
        let health_status = if stats.failed > 0 {
            "⚠ NEEDS ATTENTION"
        } else if stats.expiring_soon > 0 {
            "⚡ CERTIFICATES EXPIRING SOON"
        } else {
            "✓ HEALTHY"
        };
        println!("  Status: {}", health_status);
        println!();
    }
    
    println!("Tip: You can export these results to JSON or CSV for reporting:");
    println!("  - Use export_batch_results_json() for JSON export");
    println!("  - Use export_batch_results_csv() for CSV export");
}