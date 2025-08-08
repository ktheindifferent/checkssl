use checkssl::{CheckSSL, CheckSSLConfig};
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;

fn benchmark_single_domain(c: &mut Criterion) {
    c.bench_function("check_ssl_google", |b| {
        b.iter(|| {
            CheckSSL::from_domain(black_box("google.com".to_string()))
        });
    });
}

fn benchmark_multiple_domains(c: &mut Criterion) {
    let domains = vec![
        "google.com",
        "github.com",
        "rust-lang.org",
    ];
    
    let mut group = c.benchmark_group("check_ssl_multiple");
    for domain in domains.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(domain),
            domain,
            |b, &domain| {
                b.iter(|| {
                    CheckSSL::from_domain(black_box(domain.to_string()))
                });
            },
        );
    }
    group.finish();
}

fn benchmark_with_different_timeouts(c: &mut Criterion) {
    let timeouts = vec![1, 3, 5, 10];
    let mut group = c.benchmark_group("check_ssl_timeouts");
    
    for timeout in timeouts.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}s", timeout)),
            timeout,
            |b, &timeout| {
                let config = CheckSSLConfig {
                    timeout: Duration::from_secs(timeout),
                    port: 443,
                };
                b.iter(|| {
                    CheckSSL::from_domain_with_config(
                        black_box("google.com".to_string()),
                        config.clone()
                    )
                });
            },
        );
    }
    group.finish();
}

fn benchmark_certificate_parsing(c: &mut Criterion) {
    use checkssl::ChainValidator;
    
    c.bench_function("parse_certificate_chain", |b| {
        // Get a real certificate first
        let cert_result = CheckSSL::from_domain("google.com".to_string());
        if cert_result.is_ok() {
            // For this benchmark, we simulate parsing with empty data
            // In a real scenario, we'd have the actual certificate bytes
            let validator = ChainValidator::new(vec![vec![0u8; 1024]]);
            
            b.iter(|| {
                // Benchmark the validation process
                let _ = validator.validate_chain();
            });
        }
    });
}

fn benchmark_async_vs_sync(c: &mut Criterion) {
    let mut group = c.benchmark_group("async_vs_sync");
    
    group.bench_function("sync_check", |b| {
        b.iter(|| {
            CheckSSL::from_domain(black_box("rust-lang.org".to_string()))
        });
    });
    
    group.bench_function("async_check", |b| {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        b.iter(|| {
            runtime.block_on(async {
                let future = CheckSSL::from_domain_async(black_box("rust-lang.org".to_string()));
                future.await
            })
        });
    });
    
    group.finish();
}

fn benchmark_parallel_checks(c: &mut Criterion) {
    use std::thread;
    use std::sync::{Arc, Mutex};
    
    c.bench_function("parallel_10_domains", |b| {
        b.iter(|| {
            let domains = vec![
                "google.com", "github.com", "rust-lang.org",
                "mozilla.org", "stackoverflow.com", "wikipedia.org",
                "cloudflare.com", "amazon.com", "microsoft.com", "apple.com"
            ];
            
            let results = Arc::new(Mutex::new(Vec::new()));
            let mut handles = vec![];
            
            for domain in domains {
                let results_clone = Arc::clone(&results);
                let handle = thread::spawn(move || {
                    let result = CheckSSL::from_domain(domain.to_string());
                    let mut results = results_clone.lock().unwrap();
                    results.push((domain, result.is_ok()));
                });
                handles.push(handle);
            }
            
            for handle in handles {
                handle.join().unwrap();
            }
            
            let results = results.lock().unwrap();
            assert_eq!(results.len(), 10);
        });
    });
}

fn benchmark_memory_usage(c: &mut Criterion) {
    c.bench_function("memory_repeated_checks", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let _ = CheckSSL::from_domain(black_box("localhost".to_string()));
            }
        });
    });
}

criterion_group!(
    benches,
    benchmark_single_domain,
    benchmark_multiple_domains,
    benchmark_with_different_timeouts,
    benchmark_certificate_parsing,
    benchmark_async_vs_sync,
    benchmark_parallel_checks,
    benchmark_memory_usage
);
criterion_main!(benches);