//! Comprehensive tests for retry logic with exponential backoff

use checkssl::{retry_with_backoff, RetryConfig, RetryableError, CheckSSLError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod fixtures;

#[test]
fn test_exponential_backoff_calculation() {
    let config = RetryConfig {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(2),
        backoff_multiplier: 2.0,
        jitter: false,
    };

    let mut attempts = Arc::new(Mutex::new(Vec::new()));
    let attempts_clone = attempts.clone();
    
    let start = Instant::now();
    let result = retry_with_backoff(&config, || -> Result<(), CheckSSLError> {
        let elapsed = start.elapsed();
        attempts_clone.lock().unwrap().push(elapsed);
        
        if attempts_clone.lock().unwrap().len() < 3 {
            Err(CheckSSLError::NetworkError("Temporary failure".to_string()))
        } else {
            Ok(())
        }
    });

    assert!(result.is_ok());
    let timings = attempts.lock().unwrap();
    assert_eq!(timings.len(), 3);
    
    // Verify exponential backoff (approximately)
    // First attempt should be immediate
    assert!(timings[0] < Duration::from_millis(10));
    // Second attempt after ~100ms
    assert!(timings[1] >= Duration::from_millis(90));
    assert!(timings[1] < Duration::from_millis(150));
    // Third attempt after ~100ms + 200ms = 300ms
    assert!(timings[2] >= Duration::from_millis(280));
    assert!(timings[2] < Duration::from_millis(400));
}

#[test]
fn test_max_retry_limit() {
    let config = RetryConfig {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_secs(1),
        backoff_multiplier: 2.0,
        jitter: false,
    };

    let mut attempt_count = 0;
    let result = retry_with_backoff(&config, || -> Result<(), CheckSSLError> {
        attempt_count += 1;
        Err(CheckSSLError::NetworkError("Persistent failure".to_string()))
    });

    assert!(result.is_err());
    assert_eq!(attempt_count, 3);
    match result {
        Err(CheckSSLError::NetworkError(msg)) => {
            assert_eq!(msg, "Persistent failure");
        }
        _ => panic!("Expected NetworkError"),
    }
}

#[test]
fn test_timeout_handling() {
    let config = RetryConfig {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_secs(1),
        backoff_multiplier: 2.0,
        jitter: false,
    };

    let mut attempt_count = 0;
    let result = retry_with_backoff(&config, || -> Result<(), CheckSSLError> {
        attempt_count += 1;
        Err(CheckSSLError::TimeoutError("Connection timeout".to_string()))
    });

    assert!(result.is_err());
    assert_eq!(attempt_count, 3);
    match result {
        Err(CheckSSLError::TimeoutError(msg)) => {
            assert_eq!(msg, "Connection timeout");
        }
        _ => panic!("Expected TimeoutError"),
    }
}

#[test]
fn test_partial_failures_recovery() {
    let config = RetryConfig {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_secs(1),
        backoff_multiplier: 2.0,
        jitter: false,
    };

    let failure_pattern = vec![true, true, false, true, false]; // Fail on attempts 1, 2, 4
    let mut attempt = 0;
    
    let result = retry_with_backoff(&config, || -> Result<String, CheckSSLError> {
        let should_fail = failure_pattern[attempt];
        attempt += 1;
        
        if should_fail {
            Err(CheckSSLError::NetworkError("Intermittent failure".to_string()))
        } else {
            Ok("Success".to_string())
        }
    });

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Success");
    assert_eq!(attempt, 3); // Should succeed on third attempt
}

#[test]
fn test_max_backoff_enforcement() {
    let config = RetryConfig {
        max_attempts: 4,
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_millis(200), // Very low max
        backoff_multiplier: 10.0, // High multiplier
        jitter: false,
    };

    let start = Instant::now();
    let mut attempt_times = Vec::new();
    
    let _result = retry_with_backoff(&config, || -> Result<(), CheckSSLError> {
        attempt_times.push(start.elapsed());
        Err(CheckSSLError::NetworkError("Always fail".to_string()))
    });

    // Verify that backoff never exceeds max_backoff
    for i in 1..attempt_times.len() {
        let delay = attempt_times[i] - attempt_times[i - 1];
        assert!(delay <= Duration::from_millis(250)); // Allow some margin
    }
}

#[test]
fn test_jitter_applied() {
    let config = RetryConfig {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(1),
        backoff_multiplier: 2.0,
        jitter: true,
    };

    let mut delays = Vec::new();
    let start = Instant::now();
    let mut last_time = start;
    
    let _result = retry_with_backoff(&config, || -> Result<(), CheckSSLError> {
        let now = Instant::now();
        if now > last_time {
            delays.push(now.duration_since(last_time));
        }
        last_time = now;
        Err(CheckSSLError::NetworkError("Always fail".to_string()))
    });

    // With jitter, delays should vary
    // First delay should be around 100ms but with jitter (80-120ms)
    if delays.len() > 0 {
        assert!(delays[0] >= Duration::from_millis(60));
        assert!(delays[0] <= Duration::from_millis(140));
    }
}

#[test]
fn test_non_retryable_error_immediate_failure() {
    let config = RetryConfig {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(1),
        backoff_multiplier: 2.0,
        jitter: false,
    };

    let mut attempt_count = 0;
    let result = retry_with_backoff(&config, || -> Result<(), CheckSSLError> {
        attempt_count += 1;
        Err(CheckSSLError::CertificateParseError("Invalid certificate".to_string()))
    });

    assert!(result.is_err());
    assert_eq!(attempt_count, 1); // Should not retry non-retryable errors
}

#[test]
fn test_success_on_first_attempt() {
    let config = RetryConfig::default();
    
    let mut attempt_count = 0;
    let result = retry_with_backoff(&config, || -> Result<String, CheckSSLError> {
        attempt_count += 1;
        Ok("Immediate success".to_string())
    });

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Immediate success");
    assert_eq!(attempt_count, 1);
}

#[test]
fn test_different_retryable_errors() {
    // Test that all retryable error types are properly retried
    let error_types = vec![
        CheckSSLError::NetworkError("Network error".to_string()),
        CheckSSLError::TimeoutError("Timeout".to_string()),
        CheckSSLError::DnsResolutionError("DNS failed".to_string()),
        CheckSSLError::TlsHandshakeError("TLS failed".to_string()),
        CheckSSLError::OcspError("OCSP failed".to_string()),
        CheckSSLError::IoError("IO error".to_string()),
    ];

    for error in error_types {
        assert!(error.is_retryable(), "Error {:?} should be retryable", error);
    }

    // Test non-retryable errors
    let non_retryable = vec![
        CheckSSLError::CertificateParseError("Parse error".to_string()),
        CheckSSLError::ValidationError("Validation failed".to_string()),
    ];

    for error in non_retryable {
        assert!(!error.is_retryable(), "Error {:?} should not be retryable", error);
    }
}

#[test]
fn test_no_retry_config() {
    let config = RetryConfig::no_retry();
    
    let mut attempt_count = 0;
    let result = retry_with_backoff(&config, || -> Result<(), CheckSSLError> {
        attempt_count += 1;
        Err(CheckSSLError::NetworkError("Should not retry".to_string()))
    });

    assert!(result.is_err());
    assert_eq!(attempt_count, 1);
}

#[test]
fn test_aggressive_retry_config() {
    let config = RetryConfig::aggressive();
    
    assert_eq!(config.max_attempts, 5);
    assert_eq!(config.initial_backoff, Duration::from_millis(50));
    assert_eq!(config.max_backoff, Duration::from_secs(30));
    assert_eq!(config.backoff_multiplier, 1.5);
}

#[test]
fn test_concurrent_retries() {
    use std::thread;
    
    let config = RetryConfig {
        max_attempts: 2,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(100),
        backoff_multiplier: 2.0,
        jitter: true,
    };

    let handles: Vec<_> = (0..5).map(|i| {
        let config = config.clone();
        thread::spawn(move || {
            let mut attempt = 0;
            retry_with_backoff(&config, || -> Result<i32, CheckSSLError> {
                attempt += 1;
                if attempt == 1 {
                    Err(CheckSSLError::NetworkError(format!("Thread {} fail", i)))
                } else {
                    Ok(i)
                }
            })
        })
    }).collect();

    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.join().unwrap();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), i as i32);
    }
}