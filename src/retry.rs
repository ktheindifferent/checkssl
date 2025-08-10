//! Retry logic with exponential backoff for network operations.
//!
//! This module provides configurable retry mechanisms for handling
//! transient network failures and improving reliability.

use std::time::Duration;
use std::thread;
use crate::error::CheckSSLError;

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial backoff duration
    pub initial_backoff: Duration,
    /// Maximum backoff duration
    pub max_backoff: Duration,
    /// Backoff multiplier (typically 2.0)
    pub backoff_multiplier: f64,
    /// Add jitter to backoff to avoid thundering herd
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        RetryConfig {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryConfig {
    /// Create a retry configuration with no retries
    pub fn no_retry() -> Self {
        RetryConfig {
            max_attempts: 1,
            ..Default::default()
        }
    }

    /// Create a retry configuration for aggressive retrying
    pub fn aggressive() -> Self {
        RetryConfig {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(30),
            backoff_multiplier: 1.5,
            jitter: true,
        }
    }
}

/// Trait for determining if an error is retryable
pub trait RetryableError {
    fn is_retryable(&self) -> bool;
}

impl RetryableError for CheckSSLError {
    fn is_retryable(&self) -> bool {
        match self {
            CheckSSLError::NetworkError(_) => true,
            CheckSSLError::TimeoutError(_) => true,
            CheckSSLError::DnsResolutionError(_) => true,
            CheckSSLError::TlsHandshakeError(_) => true,
            CheckSSLError::OcspError(_) => true,
            CheckSSLError::IoError(_) => true,
            _ => false,
        }
    }
}

/// Execute a function with retry logic
pub fn retry_with_backoff<T, E, F>(
    config: &RetryConfig,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    E: RetryableError + std::fmt::Debug,
{
    let mut attempt = 0;
    let mut backoff = config.initial_backoff;

    loop {
        attempt += 1;
        
        match operation() {
            Ok(result) => return Ok(result),
            Err(err) => {
                if !err.is_retryable() || attempt >= config.max_attempts {
                    return Err(err);
                }

                // Calculate backoff with optional jitter
                let mut sleep_duration = backoff;
                if config.jitter {
                    use std::time::SystemTime;
                    let nanos = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos();
                    let jitter_factor = 0.8 + (nanos as f64 / u32::MAX as f64) * 0.4;
                    sleep_duration = Duration::from_secs_f64(
                        sleep_duration.as_secs_f64() * jitter_factor
                    );
                }

                eprintln!(
                    "Attempt {} failed: {:?}. Retrying in {:?}...",
                    attempt, err, sleep_duration
                );

                thread::sleep(sleep_duration);

                // Update backoff for next iteration
                backoff = Duration::from_secs_f64(
                    (backoff.as_secs_f64() * config.backoff_multiplier)
                        .min(config.max_backoff.as_secs_f64())
                );
            }
        }
    }
}

/// Async version of retry with backoff
#[cfg(feature = "async")]
pub async fn retry_with_backoff_async<T, E, F, Fut>(
    config: &RetryConfig,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: RetryableError + std::fmt::Debug,
{
    let mut attempt = 0;
    let mut backoff = config.initial_backoff;

    loop {
        attempt += 1;
        
        match operation().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                if !err.is_retryable() || attempt >= config.max_attempts {
                    return Err(err);
                }

                // Calculate backoff with optional jitter
                let mut sleep_duration = backoff;
                if config.jitter {
                    use std::time::SystemTime;
                    let nanos = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos();
                    let jitter_factor = 0.8 + (nanos as f64 / u32::MAX as f64) * 0.4;
                    sleep_duration = Duration::from_secs_f64(
                        sleep_duration.as_secs_f64() * jitter_factor
                    );
                }

                eprintln!(
                    "Attempt {} failed: {:?}. Retrying in {:?}...",
                    attempt, err, sleep_duration
                );

                // Use async sleep
                #[cfg(feature = "async")]
                tokio::time::sleep(sleep_duration).await;

                // Update backoff for next iteration
                backoff = Duration::from_secs_f64(
                    (backoff.as_secs_f64() * config.backoff_multiplier)
                        .min(config.max_backoff.as_secs_f64())
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
        assert_eq!(config.max_backoff, Duration::from_secs(10));
        assert_eq!(config.backoff_multiplier, 2.0);
        assert!(config.jitter);
    }

    #[test]
    fn test_retry_config_no_retry() {
        let config = RetryConfig::no_retry();
        assert_eq!(config.max_attempts, 1);
    }

    #[test]
    fn test_retry_config_aggressive() {
        let config = RetryConfig::aggressive();
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_backoff, Duration::from_millis(50));
        assert_eq!(config.max_backoff, Duration::from_secs(30));
        assert_eq!(config.backoff_multiplier, 1.5);
    }

    #[test]
    fn test_retryable_errors() {
        assert!(CheckSSLError::NetworkError("test".to_string()).is_retryable());
        assert!(CheckSSLError::TimeoutError("test".to_string()).is_retryable());
        assert!(CheckSSLError::DnsResolutionError("test".to_string()).is_retryable());
        assert!(!CheckSSLError::CertificateParseError("test".to_string()).is_retryable());
        assert!(!CheckSSLError::ValidationError("test".to_string()).is_retryable());
    }

    #[test]
    fn test_retry_success_on_second_attempt() {
        let mut attempt_count = 0;
        let config = RetryConfig {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(10),
            ..Default::default()
        };

        let result = retry_with_backoff(&config, || -> Result<i32, CheckSSLError> {
            attempt_count += 1;
            if attempt_count == 1 {
                Err(CheckSSLError::NetworkError("Temporary failure".to_string()))
            } else {
                Ok(42)
            }
        });

        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempt_count, 2);
    }

    #[test]
    fn test_retry_exhausted() {
        let mut attempt_count = 0;
        let config = RetryConfig {
            max_attempts: 2,
            initial_backoff: Duration::from_millis(10),
            ..Default::default()
        };

        let result = retry_with_backoff(&config, || -> Result<i32, CheckSSLError> {
            attempt_count += 1;
            Err(CheckSSLError::NetworkError("Persistent failure".to_string()))
        });

        assert!(result.is_err());
        assert_eq!(attempt_count, 2);
    }

    #[test]
    fn test_non_retryable_error() {
        let mut attempt_count = 0;
        let config = RetryConfig::default();

        let result = retry_with_backoff(&config, || -> Result<i32, CheckSSLError> {
            attempt_count += 1;
            Err(CheckSSLError::CertificateParseError("Parse error".to_string()))
        });

        assert!(result.is_err());
        assert_eq!(attempt_count, 1); // Should not retry
    }
}