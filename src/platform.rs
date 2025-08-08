//! Platform-specific utilities and compatibility layer.
//!
//! This module ensures consistent behavior across Windows, Linux, and macOS.

use std::path::PathBuf;
use std::env;

/// Get home directory in a cross-platform way
fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Get the system's certificate store location based on the platform.
///
/// Returns common certificate store paths for each operating system.
pub fn get_system_cert_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        // Windows typically uses the Windows Certificate Store
        // These are common paths for additional certificates
        vec![
            PathBuf::from(r"C:\ProgramData\SSL\certs"),
            env::var("USERPROFILE")
                .map(|p| PathBuf::from(p).join(".ssl").join("certs"))
                .unwrap_or_default(),
        ]
    }
    
    #[cfg(target_os = "macos")]
    {
        vec![
            PathBuf::from("/System/Library/Keychains"),
            PathBuf::from("/Library/Keychains"),
            PathBuf::from("/Network/Library/Keychains"),
            home_dir()
                .map(|p| p.join("Library").join("Keychains"))
                .unwrap_or_default(),
            PathBuf::from("/etc/ssl/certs"),
            PathBuf::from("/usr/local/etc/openssl/certs"),
        ]
    }
    
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/etc/ssl/certs"),
            PathBuf::from("/etc/pki/tls/certs"),
            PathBuf::from("/etc/pki/ca-trust/source/anchors"),
            PathBuf::from("/usr/share/ca-certificates"),
            PathBuf::from("/usr/local/share/ca-certificates"),
            home_dir()
                .map(|p| p.join(".local").join("share").join("ca-certificates"))
                .unwrap_or_default(),
        ]
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        // Fallback for other platforms (BSD, etc.)
        vec![
            PathBuf::from("/etc/ssl/certs"),
            PathBuf::from("/usr/local/etc/ssl/certs"),
        ]
    }
}

/// Normalize a path to be platform-independent.
///
/// Converts forward slashes to the platform's path separator.
#[allow(dead_code)]
pub fn normalize_path(path: &str) -> PathBuf {
    // Replace forward slashes with platform separator
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(path.replace('/', "\\"))
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from(path)
    }
}

/// Check if running with elevated privileges.
///
/// Returns true if the process has admin/root privileges.
#[allow(dead_code)]
pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::ptr;
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::processthreadsapi::OpenProcessToken;
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        
        unsafe {
            let mut token = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0 {
                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let mut size = 0;
                
                let result = GetTokenInformation(
                    token,
                    TokenElevation,
                    &mut elevation as *mut _ as *mut _,
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut size,
                );
                
                result != 0 && elevation.TokenIsElevated != 0
            } else {
                false
            }
        }
    }
    
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unsafe { libc::geteuid() == 0 }
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Get the platform name as a string.
pub fn platform_name() -> &'static str {
    #[cfg(target_os = "windows")]
    { "Windows" }
    
    #[cfg(target_os = "macos")]
    { "macOS" }
    
    #[cfg(target_os = "linux")]
    { "Linux" }
    
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    { "Unknown" }
}

/// Get the architecture name.
pub fn architecture() -> &'static str {
    #[cfg(target_arch = "x86")]
    { "x86" }
    
    #[cfg(target_arch = "x86_64")]
    { "x86_64" }
    
    #[cfg(target_arch = "arm")]
    { "ARM" }
    
    #[cfg(target_arch = "aarch64")]
    { "ARM64" }
    
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64")))]
    { "Unknown" }
}

/// Platform-specific line ending.
#[allow(dead_code)]
pub fn line_ending() -> &'static str {
    #[cfg(target_os = "windows")]
    { "\r\n" }
    
    #[cfg(not(target_os = "windows"))]
    { "\n" }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_platform_name() {
        let name = platform_name();
        assert!(!name.is_empty());
        assert!(["Windows", "macOS", "Linux", "Unknown"].contains(&name));
    }
    
    #[test]
    fn test_architecture() {
        let arch = architecture();
        assert!(!arch.is_empty());
    }
    
    #[test]
    fn test_normalize_path() {
        let path = normalize_path("ssl/certs/ca.pem");
        assert!(path.to_str().is_some());
        
        #[cfg(target_os = "windows")]
        assert!(path.to_str().unwrap().contains("\\"));
        
        #[cfg(not(target_os = "windows"))]
        assert!(path.to_str().unwrap().contains("/"));
    }
    
    #[test]
    fn test_system_cert_paths() {
        let paths = get_system_cert_paths();
        assert!(!paths.is_empty());
        
        // Each platform should have at least one cert path
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        assert!(paths.len() >= 1);
    }
    
    #[test]
    fn test_line_ending() {
        let ending = line_ending();
        
        #[cfg(target_os = "windows")]
        assert_eq!(ending, "\r\n");
        
        #[cfg(not(target_os = "windows"))]
        assert_eq!(ending, "\n");
    }
}