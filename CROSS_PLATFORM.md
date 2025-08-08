# Cross-Platform Support

CheckSSL is designed to work seamlessly across Windows, Linux, and macOS platforms.

## Platform Compatibility

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Certificate Validation | ✅ | ✅ | ✅ |
| Custom Root Stores | ✅ | ✅ | ✅ |
| CLI Tool | ✅ | ✅ | ✅ |
| Async Support | ✅ | ✅ | ✅ |
| Performance Benchmarks | ✅ | ✅ | ✅ |

## System Requirements

### Windows
- Windows 7 or later
- Visual C++ Build Tools (for compilation)
- No additional runtime dependencies

### Linux
- Any modern Linux distribution
- OpenSSL development headers (optional, for extended features)
- No additional runtime dependencies

### macOS
- macOS 10.10 or later
- Xcode Command Line Tools (for compilation)
- No additional runtime dependencies

## Platform-Specific Features

### Certificate Store Locations

The library automatically detects system certificate stores:

**Windows:**
- `C:\ProgramData\SSL\certs`
- `%USERPROFILE%\.ssl\certs`

**Linux:**
- `/etc/ssl/certs`
- `/etc/pki/tls/certs`
- `/usr/share/ca-certificates`
- `~/.local/share/ca-certificates`

**macOS:**
- `/System/Library/Keychains`
- `/Library/Keychains`
- `~/Library/Keychains`
- `/etc/ssl/certs`

### Platform Detection

```rust
use checkssl::{platform_name, architecture, get_system_cert_paths};

println!("Platform: {}", platform_name());  // "Windows", "Linux", or "macOS"
println!("Architecture: {}", architecture()); // "x86_64", "ARM64", etc.

// Get system certificate paths
let cert_paths = get_system_cert_paths();
for path in cert_paths {
    println!("Cert path: {:?}", path);
}
```

## Building from Source

### Windows

```powershell
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the project
cargo build --release

# Run tests
cargo test
```

### Linux

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install dependencies (optional)
sudo apt-get install pkg-config libssl-dev  # Debian/Ubuntu
sudo yum install openssl-devel              # RHEL/CentOS

# Build the project
cargo build --release

# Run tests
cargo test
```

### macOS

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the project
cargo build --release

# Run tests
cargo test
```

## Cross-Compilation

### From Linux to Windows

```bash
# Add Windows target
rustup target add x86_64-pc-windows-gnu

# Install cross-compilation tools
sudo apt-get install mingw-w64

# Build for Windows
cargo build --target x86_64-pc-windows-gnu --release
```

### From macOS to Linux

```bash
# Add Linux target
rustup target add x86_64-unknown-linux-gnu

# Use cross for easier cross-compilation
cargo install cross

# Build for Linux
cross build --target x86_64-unknown-linux-gnu --release
```

## Binary Distribution

Pre-built binaries are available for:
- Windows (x64): `checkssl-windows-amd64.exe`
- Linux (x64): `checkssl-linux-amd64`
- macOS (x64): `checkssl-macos-amd64`
- macOS (ARM64): `checkssl-macos-arm64`

## Testing

Run platform-specific tests:

```bash
# Run all tests
cargo test

# Run cross-platform tests specifically
cargo test --test cross_platform_tests

# Run with verbose output
cargo test -- --nocapture
```

## Known Issues and Workarounds

### Windows
- Firewall may block HTTPS connections - ensure port 443 is open
- Some antivirus software may flag the binary - add to whitelist

### Linux
- SELinux may block network connections - adjust policies if needed
- Snap/Flatpak environments may have restricted network access

### macOS
- Gatekeeper may block unsigned binaries - use `xattr -d com.apple.quarantine checkssl`
- Network permissions may be required on macOS 10.15+

## Performance Considerations

- Network timeouts are consistent across platforms (default: 5 seconds)
- Certificate parsing performance is similar across all platforms
- Threading behavior follows platform conventions

## Support

For platform-specific issues, please include:
1. Operating system and version
2. Architecture (x86_64, ARM64, etc.)
3. Rust version (`rustc --version`)
4. Error messages or logs
5. Network configuration (proxy, firewall, etc.)

Report issues at: https://github.com/pixelcoda/checkssl/issues