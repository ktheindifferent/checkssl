use std::sync::{Arc};
use rustls::Session;
use std::net::TcpStream;
use std::io::{Write, Error, ErrorKind};
use std::fmt::Debug;
use x509_parser::{parse_x509_der};
use x509_parser::objects::*;
use x509_parser::extensions::*;
use serde::{Serialize, Deserialize};
use std::time::Duration;
extern crate savefile;
#[macro_use]
extern crate savefile_derive;
use std::net::{ToSocketAddrs};
use std::thread;
use std::sync::mpsc;
use std::future::Future;
use std::pin::Pin;
use sha2::{Sha256, Digest as Sha2Digest};
use sha1::{Sha1};

#[derive(Serialize, Deserialize, Savefile, Debug, Clone, PartialEq)]
pub struct ServerCert {
    pub common_name: String,
    pub signature_algorithm: String,
    pub sans: Vec<String>,
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: String,
    pub serial_number: String,
    pub version: i32,
    pub not_after: i64,
    pub not_before: i64,
    pub issuer: String,
    pub issuer_cn: String,
    pub is_valid: bool,
    pub time_to_expiration: String,
    pub days_to_expiration: i64,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub public_key_algorithm: String,
    pub public_key_size: Option<usize>,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
}

#[derive(Serialize, Deserialize, Savefile, Debug, Clone, PartialEq)]
pub struct IntermediateCert {
    pub common_name: String,
    pub signature_algorithm: String,
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: String,
    pub serial_number: String,
    pub version: i32,
    pub not_after: i64,
    pub not_before: i64,
    pub issuer: String,
    pub issuer_cn: String,
    pub is_valid: bool,
    pub time_to_expiration: String,
    pub days_to_expiration: i64,
    pub key_usage: Vec<String>,
    pub is_ca: bool,
    pub path_len_constraint: Option<u32>,
    pub public_key_algorithm: String,
    pub public_key_size: Option<usize>,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
}

#[derive(Serialize, Deserialize, Savefile, Debug, Clone, PartialEq)]
pub struct Cert {
    pub server: ServerCert,
    pub intermediate: IntermediateCert,
    pub chain_length: usize,
    pub protocol_version: String,
}

#[derive(Debug, Clone)]
pub struct CheckSSLConfig {
    pub timeout: Duration,
    pub port: u16,
}

impl Default for CheckSSLConfig {
    fn default() -> Self {
        CheckSSLConfig {
            timeout: Duration::from_secs(5),
            port: 443,
        }
    }
}

pub struct CheckSSL();

impl CheckSSL {
    /// Check ssl from domain with port 443 (blocking)
    ///
    /// Example
    ///
    /// ```no_run
    /// use checkssl::CheckSSL;
    ///
    /// match CheckSSL::from_domain("rust-lang.org".to_string()) {
    ///   Ok(certificate) => {
    ///     // do something with certificate
    ///     assert!(certificate.server.is_valid);
    ///   }
    ///   Err(e) => {
    ///     // ssl invalid
    ///     eprintln!("{}", e);
    ///   }
    /// }
    /// ```
    pub fn from_domain(domain: String) -> Result<Cert, std::io::Error> {
        Self::from_domain_with_config(domain, CheckSSLConfig::default())
    }

    /// Check ssl from domain with custom configuration (blocking)
    pub fn from_domain_with_config(domain: String, config: CheckSSLConfig) -> Result<Cert, std::io::Error> {
        Self::check_cert_blocking(domain, config)
    }

    /// Check ssl from domain (non-blocking)
    pub fn from_domain_async(domain: String) -> Pin<Box<dyn Future<Output = Result<Cert, std::io::Error>> + Send>> {
        Self::from_domain_async_with_config(domain, CheckSSLConfig::default())
    }

    /// Check ssl from domain with custom configuration (non-blocking)
    pub fn from_domain_async_with_config(domain: String, config: CheckSSLConfig) -> Pin<Box<dyn Future<Output = Result<Cert, std::io::Error>> + Send>> {
        Box::pin(async move {
            Self::check_cert_blocking(domain, config)
        })
    }

    fn check_cert_blocking(domain: String, config: CheckSSLConfig) -> Result<Cert, std::io::Error> {

        let (sender, receiver) = mpsc::channel();
        let timeout = config.timeout;
        let port = config.port;
        let _t = thread::spawn(move || {
            let mut rustls_config = rustls::ClientConfig::new();
            rustls_config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    
            let rc_config = Arc::new(rustls_config);
            let dnn = domain.clone();
            let dnnn = dnn.as_str();
            let site = match webpki::DNSNameRef::try_from_ascii_str(dnnn) {
                Ok(val) => val,
                Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e.to_string())),
            };
    
            match format!("{}:{}", domain.clone().as_str(), port).to_socket_addrs(){
                Ok(mut val) => {
                    match val.next(){
                        Some(connect_domain) => {
    
                            let mut sess = rustls::ClientSession::new(&rc_config, site);
                            let mut sock = TcpStream::connect_timeout(&connect_domain, timeout)?;
                            let mut tls = rustls::Stream::new(&mut sess, &mut sock);
                    
                            let req = format!("GET / HTTP/1.0\r\nHost: {}\r\nConnection: \
                                                   close\r\nAccept-Encoding: identity\r\n\r\n",
                                              domain.clone());
                            tls.write_all(req.as_bytes())?;
                    
                            let mut server_cert = ServerCert {
                                common_name: "".to_string(),
                                signature_algorithm: "".to_string(),
                                sans: Vec::new(),
                                country: "".to_string(),
                                state: "".to_string(),
                                locality: "".to_string(),
                                organization: "".to_string(),
                                organizational_unit: "".to_string(),
                                serial_number: "".to_string(),
                                version: 0,
                                not_after: 0,
                                not_before: 0,
                                issuer: "".to_string(),
                                issuer_cn: "".to_string(),
                                is_valid: false,
                                time_to_expiration: "".to_string(),
                                days_to_expiration: 0,
                                key_usage: Vec::new(),
                                extended_key_usage: Vec::new(),
                                public_key_algorithm: "".to_string(),
                                public_key_size: None,
                                fingerprint_sha256: "".to_string(),
                                fingerprint_sha1: "".to_string(),
                            };
                    
                            let mut intermediate_cert = IntermediateCert {
                                common_name: "".to_string(),
                                signature_algorithm: "".to_string(),
                                country: "".to_string(),
                                state: "".to_string(),
                                locality: "".to_string(),
                                organization: "".to_string(),
                                organizational_unit: "".to_string(),
                                serial_number: "".to_string(),
                                version: 0,
                                not_after: 0,
                                not_before: 0,
                                issuer: "".to_string(),
                                issuer_cn: "".to_string(),
                                is_valid: false,
                                time_to_expiration: "".to_string(),
                                days_to_expiration: 0,
                                key_usage: Vec::new(),
                                is_ca: false,
                                path_len_constraint: None,
                                public_key_algorithm: "".to_string(),
                                public_key_size: None,
                                fingerprint_sha256: "".to_string(),
                                fingerprint_sha1: "".to_string(),
                            };
                    
                            let protocol_version = format!("{:?}", tls.sess.get_protocol_version());
                            let chain_length = tls.sess.get_peer_certificates().map(|c| c.len()).unwrap_or(0);

                            if let Some(certificates) = tls.sess.get_peer_certificates() {
                                
                                for certificate in certificates.iter() {
    
                                    let x509cert = match parse_x509_der(certificate.as_ref()) {
                                        Ok((_, x509cert)) => x509cert,
                                        Err(e) => return Err(Error::new(ErrorKind::Other, e.to_string())),
                                    };
                    
                                    let is_ca = match x509cert.tbs_certificate.basic_constraints() {
                                        Some((_, basic_constraints)) => basic_constraints.ca,
                                        None => false,
                                    };
                    
                                    // Calculate fingerprints
                                    let mut hasher_sha256 = Sha256::new();
                                    hasher_sha256.update(certificate.as_ref());
                                    let fingerprint_sha256 = format!("{:X}", hasher_sha256.finalize());
                                    
                                    let mut hasher_sha1 = Sha1::new();
                                    hasher_sha1.update(certificate.as_ref());
                                    let fingerprint_sha1 = format!("{:X}", hasher_sha1.finalize());

                                    //check if it's ca or not, if ca then insert to intermediate certificate
                                    if is_ca {
                                        intermediate_cert.is_ca = true;
                                        intermediate_cert.is_valid = x509cert.validity().is_valid();
                                        intermediate_cert.not_after = x509cert.tbs_certificate.validity.not_after.timestamp();
                                        intermediate_cert.not_before = x509cert.tbs_certificate.validity.not_before.timestamp();
                                        intermediate_cert.version = x509cert.tbs_certificate.version as i32;
                                        intermediate_cert.serial_number = format!("{:X}", x509cert.tbs_certificate.serial);
                                        intermediate_cert.fingerprint_sha256 = fingerprint_sha256.clone();
                                        intermediate_cert.fingerprint_sha1 = fingerprint_sha1.clone();
                    
                                        match oid2sn(&x509cert.signature_algorithm.algorithm) {
                                            Ok(s) => {
                                                intermediate_cert.signature_algorithm = s.to_string();
                                            }
                                            Err(_e) =>  return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                                        }

                                        // Extract public key algorithm from the signature algorithm
                                        if intermediate_cert.signature_algorithm.contains("RSA") {
                                            intermediate_cert.public_key_algorithm = "RSA".to_string();
                                            // Key size is not easily accessible in this version
                                        } else if intermediate_cert.signature_algorithm.contains("ECDSA") {
                                            intermediate_cert.public_key_algorithm = "EC".to_string();
                                        } else if intermediate_cert.signature_algorithm.contains("DSA") {
                                            intermediate_cert.public_key_algorithm = "DSA".to_string();
                                        } else {
                                            intermediate_cert.public_key_algorithm = "Unknown".to_string();
                                        }

                                        // Extract basic constraints path length
                                        if let Some((_, basic_constraints)) = x509cert.tbs_certificate.basic_constraints() {
                                            intermediate_cert.path_len_constraint = basic_constraints.path_len_constraint;
                                        }

                                        // Extract key usage
                                        if let Some((_, key_usage)) = x509cert.tbs_certificate.key_usage() {
                                            let mut usage = Vec::new();
                                            if key_usage.digital_signature() { usage.push("Digital Signature".to_string()); }
                                            if key_usage.non_repudiation() { usage.push("Non Repudiation".to_string()); }
                                            if key_usage.key_encipherment() { usage.push("Key Encipherment".to_string()); }
                                            if key_usage.data_encipherment() { usage.push("Data Encipherment".to_string()); }
                                            if key_usage.key_agreement() { usage.push("Key Agreement".to_string()); }
                                            if key_usage.key_cert_sign() { usage.push("Key Cert Sign".to_string()); }
                                            if key_usage.crl_sign() { usage.push("CRL Sign".to_string()); }
                                            if key_usage.encipher_only() { usage.push("Encipher Only".to_string()); }
                                            if key_usage.decipher_only() { usage.push("Decipher Only".to_string()); }
                                            intermediate_cert.key_usage = usage;
                                        }
                    
                                        if let Some(time_to_expiration) = x509cert.tbs_certificate.validity.time_to_expiration() {
                                            let days = time_to_expiration.as_secs() / 60 / 60 / 24;
                                            intermediate_cert.time_to_expiration = format!("{} day(s)", days);
                                            intermediate_cert.days_to_expiration = days as i64;
                                        }
                    
                                        let issuer = x509cert.issuer();
                                        let subject = x509cert.subject();
                    
                                        let mut issuer_full = Vec::new();
                                        for rdn_seq in &issuer.rdn_seq {
                                            match oid2sn(&rdn_seq.set[0].attr_type) {
                                                Ok(s) => {
                                                    let rdn_content = rdn_seq.set[0].attr_value.content.as_str().unwrap().to_string();
                                                    issuer_full.push(format!("{}={}", s, rdn_content));
                                                    if s == "CN" {
                                                        intermediate_cert.issuer_cn = rdn_content;
                                                    }
                                                }
                                                Err(_e) =>  return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                                            }
                                        }
                                        intermediate_cert.issuer = issuer_full.join(", ");
                    
                                        for rdn_seq in &subject.rdn_seq {
                                            match oid2sn(&rdn_seq.set[0].attr_type) {
                                                Ok(s) => {
                                                    let rdn_content = rdn_seq.set[0].attr_value.content.as_str().unwrap().to_string();
                                                    match s {
                                                        "C" => intermediate_cert.country = rdn_content,
                                                        "ST" => intermediate_cert.state = rdn_content,
                                                        "L" => intermediate_cert.locality = rdn_content,
                                                        "CN" => intermediate_cert.common_name = rdn_content,
                                                        "O" => intermediate_cert.organization = rdn_content,
                                                        "OU" => intermediate_cert.organizational_unit = rdn_content,
                                                        _ => {}
                                                    }
                                                }
                                                Err(_e) =>  return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                                            }
                                        }
                                    } else {
                                        server_cert.is_valid = x509cert.validity().is_valid();
                                        server_cert.not_after = x509cert.tbs_certificate.validity.not_after.timestamp();
                                        server_cert.not_before = x509cert.tbs_certificate.validity.not_before.timestamp();
                                        server_cert.version = x509cert.tbs_certificate.version as i32;
                                        server_cert.serial_number = format!("{:X}", x509cert.tbs_certificate.serial);
                                        server_cert.fingerprint_sha256 = fingerprint_sha256;
                                        server_cert.fingerprint_sha1 = fingerprint_sha1;
                    
                                        match oid2sn(&x509cert.signature_algorithm.algorithm) {
                                            Ok(s) => {
                                                server_cert.signature_algorithm = s.to_string();
                                            }
                                            Err(_e) =>  return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                                        }

                                        // Extract public key algorithm from the signature algorithm
                                        if server_cert.signature_algorithm.contains("RSA") {
                                            server_cert.public_key_algorithm = "RSA".to_string();
                                            // Key size is not easily accessible in this version
                                        } else if server_cert.signature_algorithm.contains("ECDSA") {
                                            server_cert.public_key_algorithm = "EC".to_string();
                                        } else if server_cert.signature_algorithm.contains("DSA") {
                                            server_cert.public_key_algorithm = "DSA".to_string();
                                        } else {
                                            server_cert.public_key_algorithm = "Unknown".to_string();
                                        }

                                        // Extract key usage
                                        if let Some((_, key_usage)) = x509cert.tbs_certificate.key_usage() {
                                            let mut usage = Vec::new();
                                            if key_usage.digital_signature() { usage.push("Digital Signature".to_string()); }
                                            if key_usage.non_repudiation() { usage.push("Non Repudiation".to_string()); }
                                            if key_usage.key_encipherment() { usage.push("Key Encipherment".to_string()); }
                                            if key_usage.data_encipherment() { usage.push("Data Encipherment".to_string()); }
                                            if key_usage.key_agreement() { usage.push("Key Agreement".to_string()); }
                                            if key_usage.key_cert_sign() { usage.push("Key Cert Sign".to_string()); }
                                            if key_usage.crl_sign() { usage.push("CRL Sign".to_string()); }
                                            if key_usage.encipher_only() { usage.push("Encipher Only".to_string()); }
                                            if key_usage.decipher_only() { usage.push("Decipher Only".to_string()); }
                                            server_cert.key_usage = usage;
                                        }

                                        // Extract extended key usage
                                        if let Some((_, eku)) = x509cert.tbs_certificate.extended_key_usage() {
                                            let mut usage = Vec::new();
                                            if eku.any { usage.push("Any".to_string()); }
                                            if eku.server_auth { usage.push("Server Auth".to_string()); }
                                            if eku.client_auth { usage.push("Client Auth".to_string()); }
                                            if eku.code_signing { usage.push("Code Signing".to_string()); }
                                            if eku.email_protection { usage.push("Email Protection".to_string()); }
                                            if eku.time_stamping { usage.push("Time Stamping".to_string()); }
                                            if eku.ocscp_signing { usage.push("OCSP Signing".to_string()); }
                                            server_cert.extended_key_usage = usage;
                                        }
                    
                                        if let Some((_, san)) = x509cert.tbs_certificate.subject_alternative_name() {
                                            for name in san.general_names.iter() {
                                                match name {
                                                    GeneralName::DNSName(dns) => {
                                                        server_cert.sans.push(dns.to_string())
                                                    }
                                                    _ => {},
                                                }
                                            }
                                        }
                    
                                        if let Some(time_to_expiration) = x509cert.tbs_certificate.validity.time_to_expiration() {
                                            let days = time_to_expiration.as_secs() / 60 / 60 / 24;
                                            server_cert.time_to_expiration = format!("{} day(s)", days);
                                            server_cert.days_to_expiration = days as i64;
                                        }
                    
                                        let issuer = x509cert.issuer();
                                        let subject = x509cert.subject();
                    
                                        let mut issuer_full = Vec::new();
                                        for rdn_seq in &issuer.rdn_seq {
                                            match oid2sn(&rdn_seq.set[0].attr_type) {
                                                Ok(s) => {
                                                    let rdn_content = rdn_seq.set[0].attr_value.content.as_str().unwrap().to_string();
                                                    issuer_full.push(format!("{}={}", s, rdn_content));
                                                    if s == "CN" {
                                                        server_cert.issuer_cn = rdn_content;
                                                    }
                                                }
                                                Err(_e) =>  return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                                            }
                                        }
                                        server_cert.issuer = issuer_full.join(", ");
                    
                                        for rdn_seq in &subject.rdn_seq {
                                            match oid2sn(&rdn_seq.set[0].attr_type) {
                                                Ok(s) => {
                                                    let rdn_content = rdn_seq.set[0].attr_value.content.as_str().unwrap().to_string();
                                                    match s {
                                                        "C" => server_cert.country = rdn_content,
                                                        "ST" => server_cert.state = rdn_content,
                                                        "L" => server_cert.locality = rdn_content,
                                                        "CN" => server_cert.common_name = rdn_content,
                                                        "O" => server_cert.organization = rdn_content,
                                                        "OU" => server_cert.organizational_unit = rdn_content,
                                                        _ => {}
                                                    }
                                                }
                                                Err(_e) =>  return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                                            }
                                        }
                                    }
                                }
                    
                                let cert = Cert{
                                    server: server_cert,
                                    intermediate: intermediate_cert,
                                    chain_length,
                                    protocol_version,
                                };
                                match sender.send(cert.clone()) {
                                    Ok(()) => {

                                        return Ok(cert.clone());

                                    }, // everything good
                                    Err(_) => {
                                        return Err(Error::new(ErrorKind::Other, "Error sending message to main thread".to_string()));
                                    }, // we have been released, don't panic
                                }
                         
                            } else {
                                Err(Error::new(ErrorKind::NotFound, "certificate not found".to_string()))
                            }
                        },
                        None => return Err(Error::new(ErrorKind::InvalidInput, "empty".to_string()))
                    }
                },
                Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e.to_string()))
            }
    









      
        });
        match receiver.recv_timeout(timeout){
            Ok(dat) => {
                return Ok(dat);
            },
            Err(_e) => return Err(Error::new(ErrorKind::TimedOut, "Certificate check timed out".to_string()))
        }

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn main() {
        println!("SSL: {:?}", CheckSSL::from_domain("rust-lang.org".to_string()));
       
    }

    #[test]
    fn test_check_ssl_server_is_valid() {
        println!("SSL: {:?}", CheckSSL::from_domain("rust-lang.org".to_string()));
        assert!(CheckSSL::from_domain("rust-lang.org".to_string()).unwrap().server.is_valid);
    }

    #[test]
    fn test_check_ssl_server_is_invalid() {
        let actual = CheckSSL::from_domain("expired.badssl.com".to_string());
        // The test may fail with either InvalidData or TimedOut depending on the SSL verification
        assert!(actual.is_err());
    }

    #[test]
    fn test_check_ssl_with_custom_config() {
        let config = CheckSSLConfig {
            timeout: Duration::from_secs(10),
            port: 443,
        };
        let result = CheckSSL::from_domain_with_config("rust-lang.org".to_string(), config);
        assert!(result.is_ok());
        let cert = result.unwrap();
        assert!(cert.server.is_valid);
        assert!(!cert.server.fingerprint_sha256.is_empty());
        assert!(!cert.server.public_key_algorithm.is_empty());
    }
}
