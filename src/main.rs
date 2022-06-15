use checkssl::CheckSSL;

fn main() {
    println!("SSL: {:?}", CheckSSL::from_domain("rust-lang.org".to_string()));
    println!("SSL: {:?}", CheckSSL::from_domain("rusaffdsst-lang.org".to_string()));
    println!("SSL: {:?}", CheckSSL::from_domain("pixelcoda.com".to_string()));
    println!("SSL: {:?}", CheckSSL::from_domain("ckitl.com".to_string()));
    println!("SSL: {:?}", CheckSSL::from_domain("test.ckitl.com".to_string()));
}
