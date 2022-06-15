use checkssl::CheckSSL;

fn main() {
    println!("SSL: {:?}", CheckSSL::from_domain("rust-lang.org"));
   
}
