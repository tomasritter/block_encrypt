pub use self::rust::RustCipher;
//pub use self::openssl::OpenSSLCipher;

mod rust;
//mod openssl;

pub trait Cipher {
    fn encrypt(&self, buffer : &[u8]) -> Vec<u8>;
    fn decrypt(&self, buffer : &mut [u8]);
}
