pub use self::rust::RustCipher;
pub use self::ivgenerators::IVGenerator;
pub use self::ivgenerators::IVPlain;
pub use self::ivgenerators::IVPlainBe;
pub use self::ivgenerators::IVNull;
pub use self::ivgenerators::IVEssiv;
//pub use self::openssl::OpenSSLCipher;

mod rust;
mod ivgenerators;
//mod openssl;

pub trait Cipher {
    fn encrypt(&self, block : u64, buffer : &[u8]) -> Vec<u8>;
    fn decrypt(&self, block : u64, buffer : &mut [u8]);
}
