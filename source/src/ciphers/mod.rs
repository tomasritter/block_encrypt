pub use self::rust::CipherImpl;
pub use self::ivgenerators::IVGenerator;
pub use self::ivgenerators::IVPlain;
pub use self::ivgenerators::IVPlainBe;
pub use self::ivgenerators::IVNull;
pub use self::ivgenerators::IVEssiv;

mod rust;
mod ivgenerators;

pub trait Cipher {
    fn encrypt(&self, block : u64, buffer : &[u8]) -> Vec<u8>;
    fn decrypt(&self, block : u64, buffer : &mut [u8]);
}
