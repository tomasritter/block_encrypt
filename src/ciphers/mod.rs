use self::cipher::{CipherImpl, XTSCipherImpl};
use block_modes::{Cbc, Ecb, Pcbc};
use block_modes::block_padding::NoPadding;
use aes::{Aes128, Aes192, Aes256};
use aesni::{Aes128 as Aesni128, Aes192 as Aesni192, Aes256 as Aesni256};
use enum_dispatch::enum_dispatch;

pub type Aes128Cbc = CipherImpl<Aes128, Cbc<Aes128, NoPadding>>;
pub type Aes128Ecb = CipherImpl<Aes128, Ecb<Aes128, NoPadding>>;
pub type Aes128Pcbc = CipherImpl<Aes128, Pcbc<Aes128, NoPadding>>;
pub type Aes128Xts = XTSCipherImpl<Aes128>;

pub type Aes192Cbc = CipherImpl<Aes192, Cbc<Aes192, NoPadding>>;
pub type Aes192Ecb = CipherImpl<Aes192, Ecb<Aes192, NoPadding>>;
pub type Aes192Pcbc = CipherImpl<Aes192, Pcbc<Aes192, NoPadding>>;
pub type Aes192Xts = XTSCipherImpl<Aes192>;

pub type Aes256Cbc = CipherImpl<Aes256, Cbc<Aes256, NoPadding>>;
pub type Aes256Ecb = CipherImpl<Aes256, Ecb<Aes256, NoPadding>>;
pub type Aes256Pcbc = CipherImpl<Aes256, Pcbc<Aes256, NoPadding>>;
pub type Aes256Xts = XTSCipherImpl<Aes256>;

pub type Aesni128Cbc = CipherImpl<Aesni128, Cbc<Aesni128, NoPadding>>;
pub type Aesni128Ecb = CipherImpl<Aesni128, Ecb<Aesni128, NoPadding>>;
pub type Aesni128Pcbc = CipherImpl<Aesni128, Pcbc<Aesni128, NoPadding>>;
pub type Aesni128Xts = XTSCipherImpl<Aesni128>;

pub type Aesni192Cbc = CipherImpl<Aesni192, Cbc<Aesni192, NoPadding>>;
pub type Aesni192Ecb = CipherImpl<Aesni192, Ecb<Aesni192, NoPadding>>;
pub type Aesni192Pcbc = CipherImpl<Aesni192, Pcbc<Aesni192, NoPadding>>;
pub type Aesni192Xts = XTSCipherImpl<Aesni192>;

pub type Aesni256Cbc = CipherImpl<Aesni256, Cbc<Aesni256, NoPadding>>;
pub type Aesni256Ecb = CipherImpl<Aesni256, Ecb<Aesni256, NoPadding>>;
pub type Aesni256Pcbc = CipherImpl<Aesni256, Pcbc<Aesni256, NoPadding>>;
pub type Aesni256Xts = XTSCipherImpl<Aesni256>;

mod cipher;
mod ivgenerators;

#[enum_dispatch(CipherEnum)]
pub trait Cipher {
    fn encrypt(&self, block : u64, buffer : &[u8]) -> Vec<u8>;
    fn decrypt(&self, block : u64, buffer : &mut [u8]);
}

#[enum_dispatch]
pub enum CipherEnum {
    Aes128Cbc(Aes128Cbc),
    Aes128Ecb(Aes128Ecb),
    Aes128Pcbc(Aes128Pcbc),
    Aes128Xts(Aes128Xts),

    Aes192Cbc(Aes192Cbc),
    Aes192Ecb(Aes192Ecb),
    Aes192Pcbc(Aes192Pcbc),
    Aes192Xts(Aes192Xts),

    Aes256Cbc(Aes256Cbc),
    Aes256Ecb(Aes256Ecb),
    Aes256Pcbc(Aes256Pcbc),
    Aes256Xts(Aes256Xts),

    Aesni128Cbc(Aesni128Cbc),
    Aesni128Ecb(Aesni128Ecb),
    Aesni128Pcbc(Aesni128Pcbc),
    Aesni128Xts(Aesni128Xts),

    Aesni192Cbc(Aesni192Cbc),
    Aesni192Ecb(Aesni192Ecb),
    Aesni192Pcbc(Aesni192Pcbc),
    Aesni192Xts(Aesni192Xts),

    Aesni256Cbc(Aesni256Cbc),
    Aesni256Ecb(Aesni256Ecb),
    Aesni256Pcbc(Aesni256Pcbc),
    Aesni256Xts(Aesni256Xts)
}
