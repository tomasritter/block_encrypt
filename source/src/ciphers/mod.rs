use self::rust::CipherImpl;
use block_modes::{BlockMode, Cbc, Ecb, Pcbc, Xts};
use block_modes::block_padding::ZeroPadding;
use aes::{Aes128, Aes192, Aes256};
use enum_dispatch::enum_dispatch;

pub type Aes128Cbc = CipherImpl<Aes128, Cbc<Aes128, ZeroPadding>>;
pub type Aes128Ecb = CipherImpl<Aes128, Ecb<Aes128, ZeroPadding>>;
pub type Aes128Pcbc = CipherImpl<Aes128, Pcbc<Aes128, ZeroPadding>>;
pub type Aes128Xts = CipherImpl<Aes128, Xts<Aes128, ZeroPadding>>;

pub type Aes192Cbc = CipherImpl<Aes192, Cbc<Aes192, ZeroPadding>>;
pub type Aes192Ecb = CipherImpl<Aes192, Ecb<Aes192, ZeroPadding>>;
pub type Aes192Pcbc = CipherImpl<Aes192, Pcbc<Aes192, ZeroPadding>>;
pub type Aes192Xts = CipherImpl<Aes192, Xts<Aes192, ZeroPadding>>;

pub type Aes256Cbc = CipherImpl<Aes256, Cbc<Aes256, ZeroPadding>>;
pub type Aes256Ecb = CipherImpl<Aes256, Ecb<Aes256, ZeroPadding>>;
pub type Aes256Pcbc = CipherImpl<Aes256, Pcbc<Aes256, ZeroPadding>>;
pub type Aes256Xts = CipherImpl<Aes256, Xts<Aes256, ZeroPadding>>;

mod rust;
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
    Aes256Xts(Aes256Xts)
}