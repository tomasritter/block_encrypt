extern crate block_modes;
extern crate aes_soft as aes;
extern crate block_cipher_trait;
extern crate generic_array;

use ciphers::Cipher;

use block_modes::BlockMode;
use block_modes::block_padding::ZeroPadding;
use std::vec::Vec;
use self::block_cipher_trait::{BlockCipher};
use std::marker::PhantomData;
use self::generic_array::{GenericArray, ArrayLength};
use super::ivgenerators::{IVGenerator, IVPlain, IVPlainBe, IVEssiv, IVNull};
use header::IVGeneratorEnum;

pub struct CipherImpl<BC : BlockCipher, C : BlockMode<BC, ZeroPadding>>
{
    key : GenericArray<u8, BC::KeySize>,
    iv_generator : Box<dyn IVGenerator<BC::BlockSize>>, // TODO: Try to get static dispatch working
    cipher_type : PhantomData<BC>,
    cipher_impl : PhantomData<C>
}

impl <BC : 'static + BlockCipher, C : BlockMode<BC, ZeroPadding>> CipherImpl<BC, C>
{
    pub fn create(key : &[u8], iv_generator_type : &IVGeneratorEnum) -> Self {
        let mut gen_key : GenericArray<u8, BC::KeySize> = Default::default();
        let gen_key_len = gen_key.len();
        //assert!(key.len() == gen_key.len());
        gen_key[..gen_key_len].copy_from_slice(key);

        let iv_generator = match iv_generator_type {
            IVGeneratorEnum::Plain => Box::new(IVPlain::<BC::BlockSize>::create()) as Box<dyn IVGenerator<BC::BlockSize>>,
            IVGeneratorEnum::PlainBE => Box::new(IVPlainBe::<BC::BlockSize>::create()) as Box<dyn IVGenerator<BC::BlockSize>>,
            IVGeneratorEnum::Null => Box::new(IVNull::<BC::BlockSize>::create()) as Box<dyn IVGenerator<BC::BlockSize>>,
            _ => Box::new(IVEssiv::<BC>::create(&gen_key, iv_generator_type))
        };

        CipherImpl::<BC, C> {
            key: gen_key,
            iv_generator,
            cipher_type : Default::default(),
            cipher_impl : Default::default()
        }
    }

    fn get_iv(&self, block : u64) -> GenericArray<u8, BC::BlockSize> {
        self.iv_generator.getiv(block)
    }
}

impl <BC : 'static + BlockCipher, C : BlockMode<BC, ZeroPadding>> Cipher for CipherImpl<BC, C>
{
    fn encrypt(&self, block : u64, buffer : &[u8]) -> Vec<u8> {
        let c = C::new_var(&self.key, &self.get_iv(block)).unwrap();
        c.encrypt_vec(buffer)
    }

    fn decrypt(&self, block : u64, buffer : &mut [u8]) {
        let c = C::new_var(&self.key, &self.get_iv(block)).unwrap();
        c.decrypt(buffer);
    }
}