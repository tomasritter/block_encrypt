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

pub struct RustCipher<BC : BlockCipher, C : BlockMode<BC, ZeroPadding>>
{
    key : GenericArray<u8, <BC as BlockCipher>::KeySize>,
    iv_generator : Box<dyn IVGenerator<<BC as BlockCipher>::BlockSize>>, // TODO: Try to get static dispatch working
    cipher_type : PhantomData<BC>,
    cipher_impl : PhantomData<C>
}

impl <BC : 'static + BlockCipher, C : BlockMode<BC, ZeroPadding>> RustCipher<BC, C>
{
    pub fn create(key : &[u8], iv_generator_type : &IVGeneratorEnum) -> Self {
        let mut gen_key : GenericArray<u8, <BC as BlockCipher>::KeySize> = Default::default();
        let gen_key_len = gen_key.len();
        //assert!(key.len() == gen_key.len());
        gen_key[..gen_key_len].copy_from_slice(key);

        let iv_generator = match iv_generator_type {
            IVGeneratorEnum::Plain => Box::new(IVPlain::<<BC as BlockCipher>::BlockSize>::create()) as Box<dyn IVGenerator<<BC as BlockCipher>::BlockSize>>,
            IVGeneratorEnum::PlainBE => Box::new(IVPlainBe::<<BC as BlockCipher>::BlockSize>::create()) as Box<dyn IVGenerator<<BC as BlockCipher>::BlockSize>>,
            IVGeneratorEnum::Null => Box::new(IVNull::<<BC as BlockCipher>::BlockSize>::create()) as Box<dyn IVGenerator<<BC as BlockCipher>::BlockSize>>,
            _ => Box::new(IVEssiv::<BC, <BC as BlockCipher>::KeySize, <BC as BlockCipher>::BlockSize>::create(&gen_key, iv_generator_type))
        };

        RustCipher::<BC, C> {
            key: gen_key,
            iv_generator,
            cipher_type : PhantomData,
            cipher_impl : PhantomData
        }
    }

    fn get_iv(&self, block : u64) -> GenericArray<u8, <BC as BlockCipher>::BlockSize> {
        self.iv_generator.getiv(block)
    }
}

impl <BC : 'static + BlockCipher, C : BlockMode<BC, ZeroPadding>> Cipher for RustCipher<BC, C>
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