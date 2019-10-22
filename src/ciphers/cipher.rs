use ciphers::Cipher;
use block_modes::BlockMode;
use block_modes::block_padding::ZeroPadding;
use std::vec::Vec;
use block_cipher_trait::{BlockCipher};
use std::marker::PhantomData;
use generic_array::{GenericArray};
use super::ivgenerators::{IVGenerator, IVPlain, IVPlainBe, IVEssiv, IVNull, IVGeneratorEnumType};
use header::IVGeneratorEnum;

pub struct CipherImpl<BC : BlockCipher, C : BlockMode<BC, ZeroPadding>>
{
    key : Vec<u8>,
    iv_generator : IVGeneratorEnumType<BC>,
    cipher_type : PhantomData<BC>,
    cipher_impl : PhantomData<C>
}

impl <BC : 'static + BlockCipher, C : BlockMode<BC, ZeroPadding>> CipherImpl<BC, C>
{
    pub fn create(key : &[u8], iv_generator_type : &IVGeneratorEnum) -> Self {
        let gen_key = key.to_vec();

        let iv_generator = match iv_generator_type {
            IVGeneratorEnum::Plain => IVPlain::<BC>::create().into(),
            IVGeneratorEnum::PlainBE => IVPlainBe::<BC>::create().into(),
            IVGeneratorEnum::Null => IVNull::<BC>::create().into(),
            _ => IVEssiv::<BC>::create(&gen_key, iv_generator_type).into()
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
        c.decrypt(buffer).unwrap();
    }
}