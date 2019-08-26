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


// !!!TODO: Check whether size of key and iv arrays can be somehow precomputed from BC: BlockCipher type with some magic/already in crate
pub struct RustCipher<BC : BlockCipher, C : BlockMode<BC, ZeroPadding>, KeyLength : 'static + ArrayLength<u8>, IVLength : 'static + ArrayLength<u8>>
    where
        BC: BlockCipher<KeySize = KeyLength, BlockSize = IVLength>,
        <BC as BlockCipher>::ParBlocks: ArrayLength<GenericArray<u8, IVLength>>
{
    key : GenericArray<u8, KeyLength>,
    iv_generator : Box<dyn IVGenerator<IVLength>>, // TODO: Try to get static dispatch working
    cipher_type : PhantomData<BC>,
    cipher_impl : PhantomData<C>
}

impl <BC : 'static + BlockCipher, C : BlockMode<BC, ZeroPadding>, KeyLength : 'static + ArrayLength<u8>, IVLength : 'static + ArrayLength<u8>> RustCipher<BC, C, KeyLength, IVLength>
    where
        BC: BlockCipher<KeySize = KeyLength, BlockSize = IVLength>,
        <BC as BlockCipher>::ParBlocks: ArrayLength<GenericArray<u8, IVLength>>
{
    // TODO: Probably change arguments to Vec with some asserts about the size of it? Will see after salting of key
    pub fn create(key : &[u8], iv_generator_type : &IVGeneratorEnum) -> Self {
        let mut gen_key : GenericArray<u8, KeyLength> = Default::default();
        let gen_key_len = gen_key.len();
        //assert!(key.len() == gen_key.len());
        gen_key[..gen_key_len].copy_from_slice(key);

        let iv_generator = match iv_generator_type {
            IVGeneratorEnum::Plain => Box::new(IVPlain::<IVLength>::create()) as Box<dyn IVGenerator<IVLength>>,
            IVGeneratorEnum::PlainBE => Box::new(IVPlainBe::<IVLength>::create()) as Box<dyn IVGenerator<IVLength>>,
            IVGeneratorEnum::Null => Box::new(IVNull::<IVLength>::create()) as Box<dyn IVGenerator<IVLength>>,
            _ => Box::new(IVEssiv::<BC, KeyLength, IVLength>::create(&gen_key, iv_generator_type))
        };

        RustCipher::<BC, C, KeyLength, IVLength> {
            key: gen_key,
            iv_generator,
            cipher_type : PhantomData,
            cipher_impl : PhantomData
        }
    }

    fn get_iv(&self, block : u64) -> GenericArray<u8, IVLength> {
        self.iv_generator.getiv(block)
    }
}

impl <BC : 'static + BlockCipher, C : BlockMode<BC, ZeroPadding>, KeyLength : 'static + ArrayLength<u8>, IVLength : 'static + ArrayLength<u8>> Cipher for RustCipher<BC, C, KeyLength, IVLength>
    where
        BC: BlockCipher<KeySize = KeyLength, BlockSize = IVLength>,
        <BC as BlockCipher>::ParBlocks: ArrayLength<GenericArray<u8, IVLength>>
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