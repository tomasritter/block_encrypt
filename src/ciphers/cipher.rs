use ciphers::Cipher;
use block_modes::{BlockMode, Xts};
use block_modes::block_padding::NoPadding;
use std::vec::Vec;
use block_cipher_trait::{BlockCipher};
use std::marker::PhantomData;
use generic_array::{GenericArray, ArrayLength};
use super::ivgenerators::{IVGenerator, IVPlain, IVPlainBe, IVEssiv, IVNull, IVGeneratorEnumType};
use header::IVType;
use typenum::Sum;

pub struct CipherImpl<BC : BlockCipher, C : BlockMode<BC, NoPadding>>
{
    key : GenericArray<u8, BC::KeySize>,
    iv_generator : IVGeneratorEnumType<BC>,
    cipher_impl : PhantomData<C>
}

impl <BC : BlockCipher, C : BlockMode<BC, NoPadding>> CipherImpl<BC, C>
{
    pub fn create(key : &[u8], iv_generator_type : &IVType) -> Self {
        let mut key_copy : GenericArray<u8, BC::KeySize> = Default::default();
        assert_eq!(key.len(), key_copy.len());
        let key_len = key_copy.len();
        key_copy[..key_len].copy_from_slice(key);

        let iv_generator = match iv_generator_type {
            IVType::Plain => IVPlain::<BC>::create().into(),
            IVType::PlainBE => IVPlainBe::<BC>::create().into(),
            IVType::Null => IVNull::<BC>::create().into(),
            _ => IVEssiv::<BC>::create(&key_copy, iv_generator_type).into()
        };

        CipherImpl::<BC, C> {
            key: key_copy,
            iv_generator,
            cipher_impl : Default::default()
        }
    }

    fn get_iv(&self, block : u64) -> GenericArray<u8, BC::BlockSize> {
        self.iv_generator.getiv(block)
    }
}

impl <BC : BlockCipher, C : BlockMode<BC, NoPadding>> Cipher for CipherImpl<BC, C>
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


// Specialization for XTS cipher mode, since it requires double the size of the key
// and the initialization vector is always plain
pub struct XTSCipherImpl<BC: BlockCipher>
where BC::KeySize: std::ops::Add,
    <BC::KeySize as std::ops::Add>::Output: ArrayLength<u8>
{
    key: GenericArray<u8, Sum<BC::KeySize, BC::KeySize>>,
    iv_generator: IVPlain<BC>
}

impl <BC: BlockCipher> XTSCipherImpl<BC>
where BC::KeySize: std::ops::Add,
      <BC::KeySize as std::ops::Add>::Output: ArrayLength<u8>
{
    pub fn create(key: &[u8]) -> Self {
        let mut key_copy : GenericArray<u8, Sum<BC::KeySize, BC::KeySize>> = Default::default();
        let key_len = key_copy.len();
        key_copy[..key_len].copy_from_slice(key);

        XTSCipherImpl::<BC> {
            key: key_copy,
            iv_generator : IVPlain::<BC>::create()
        }
    }
}

impl <BC : BlockCipher> Cipher for XTSCipherImpl<BC>
where BC::KeySize: std::ops::Add,
      <BC::KeySize as std::ops::Add>::Output: ArrayLength<u8>
{
    fn encrypt(&self, block : u64, buffer : &[u8]) -> Vec<u8> {
        let c = Xts::<BC, NoPadding>::new_var(&self.key, &self.iv_generator.getiv(block)).unwrap();
        c.encrypt_vec(buffer)
    }

    fn decrypt(&self, block : u64, buffer : &mut [u8]) {
        let c = Xts::<BC, NoPadding>::new_var(&self.key, &self.iv_generator.getiv(block)).unwrap();
        c.decrypt(buffer).unwrap();
    }
}
