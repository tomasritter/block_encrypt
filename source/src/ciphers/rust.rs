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


// !!!TODO: Check whether size of key and iv arrays can be somehow precomputed from BC: BlockCipher type with some magic/already in crate
pub struct RustCipher<BC : BlockCipher, C : BlockMode<BC, ZeroPadding>, KeyLength : ArrayLength<u8>, IVLength : ArrayLength<u8>> {
    key : GenericArray<u8, KeyLength>, // TODO: Change to native const generics if they become available in my lifetime
    iv : GenericArray<u8, IVLength>, // TODO: different iv's for different blocks?
    cipher_type : PhantomData<BC>,
    cipher_impl : PhantomData<C>
}

impl <BC : BlockCipher, C : BlockMode<BC, ZeroPadding>, KeyLength : ArrayLength<u8>, IVLength : ArrayLength<u8>> RustCipher<BC, C, KeyLength, IVLength> {
    // TODO: Probably change arguments to Vec with some asserts about the size of it? Will see after salting of key
    pub fn create(key : GenericArray<u8, KeyLength>, iv : GenericArray<u8, IVLength>) -> Self {
        RustCipher::<BC, C, KeyLength, IVLength> {
            key,
            iv,
            cipher_type : PhantomData,
            cipher_impl : PhantomData
        }
    }
}

impl <BC : BlockCipher, C : BlockMode<BC, ZeroPadding>, KeyLength : ArrayLength<u8>, IVLength : ArrayLength<u8>> Cipher for RustCipher<BC, C, KeyLength, IVLength> {
    fn encrypt(&self, buffer : &[u8]) -> Vec<u8> {
        let c = C::new_var(&self.key, &self.iv).unwrap();
        c.encrypt_vec(buffer)
    }

    fn decrypt(&self, buffer : &mut [u8]) {
        let c = C::new_var(&self.key, &self.iv).unwrap();
        c.decrypt(buffer);
    }
}