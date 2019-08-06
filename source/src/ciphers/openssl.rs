extern crate openssl;

use ciphers::Cipher;

use std::vec::Vec;
use std::marker::PhantomData;
use self::generic_array::{GenericArray, ArrayLength};
use openssl::symm::{encrypt, decrypt};
use openssl::symm::Cipher as BlockCipher;

pub struct OpenSSLCipher<KeyLength : ArrayLength<u8>, IVLength : ArrayLength<u8>> {
    key : GenericArray<u8, KeyLength>,
    iv : GenericArray<u8, IVLength>, // TODO: different ivs for different blocks?
    cipher : BlockCipher
}

impl <KeyLength : ArrayLength<u8>, IVLength : ArrayLength<u8>> OpenSSLCipher<KeyLength, IVLength> {
    pub fn create(key : GenericArray<u8, KeyLength>, iv : GenericArray<u8, IVLength>, cipher : BlockCipher) -> Self {
        OpenSSLCipher::<KeyLength, IVLength> {
            key,
            iv,
            cipher
        }
    }
}

impl <KeyLength : ArrayLength<u8>, IVLength : ArrayLength<u8>> Cipher for OpenSSLCipher<KeyLength, IVLength> {
    fn encrypt(&self, buffer : &[u8]) -> Vec<u8> {
        encrypt(
            self.cipher.clone(),
            key,
            Some(iv),
            buffer).unwrap()
    }

    fn decrypt(&self, buffer : &mut [u8]) {
        let v = decrypt(
            self.cipher.clone(),
            key,
            Some(iv),
            buffer).unwrap();
        buffer[..v.len()].copy_from_slice(v);
    }
}