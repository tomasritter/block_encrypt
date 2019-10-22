extern crate typenum;
extern crate byteorder;
extern crate generic_array;
extern crate digest;
extern crate blake2;
extern crate sha2;
extern crate sha3;
extern crate groestl;
extern crate block_cipher_trait;
extern crate aes_soft as aes;


use self::byteorder::{ByteOrder, LittleEndian, BigEndian};
use self::generic_array::{GenericArray, ArrayLength};
use std::marker::PhantomData;
use self::digest::Digest;
use self::blake2::{Blake2b, Blake2s};
use self::sha2::{Sha256, Sha512};
use self::sha3::{Sha3_256, Sha3_512};
use self::groestl::{Groestl256};
use self::block_cipher_trait::BlockCipher;
use typenum::{U1, Unsigned};
use header::IVGeneratorEnum;

pub trait IVGenerator<IVLength : ArrayLength<u8>> {
    fn getiv(&self, block : u64) -> GenericArray<u8, IVLength>;
}

pub struct IVPlain<IVLength : ArrayLength<u8>> {
    ivlength : PhantomData<IVLength>
}

impl <IVLength : ArrayLength<u8>> IVPlain<IVLength> {
    pub fn create() -> Self {
        IVPlain::<IVLength> {
            ivlength : Default::default()
        }
    }
}

impl <IVLength : ArrayLength<u8>> IVGenerator<IVLength> for IVPlain<IVLength> {
    fn getiv(&self, block : u64) -> GenericArray<u8, IVLength> {
        let mut buf : GenericArray<u8, IVLength> = Default::default();
        if buf.len() == 8 {
            LittleEndian::write_u64(&mut buf, block);
        }
        else if buf.len() == 16 {
            LittleEndian::write_u128(&mut buf, block as u128);
        }
        else {
            assert!(false);
        }
        buf
    }
}

pub struct IVPlainBe<IVLength : ArrayLength<u8>> {
    ivlength : PhantomData<IVLength>
}

impl <IVLength : ArrayLength<u8>> IVPlainBe<IVLength> {
    pub fn create() -> Self {
        IVPlainBe::<IVLength> {
            ivlength : Default::default()
        }
    }
}

impl <IVLength : ArrayLength<u8>> IVGenerator<IVLength> for IVPlainBe<IVLength> {
    fn getiv(&self, block : u64) -> GenericArray<u8, IVLength> {
        let mut buf : GenericArray<u8, IVLength> = Default::default();
        if buf.len() == 8 {
            BigEndian::write_u64(&mut buf, block);
        }
        else if buf.len() == 16 {
            BigEndian::write_u128(&mut buf, block as u128);
        }
        else {
            assert!(false);
        }
        buf
    }
}

pub struct IVEssiv<Cipher: BlockCipher>
{
    hashed_key: GenericArray<u8, Cipher::KeySize>,
    plain_gen: IVPlain<Cipher::BlockSize>,
    cipher_type: PhantomData<Cipher>
}

impl <Cipher: BlockCipher> IVEssiv<Cipher>
{
    pub fn create(key : &[u8], essiv_generator : &IVGeneratorEnum) -> Self {
        let mut hashed_key : GenericArray<u8, Cipher::KeySize> = Default::default();
        let length = Cipher::KeySize::to_usize();
        match essiv_generator {
            IVGeneratorEnum::EssivSha2_256 => { hashed_key[..length].copy_from_slice(&Sha256::digest(key)); },
            IVGeneratorEnum::EssivSha2_512 => { hashed_key[..length].copy_from_slice(&Sha512::digest(key)); },
            IVGeneratorEnum::EssivSha3_256 => { hashed_key[..length].copy_from_slice(&Sha3_256::digest(key)); },
            IVGeneratorEnum::EssivSha3_512 => { hashed_key[..length].copy_from_slice(&Sha3_512::digest(key)); },
            IVGeneratorEnum::EssivBlake2b => { hashed_key[..length].copy_from_slice(&Blake2b::digest(key)); },
            IVGeneratorEnum::EssivBlake2s => { hashed_key[..length].copy_from_slice(&Blake2s::digest(key)); },
            IVGeneratorEnum::EssivGroestl => { hashed_key[..length].copy_from_slice(&Groestl256::digest(key)); },
            _ => assert!(false)
        };

        IVEssiv::<Cipher> {
            hashed_key,
            plain_gen : IVPlain::<Cipher::BlockSize>::create(),
            cipher_type: Default::default()
        }

    }
}

impl <Cipher: BlockCipher> IVGenerator<Cipher::BlockSize> for IVEssiv<Cipher> {
    fn getiv(&self, block : u64) -> GenericArray<u8, Cipher::BlockSize> {
        let mut iv = self.plain_gen.getiv(block);
        let cipher = Cipher::new(&self.hashed_key);
        cipher.encrypt_block(&mut iv);
        iv
    }
}

pub struct IVNull<IVLength : ArrayLength<u8>> {
    ivlength : PhantomData<IVLength>
}

impl <IVLength : ArrayLength<u8>> IVNull<IVLength> {
    pub fn create() -> Self {
        IVNull::<IVLength> {
            ivlength : Default::default()
        }
    }
}

impl <IVLength : ArrayLength<u8>> IVGenerator<IVLength> for IVNull<IVLength> {
    fn getiv(&self, _block: u64) -> GenericArray<u8, IVLength> {
        let mut buf : GenericArray<u8, IVLength> = Default::default();
        buf.iter_mut().for_each(|x| *x = 0);
        buf
    }
}



