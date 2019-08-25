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
use typenum::U1;
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
            ivlength : PhantomData
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
            ivlength : PhantomData
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

pub struct IVEssiv<Cipher, KeyLength: ArrayLength<u8>, IVLength : ArrayLength<u8>>
    where
        Cipher: BlockCipher<KeySize = KeyLength, BlockSize = IVLength>,
        <Cipher as BlockCipher>::ParBlocks: ArrayLength<GenericArray<u8, IVLength>>
{
    hashed_key: GenericArray<u8, KeyLength>,
    plain_gen: IVPlain<IVLength>,
    cipher_type: PhantomData<Cipher>
}

impl <Cipher, KeyLength: ArrayLength<u8>, IVLength : ArrayLength<u8>> IVEssiv<Cipher, KeyLength, IVLength>
    where
        Cipher: BlockCipher<KeySize = KeyLength, BlockSize = IVLength>,
        <Cipher as BlockCipher>::ParBlocks: ArrayLength<GenericArray<u8, IVLength>>
{
    pub fn create(key : &GenericArray<u8, KeyLength>, essiv_generator : &IVGeneratorEnum) -> Self {
        let mut hashed_key : GenericArray<u8, KeyLength> = Default::default();
        let length = KeyLength::to_usize();
        match essiv_generator {
            IVGeneratorEnum::EssivSha2_256 => { hashed_key[..length].copy_from_slice(&Sha256::digest(key)); },
            IVGeneratorEnum::EssivSha2_512 => { hashed_key[..length].copy_from_slice(&Sha512::digest(key)); },
            IVGeneratorEnum::EssivSha3_256 => { hashed_key[..length].copy_from_slice(&Sha3_256::digest(key)); },
            IVGeneratorEnum::EssivSha3_512 => { hashed_key[..length].copy_from_slice(&Sha3_512::digest(key)); },
            // TODO: Try to do it without cutting off the end for Blake and Groestl since they should be variable length hashes
            IVGeneratorEnum::EssivBlake2b => { hashed_key[..length].copy_from_slice(&Blake2b::digest(key)); },
            IVGeneratorEnum::EssivBlake2s => { hashed_key[..length].copy_from_slice(&Blake2s::digest(key)); },
            IVGeneratorEnum::EssivGroestl => { hashed_key[..length].copy_from_slice(&Groestl256::digest(key)); },
            _ => assert!(false)
        };

        IVEssiv::<Cipher, KeyLength, IVLength> {
            hashed_key,
            plain_gen : IVPlain::<IVLength>::create(),
            cipher_type: PhantomData
        }

    }
}

impl <Cipher, KeyLength: ArrayLength<u8>, IVLength : ArrayLength<u8>> IVGenerator<IVLength> for IVEssiv<Cipher, KeyLength, IVLength>
    where
        Cipher: BlockCipher<KeySize = KeyLength, BlockSize = IVLength>,
        <Cipher as BlockCipher>::ParBlocks: ArrayLength<GenericArray<u8, IVLength>>
{
    fn getiv(&self, block : u64) -> GenericArray<u8, IVLength> {
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
            ivlength : PhantomData
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



