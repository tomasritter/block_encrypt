use byteorder::{ByteOrder, LittleEndian, BigEndian};
use generic_array::{GenericArray, ArrayLength};
use std::marker::PhantomData;
use digest::Digest;
use blake2::{Blake2b, Blake2s};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use groestl::{Groestl256};
use block_cipher_trait::BlockCipher;
use header::IVType;
use enum_dispatch::enum_dispatch;
use aes::{Aes128, Aes192, Aes256};
use aesni::{Aes128 as Aesni128, Aes192 as Aesni192, Aes256 as Aesni256};

#[enum_dispatch(IVGeneratorEnumType)]
pub trait IVGenerator<BlockSize : ArrayLength<u8>> {
    fn getiv(&self, block : u64) -> GenericArray<u8, BlockSize>;
}

#[enum_dispatch]
pub enum IVGeneratorEnumType<BlockSize : ArrayLength<u8>> {
    Plain(IVPlain<BlockSize>),
    PlainBe(IVPlainBe<BlockSize>),
    Null(IVNull<BlockSize>),
    EssivAes128(IVEssiv<Aes128>),
    EssivAes192(IVEssiv<Aes192>),
    EssivAes256(IVEssiv<Aes256>),
    EssivAesni128(IVEssiv<Aesni128>),
    EssivAesni192(IVEssiv<Aesni192>),
    EssivAesni256(IVEssiv<Aesni256>),
}

pub struct IVPlain<BlockSize : ArrayLength<u8>> {
    ivlength : PhantomData<BlockSize>
}

impl <BlockSize : ArrayLength<u8>> IVPlain<BlockSize> {
    pub fn create() -> Self {
        IVPlain::<BlockSize> {
            ivlength : Default::default()
        }
    }
}

impl <BlockSize : ArrayLength<u8>> IVGenerator<BlockSize> for IVPlain<BlockSize> {
    fn getiv(&self, block : u64) -> GenericArray<u8, BlockSize> {
        let mut buf : GenericArray<u8, BlockSize> = Default::default();
        if buf.len() == 8 {
            LittleEndian::write_u64(&mut buf, block);
        }
        else if buf.len() == 16 {
            LittleEndian::write_u128(&mut buf, block as u128);
        }
        else {
            unreachable!();
        }
        buf
    }
}

pub struct IVPlainBe<BlockSize : ArrayLength<u8>> {
    ivlength : PhantomData<BlockSize>
}

impl <BlockSize : ArrayLength<u8>> IVPlainBe<BlockSize> {
    pub fn create() -> Self {
        IVPlainBe::<BlockSize> {
            ivlength : Default::default()
        }
    }
}

impl <BlockSize : ArrayLength<u8>> IVGenerator<BlockSize> for IVPlainBe<BlockSize> {
    fn getiv(&self, block : u64) -> GenericArray<u8, BlockSize> {
        let mut buf : GenericArray<u8, BlockSize> = Default::default();
        if buf.len() == 8 {
            BigEndian::write_u64(&mut buf, block);
        }
        else if buf.len() == 16 {
            BigEndian::write_u128(&mut buf, block as u128);
        }
        else {
            unreachable!();
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
    pub fn create(key : &[u8], essiv_generator : &IVType) -> Self {
        let mut hashed_key : GenericArray<u8, Cipher::KeySize> = Default::default();
        let length = hashed_key.len();
        match essiv_generator {
            IVType::EssivSha2_256 => { hashed_key[..length].copy_from_slice(&Sha256::digest(key)[..length]); },
            IVType::EssivSha2_512 => { hashed_key[..length].copy_from_slice(&Sha512::digest(key)[..length]); },
            IVType::EssivSha3_256 => { hashed_key[..length].copy_from_slice(&Sha3_256::digest(key)[..length]); },
            IVType::EssivSha3_512 => { hashed_key[..length].copy_from_slice(&Sha3_512::digest(key)[..length]); },
            IVType::EssivBlake2b => { hashed_key[..length].copy_from_slice(&Blake2b::digest(key)[..length]); },
            IVType::EssivBlake2s => { hashed_key[..length].copy_from_slice(&Blake2s::digest(key)[..length]); },
            IVType::EssivGroestl => { hashed_key[..length].copy_from_slice(&Groestl256::digest(key)[..length]); },
            _ => unreachable!()
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

pub struct IVNull<BlockSize : ArrayLength<u8>> {
    ivlength : PhantomData<BlockSize>
}

impl <BlockSize : ArrayLength<u8>> IVNull<BlockSize> {
    pub fn create() -> Self {
        IVNull::<BlockSize> {
            ivlength : Default::default()
        }
    }
}

impl <BlockSize : ArrayLength<u8>> IVGenerator<BlockSize> for IVNull<BlockSize> {
    fn getiv(&self, _block: u64) -> GenericArray<u8, BlockSize> {
        let mut buf : GenericArray<u8, BlockSize> = Default::default();
        buf.iter_mut().for_each(|x| *x = 0);
        buf
    }
}



