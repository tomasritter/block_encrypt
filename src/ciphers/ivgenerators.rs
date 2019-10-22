use byteorder::{ByteOrder, LittleEndian, BigEndian};
use generic_array::{GenericArray};
use std::marker::PhantomData;
use digest::Digest;
use blake2::{Blake2b, Blake2s};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use groestl::{Groestl256};
use block_cipher_trait::BlockCipher;
use typenum::{Unsigned};
use header::IVGeneratorEnum;
use enum_dispatch::enum_dispatch;

#[enum_dispatch(IVGeneratorEnumType)]
pub trait IVGenerator<Cipher : BlockCipher> {
    fn getiv(&self, block : u64) -> GenericArray<u8, Cipher::BlockSize>;
}

#[enum_dispatch]
pub enum IVGeneratorEnumType<Cipher : BlockCipher> {
    Plain(IVPlain<Cipher>),
    PlainBe(IVPlainBe<Cipher>),
    Null(IVNull<Cipher>),
    Essiv(IVEssiv<Cipher>),
}

pub struct IVPlain<Cipher : BlockCipher> {
    ivlength : PhantomData<Cipher>
}

impl <Cipher : BlockCipher> IVPlain<Cipher> {
    pub fn create() -> Self {
        IVPlain::<Cipher> {
            ivlength : Default::default()
        }
    }
}

impl <Cipher : BlockCipher> IVGenerator<Cipher> for IVPlain<Cipher> {
    fn getiv(&self, block : u64) -> GenericArray<u8, Cipher::BlockSize> {
        let mut buf : GenericArray<u8, Cipher::BlockSize> = Default::default();
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

pub struct IVPlainBe<Cipher : BlockCipher> {
    ivlength : PhantomData<Cipher>
}

impl <Cipher : BlockCipher> IVPlainBe<Cipher> {
    pub fn create() -> Self {
        IVPlainBe::<Cipher> {
            ivlength : Default::default()
        }
    }
}

impl <Cipher : BlockCipher> IVGenerator<Cipher> for IVPlainBe<Cipher> {
    fn getiv(&self, block : u64) -> GenericArray<u8, Cipher::BlockSize> {
        let mut buf : GenericArray<u8, Cipher::BlockSize> = Default::default();
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
    plain_gen: IVPlain<Cipher>,
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
            plain_gen : IVPlain::<Cipher>::create(),
            cipher_type: Default::default()
        }

    }
}

impl <Cipher: BlockCipher> IVGenerator<Cipher> for IVEssiv<Cipher> {
    fn getiv(&self, block : u64) -> GenericArray<u8, Cipher::BlockSize> {
        let mut iv = self.plain_gen.getiv(block);
        let cipher = Cipher::new(&self.hashed_key);
        cipher.encrypt_block(&mut iv);
        iv
    }
}

pub struct IVNull<Cipher : BlockCipher> {
    ivlength : PhantomData<Cipher>
}

impl <Cipher : BlockCipher> IVNull<Cipher> {
    pub fn create() -> Self {
        IVNull::<Cipher> {
            ivlength : Default::default()
        }
    }
}

impl <Cipher : BlockCipher> IVGenerator<Cipher> for IVNull<Cipher> {
    fn getiv(&self, _block: u64) -> GenericArray<u8, Cipher::BlockSize> {
        let mut buf : GenericArray<u8, Cipher::BlockSize> = Default::default();
        buf.iter_mut().for_each(|x| *x = 0);
        buf
    }
}



