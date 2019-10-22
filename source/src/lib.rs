#![crate_name="block_encrypt"]
#![crate_type="lib"]

extern crate syscall;
extern crate redoxfs;
extern crate block_modes;
extern crate aes_soft as aes;
extern crate typenum;
extern crate generic_array;
extern crate rdrand;
extern crate rand_core;
extern crate argon2;
extern crate enum_dispatch;
extern crate block_cipher_trait;
extern crate byteorder;
extern crate digest;
extern crate blake2;
extern crate sha2;
extern crate sha3;
extern crate groestl;

mod ciphers;
pub mod header;

use ciphers::{*};
use rdrand::RdRand;
use rand_core::RngCore;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use syscall::error::{Error, Result, EIO};
use std::vec::Vec;

use self::argon2::Config as ArgonConfig;
use self::argon2::Variant as ArgonVariant;

use redoxfs::{Disk, BLOCK_SIZE};
use header::*;

macro_rules! try_disk {
    ($expr:expr) => (match $expr {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Disk I/O Error: {}", err);
            return Err(Error::new(EIO));
        }
    })
}

pub struct BlockEncrypt {
    file: File,
    cipher : CipherEnum, // TODO: static dispatch
    offset: u64
}

impl BlockEncrypt {
    pub fn open_new_disk(path: &str,
                         encryption_alg: EncryptionAlgorithm,
                         cipher_mode: CipherMode,
                         iv_generator: IVGeneratorEnum,
                         password: &[u8])
        -> Result<BlockEncrypt> {
        println!("Creating encrypted filesystem {} ", path);
        let mut generator = match RdRand::new() {
            Ok(gen) => gen,
            Err(_) => {
                eprintln!("Unable to use the underlying random number generator");
                return Err(Error::new(EIO))
            }
        };

        let mut file = try_disk!(OpenOptions::new().read(true).write(true).open(path));
        let mut user_key_salt = [0u8; 32];
        let mut master_key_salt = [0u8; 32];

        generator.fill_bytes(&mut user_key_salt);
        generator.fill_bytes(&mut master_key_salt);

        let key_length = BlockEncrypt::get_length_of_key(&encryption_alg, &cipher_mode);
        let user_key = BlockEncrypt::derive_digest(&password, &user_key_salt, &key_length);

        let mut master_key = [0u8; 64];
        generator.fill_bytes(&mut master_key[..key_length]);

        // Master key digest
        let master_key_digest_vec = BlockEncrypt::derive_digest(&master_key[..key_length], &master_key_salt, &key_length);

        let mut master_key_digest= [0u8; 64];
        master_key_digest[..key_length].copy_from_slice(&master_key_digest_vec);

        // Encrypt master key
        let cipher = BlockEncrypt::get_cipher(&encryption_alg, &cipher_mode, &iv_generator, &user_key);
        let master_key_encrypted_vec = cipher.encrypt(0, &master_key[..key_length]);

        let mut master_key_encrypted= [0u8; 64];
        master_key_encrypted[..key_length].copy_from_slice(&master_key_encrypted_vec[..key_length]);

        let header = EncryptHeader {
            encryption_alg,
            cipher_mode,
            iv_generator,
            user_key_salt,
            master_key_encrypted,
            master_key_digest,
            master_key_salt
        };
        let serialized_header = EncryptHeader::serialize(&header);
        try_disk!(file.write(&serialized_header));

        let offset = 1; // Size of struct in BLOCK_SIZE size

        // create instance of block encrypt
        Ok(
            BlockEncrypt {
                file,
                cipher: BlockEncrypt::get_cipher(&header.encryption_alg, &header.cipher_mode, &header.iv_generator, &master_key[..key_length]),
                offset
            }
        )
    }

    pub fn open_used_disk(path: &str, password: &[u8]) -> Result<BlockEncrypt> {
        let mut file = try_disk!(OpenOptions::new().read(true).write(true).open(path));
        // Read header from disk
        let mut buffer = [0u8; BLOCK_SIZE as usize];
        try_disk!(file.read(&mut buffer));
        let header = EncryptHeader::deserialize(&buffer);
        let offset = 1;
        let key_length = BlockEncrypt::get_length_of_key(&header.encryption_alg, &header.cipher_mode);


        // Verify password
        // derive user key
        let user_key = BlockEncrypt::derive_digest(&password, &header.user_key_salt, &key_length);

        // decrypt master key
        let cipher = BlockEncrypt::get_cipher(&header.encryption_alg, &header.cipher_mode, &header.iv_generator, &user_key);
        let mut master_key = header.master_key_encrypted.clone();
        cipher.decrypt(0, &mut master_key[..key_length]);

        // compare passwords
        let master_key_digest = BlockEncrypt::derive_digest(&master_key[..key_length], &header.master_key_salt, &key_length);
        match master_key_digest == header.master_key_digest[..key_length].to_vec() {
            true => Ok(
                BlockEncrypt {
                    file,
                    cipher: BlockEncrypt::get_cipher(&header.encryption_alg, &header.cipher_mode, &header.iv_generator, &master_key[..key_length]),
                    offset
                }
            ),
            _ => {
                eprintln!("Entered candidate key is invalid.");
                Err(Error::new(EIO))
            }
        }


    }

    fn get_length_of_key(encryption_alg: &EncryptionAlgorithm, cipher_mode: &CipherMode) -> usize {
        let length = match encryption_alg {
            EncryptionAlgorithm::Aes128 => 16,
            EncryptionAlgorithm::Aes192 => 24,
            EncryptionAlgorithm::Aes256 => 32
        };

        match cipher_mode {
            CipherMode::XTS => 2 * length,
            _ =>  length
        }
    }

    fn derive_digest(password: &[u8], salt: &[u8], hash_length: &usize) -> Vec<u8> {
        let mut config = ArgonConfig::default();
        config.variant = ArgonVariant::Argon2i;
        config.hash_length = *hash_length as u32;

        argon2::hash_raw(password, salt, &config).unwrap()
    }

    fn get_cipher(encryption_alg: &EncryptionAlgorithm, cipher_mode: &CipherMode,
                  iv_generator: &IVGeneratorEnum, master_key: &[u8]) -> CipherEnum {

        match encryption_alg {
            EncryptionAlgorithm::Aes128 => {
                match cipher_mode {
                    CipherMode::CBC => Aes128Cbc::create(master_key, iv_generator).into(),
                    CipherMode::ECB => Aes128Ecb::create(master_key, iv_generator).into(),
                    CipherMode::PCBC => Aes128Pcbc::create(master_key, iv_generator).into(),
                    CipherMode::XTS => Aes128Xts::create(master_key, iv_generator).into()
                }
            },
            EncryptionAlgorithm::Aes192 => {
                match cipher_mode {
                    CipherMode::CBC => Aes192Cbc::create(master_key, iv_generator).into(),
                    CipherMode::ECB => Aes192Ecb::create(master_key, iv_generator).into(),
                    CipherMode::PCBC => Aes192Pcbc::create(master_key, iv_generator).into(),
                    CipherMode::XTS => Aes192Xts::create(master_key, iv_generator).into(),
                }
            },
            EncryptionAlgorithm::Aes256 => {
                match cipher_mode {
                    CipherMode::CBC => Aes256Cbc::create(master_key, iv_generator).into(),
                    CipherMode::ECB => Aes256Ecb::create(master_key, iv_generator).into(),
                    CipherMode::PCBC => Aes256Pcbc::create(master_key, iv_generator).into(),
                    CipherMode::XTS => Aes256Xts::create(master_key, iv_generator).into()
                }
            }
        }
    }
}

impl Disk for BlockEncrypt {
    fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        println!("BlockEncrypt file read at {}", block);
        try_disk!(self.file.seek(SeekFrom::Start((block + self.offset) * BLOCK_SIZE)));

        let count = try_disk!(self.file.read(buffer));
        self.cipher.decrypt(block, buffer);

        Ok(count)
    }

    fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        println!("BlockEncrypt file write at {}", block);
        try_disk!(self.file.seek(SeekFrom::Start((block + self.offset) * BLOCK_SIZE)));

        let vec = self.cipher.encrypt(block, buffer);
        let count = try_disk!(self.file.write(&vec));

        Ok(count)
    }

    fn size(&mut self) -> Result<u64> {
        let size = try_disk!(self.file.seek(SeekFrom::End(0)));
        Ok(size)
    }
}