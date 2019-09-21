#![crate_name="block_encrypt"]
#![crate_type="lib"]

extern crate syscall;
extern crate redoxfs;
extern crate block_modes;
extern crate aes_soft as aes;
extern crate typenum;
//extern crate openssl;
#[macro_use] extern crate generic_array;
extern crate rdrand;
extern crate rand_core;

mod ciphers;
pub mod header;
pub mod utils;

use block_modes::{BlockMode, Cbc, Ecb, Pcbc};
use block_modes::block_padding::ZeroPadding;
use aes::{Aes128, Aes192, Aes256};
use ciphers::Cipher;
use self::ciphers::RustCipher;
//use self::ciphers::OpenSSLCipher; //TODO: Figure out how to compile with openssl?
use typenum::{U16, U24, U32, Unsigned};
//use openssl::symm::Cipher as OpenSSLCipherOption;
use rdrand::RdRand;
use rand_core::RngCore;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use syscall::error::{Error, Result, EIO};
use std::vec::Vec;
use std::boxed::Box;

use redoxfs::{Disk, BLOCK_SIZE};
use header::*;
use self::ciphers::Argon2;
use self::ciphers::KeyDerivationFunction;

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
    cipher : Box<dyn Cipher>,
    offset: u64
}

impl BlockEncrypt {
    pub fn open_new_disk(path: &str, deriv_function: DerivationFunction,
                         encryption_alg: EncryptionAlgorithm, cipher_mode: CipherMode,
                         iv_generator: IVGeneratorEnum, user_key_iterations: u64,
                         master_key_iterations: u64, password: &[u8]) -> Result<BlockEncrypt> {
        println!("Open BlockEncrypt {} ", path);
        let mut generator = match RdRand::new() {
            Ok(gen) => gen,
            Err(err) => {
                eprintln!("Unable to use the underlying random number generator");
                return Err(Error::new(EIO))
            }
        };

        let mut file = try_disk!(OpenOptions::new().read(true).write(true).open(path));
        let mut salt = [0u8; 32];
        let mut master_key_salt = [0u8; 32];

        generator.fill_bytes(&mut salt);
        generator.fill_bytes(&mut master_key_salt);

        println!("1");
        let length_of_key = BlockEncrypt::get_length_of_key(&encryption_alg);
        let user_key = BlockEncrypt::derive_digest(&deriv_function, &user_key_iterations, &password, &salt, &length_of_key);
        println!("User key digest: {:?}", user_key);

        let mut master_key = [0u8; 32];
        generator.fill_bytes(&mut master_key[..length_of_key as usize]);
        println!("3");

        // Master key digest
        println!("Master key: {:?}", master_key);
        let master_key_digest_vec = BlockEncrypt::derive_digest(&deriv_function, &master_key_iterations, &master_key[..length_of_key as usize], &master_key_salt, &32);
        println!("4");

        let mut master_key_digest= [0u8; 32];
        master_key_digest[..32 as usize].copy_from_slice(&master_key_digest_vec);
        println!("5");

        // Encrypt master key
        let cipher = BlockEncrypt::get_cipher(&encryption_alg, &cipher_mode, &iv_generator, &user_key);
        let master_key_encrypted_vec = cipher.encrypt(0, &master_key);
        println!("6");

        let mut master_key_encrypted= [0u8; 32];
        println!("Mkey vec size: {}", master_key_encrypted_vec.len());
        master_key_encrypted[..32 as usize].copy_from_slice(&master_key_encrypted_vec[..32 as usize]);

        println!("7");

        let header = EncryptHeader {
            deriv_function,
            encryption_alg,
            cipher_mode,
            iv_generator,
            salt,
            user_key_iterations,
            master_key_iterations,
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
                cipher: BlockEncrypt::get_cipher(&header.encryption_alg, &header.cipher_mode, &header.iv_generator, &master_key),
                offset
            }
        )
    }

    pub fn open_used_disk(path: &str, password: &[u8]) -> Result<BlockEncrypt> {
        println!("Open BlockEncrypt {} ", path);
        let mut file = try_disk!(OpenOptions::new().read(true).write(true).open(path));

        // Read header from disk
        let mut buffer = [0u8; BLOCK_SIZE as usize];
        let count = try_disk!(file.read(&mut buffer));
        let header = EncryptHeader::deserialize(&buffer);
        let offset = 1;
        let length_of_key = BlockEncrypt::get_length_of_key(&header.encryption_alg);


        // Verify password
        // derive user key
        let user_key = BlockEncrypt::derive_digest(&header.deriv_function, &header.user_key_iterations, &password, &header.salt, &length_of_key);

        println!("User key digest: {:?}", user_key);
        // decrypt master key
        let cipher = BlockEncrypt::get_cipher(&header.encryption_alg, &header.cipher_mode, &header.iv_generator, &user_key);
        let mut master_key = header.master_key_encrypted.clone();
        cipher.decrypt(0, &mut master_key[..32 as usize]);
        println!("Master key: {:?}", master_key);

        // compare passwords
        let master_key_digest = BlockEncrypt::derive_digest(&header.deriv_function, &header.master_key_iterations, &master_key[..length_of_key as usize], &header.master_key_salt, &32);
        println!("Master key digest: {:?}", master_key_digest);
        println!("Master key digest header: {:?}", header.master_key_digest);
        match master_key_digest == header.master_key_digest {
            true => Ok(
                BlockEncrypt {
                    file,
                    cipher: BlockEncrypt::get_cipher(&header.encryption_alg, &header.cipher_mode, &header.iv_generator, &master_key),
                    offset
                }
            ),
            _ => {
                eprintln!("Entered candidate key is invalid.");
                Err(Error::new(EIO))
            }
        }


    }

    fn get_length_of_key(encryption_alg: &EncryptionAlgorithm) -> u64 {
        match encryption_alg {
            EncryptionAlgorithm::RustAes128 => 16,
            EncryptionAlgorithm::RustAes192 => 24,
            EncryptionAlgorithm::RustAes256 => 32
        }
    }

    fn derive_digest(deriv_function: &DerivationFunction, iterations: &u64, password: &[u8], salt: &[u8], length_of_key: &u64) -> Vec<u8> {
        match deriv_function {
            DerivationFunction::Argon2i | DerivationFunction::Argon2id => {
                Argon2::create(deriv_function, length_of_key, iterations).hash_password(password, salt)
            }
        }
    }

    fn get_cipher(encryption_alg: &EncryptionAlgorithm, cipher_mode: &CipherMode,
                  iv_generator: &IVGeneratorEnum, user_key: &[u8]) -> Box<dyn Cipher> {
        match encryption_alg {
            EncryptionAlgorithm::RustAes128 => {
                match cipher_mode {
                    CipherMode::CBC => {
                        Box::new(RustCipher::<Aes128, Cbc<Aes128, ZeroPadding>>::create(&user_key[..16], iv_generator)) as Box<dyn Cipher>
                    },
                    CipherMode::ECB => {
                        Box::new(RustCipher::<Aes128, Ecb<Aes128, ZeroPadding>>::create(&user_key[..16], iv_generator)) as Box<dyn Cipher>
                    },
                    CipherMode::PCBC => {
                        Box::new(RustCipher::<Aes128, Pcbc<Aes128, ZeroPadding>>::create(&user_key[..16], iv_generator)) as Box<dyn Cipher>
                    }
                }
            },
            EncryptionAlgorithm::RustAes192 => {
                match cipher_mode {
                    CipherMode::CBC => {
                        Box::new(RustCipher::<Aes192, Cbc<Aes192, ZeroPadding>>::create(&user_key[..24], iv_generator)) as Box<dyn Cipher>
                    },
                    CipherMode::ECB => {
                        Box::new(RustCipher::<Aes192, Ecb<Aes192, ZeroPadding>>::create(&user_key[..24], iv_generator)) as Box<dyn Cipher>
                    },
                    CipherMode::PCBC => {
                        Box::new(RustCipher::<Aes192, Pcbc<Aes192, ZeroPadding>>::create(&user_key[..24], iv_generator)) as Box<dyn Cipher>
                    }
                }
            },
            EncryptionAlgorithm::RustAes256 => {
                match cipher_mode {
                    CipherMode::CBC => {
                        Box::new(RustCipher::<Aes256, Cbc<Aes256, ZeroPadding>>::create(user_key, iv_generator)) as Box<dyn Cipher>
                    },
                    CipherMode::ECB => {
                        Box::new(RustCipher::<Aes256, Ecb<Aes256, ZeroPadding>>::create(user_key, iv_generator)) as Box<dyn Cipher>
                    },
                    CipherMode::PCBC => {
                        Box::new(RustCipher::<Aes256, Pcbc<Aes256, ZeroPadding>>::create(user_key, iv_generator)) as Box<dyn Cipher>
                    }
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

        println!("Read_at-count: {}", count);
        //println!("Read-at-buffer len: {}", buffer.len());
        //println!("Read-at-vec len: {}", new_buf.len());

        //buffer[..vec.len()].copy_from_slice(&vec);

        Ok(count)
    }

    fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        println!("BlockEncrypt file write at {}", block);
        try_disk!(self.file.seek(SeekFrom::Start((block + self.offset) * BLOCK_SIZE)));

        let vec = self.cipher.encrypt(block, buffer);
        //println!("Wrote encoded: {:?}", vec);
        let count = try_disk!(self.file.write(&vec));
        println!("Read encoded vec size: {}", vec.len());
        println!("Read encoded buffer size: {}", count);

        Ok(count)
    }

    fn size(&mut self) -> Result<u64> {
        let size = try_disk!(self.file.seek(SeekFrom::End(0)));
        Ok(size)
    }
}