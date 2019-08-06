extern crate syscall;
extern crate redoxfs;
extern crate block_modes;
extern crate aes_soft as aes;
extern crate typenum;
//extern crate openssl;
#[macro_use] extern crate hex_literal;
#[macro_use] extern crate generic_array;

mod ciphers;

use block_modes::{BlockMode, Cbc, Ecb, Pcbc};
use block_modes::block_padding::ZeroPadding;
use aes::{Aes128, Aes192, Aes256};
use ciphers::Cipher;
use self::ciphers::RustCipher;
//use self::ciphers::OpenSSLCipher; TODO: Figure out how to compile with openssl?
use typenum::{U16, U24, U32};

//use openssl::symm::Cipher as OpenSSLCipherOption;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use syscall::error::{Error, Result, EIO};
use std::vec::Vec;
use std::boxed::Box;

use redoxfs::BLOCK_SIZE;

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
    cipher : Box<dyn Cipher> // TODO: Static dispatch somehow without it hurting too much
}

impl BlockEncrypt {
    pub fn open(path: &str, cipher : &str) -> Result<BlockEncrypt> {
        println!("Open BlockEncrypt {} ", path);
        let file = try_disk!(OpenOptions::new().read(true).write(true).open(path));
        Self::create_block_encrypt(file, cipher)
    }

    pub fn create(path: &str, size: u64, cipher : &str) -> Result<BlockEncrypt>  {
        println!("Create BlockEncrypt {}", path);
        let file = try_disk!(OpenOptions::new().read(true).write(true).create(true).open(path));
        try_disk!(file.set_len(size));
        Self::create_block_encrypt(file , cipher)
    }

    fn create_block_encrypt(file : File, cipher_str : &str) -> Result<BlockEncrypt> {
        let key16 = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let key24 = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let key32 = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
        let iv16 = arr![u8; 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff];

        // TODO: Add more ciphers from block_modes
        let cipher = match cipher_str {
            "rust-aes128cbc" =>  Box::new(RustCipher::<Aes128, Cbc<Aes128, ZeroPadding>, U16, U16>::create(key16, iv16)) as Box<dyn Cipher>,
            "rust-aes192cbc" =>  Box::new(RustCipher::<Aes192, Cbc<Aes192, ZeroPadding>, U24, U16>::create(key24, iv16)) as Box<dyn Cipher>,
            "rust-aes256cbc" =>  Box::new(RustCipher::<Aes256, Cbc<Aes256, ZeroPadding>, U32, U16>::create(key32, iv16)) as Box<dyn Cipher>,
            "rust-aes128ecb" =>  Box::new(RustCipher::<Aes128, Ecb<Aes128, ZeroPadding>, U16, U16>::create(key16, iv16)) as Box<dyn Cipher>,
            "rust-aes192ecb" =>  Box::new(RustCipher::<Aes192, Ecb<Aes192, ZeroPadding>, U24, U16>::create(key24, iv16)) as Box<dyn Cipher>,
            "rust-aes256ecb" =>  Box::new(RustCipher::<Aes256, Ecb<Aes256, ZeroPadding>, U32, U16>::create(key32, iv16)) as Box<dyn Cipher>,
            "rust-aes128pcbc" => Box::new(RustCipher::<Aes128, Pcbc<Aes128, ZeroPadding>, U16, U16>::create(key16, iv16)) as Box<dyn Cipher>,
            "rust-aes192pcbc" => Box::new(RustCipher::<Aes192, Pcbc<Aes192, ZeroPadding>, U24, U16>::create(key24, iv16)) as Box<dyn Cipher>,
            "rust-aes256pcbc" => Box::new(RustCipher::<Aes256, Pcbc<Aes256, ZeroPadding>, U32, U16>::create(key32, iv16)) as Box<dyn Cipher>,
            //"openssl-aes128ecb" => Box::new(OpenSSLCipher::<U16,U16>::create(OpenSSLCipherOption::aes_128_ecb(), key16, iv16)) as Box<dyn Cipher>,
            _ => Box::new(RustCipher::<Aes256, Cbc<Aes256, ZeroPadding>, U32, U16>::create(key32, iv16)) as Box<dyn Cipher>
        };

        Ok (
            BlockEncrypt {
                file,
                cipher
            }
        )
    }

    pub fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        println!("BlockEncrypt file read at {}", block);
        try_disk!(self.file.seek(SeekFrom::Start(block * BLOCK_SIZE)));


        let count = try_disk!(self.file.read(buffer));
        let buffer = self.cipher.decrypt(buffer);

        println!("Read_at-count: {}", count);
        //println!("Read-at-buffer len: {}", buffer.len());
        //println!("Read-at-vec len: {}", new_buf.len());

        //buffer[..vec.len()].copy_from_slice(&vec);

        Ok(count)
    }

    pub fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        println!("BlockEncrypt file write at {}", block);
        try_disk!(self.file.seek(SeekFrom::Start(block * BLOCK_SIZE)));

        let vec = self.cipher.encrypt(buffer);
        //println!("Wrote encoded: {:?}", vec);
        let count = try_disk!(self.file.write(&vec));
        println!("Read encoded vec size: {}", vec.len());
        println!("Read encoded buffer size: {}", count);

        Ok(count)
    }

    pub fn size(&mut self) -> Result<u64> {
        let size = try_disk!(self.file.seek(SeekFrom::End(0)));
        Ok(size)
    }
}