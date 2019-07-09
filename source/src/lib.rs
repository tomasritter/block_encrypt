extern crate syscall;
extern crate redoxfs;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use syscall::error::{Error, Result, EIO};

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
    pub file: File
}

impl BlockEncrypt {
    pub fn open(path: &str) -> Result<BlockEncrypt> {
        println!("Open BlockEncrypt {} ", path);
        let file = try_disk!(OpenOptions::new().read(true).write(true).open(path));
        Ok(BlockEncrypt {
            file
        })
    }

    pub fn create(path: &str, size: u64) -> Result<BlockEncrypt> {
        println!("Create BlockEncrypt {}", path);
        let file = try_disk!(OpenOptions::new().read(true).write(true).create(true).open(path));
        try_disk!(file.set_len(size));
        Ok(BlockEncrypt {
            file
        })
    }

    pub fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        println!("BlockEncrypt file read at {}", block);
        try_disk!(self.file.seek(SeekFrom::Start(block * BLOCK_SIZE)));
        let count = try_disk!(self.file.read(buffer));
        Ok(count)
    }

    pub fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        println!("BlockEncrypt file write at {}", block);
        try_disk!(self.file.seek(SeekFrom::Start(block * BLOCK_SIZE)));
        let count = try_disk!(self.file.write(buffer));
        Ok(count)
    }

    pub fn size(&mut self) -> Result<u64> {
        let size = try_disk!(self.file.seek(SeekFrom::End(0)));
        Ok(size)
    }
}