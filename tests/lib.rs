extern crate block_encrypt;
extern crate rand;
extern crate redoxfs;

use block_encrypt::*;
use block_encrypt::header::*;
use block_encrypt::header::EncryptionAlgorithm::*;
use block_encrypt::header::CipherMode::*;
use block_encrypt::header::IVType::*;
use rand::{RngCore, Rng};
use std::fs::File;
use std::io::prelude::*;
use redoxfs::Disk;

fn get_path_name(encryption_alg: &EncryptionAlgorithm,
                  cipher_mode: &CipherMode,
                  iv_generator: &IVType) -> String {
    let mut s = String::new();
    s.push_str(match encryption_alg {
        Aes128 => "Aes128_",
        Aes192 => "Aes192_",
        Aes256 => "Aes256_",
    });

    s.push_str(match cipher_mode{
        ECB => "ECB_",
        CBC => "CBC_",
        PCBC => "PCBC_",
        XTS => "XTS_"
    });

    s.push_str(match iv_generator {
        Plain => "Plain",
        PlainBE => "PlainBe",
        Null => "Null",
        EssivSha2_256 => "Sha2_256",
        EssivSha2_512 => "Sha2_512",
        EssivSha3_256 => "Sha3_256",
        EssivSha3_512 => "Sha3_512",
        EssivBlake2b => "Blake2b",
        EssivBlake2s => "Blake2s",
        EssivGroestl => "Groestl"
    });
    s.push_str(".txt");
    s
}

fn create_mount_read_write(encryption_alg: EncryptionAlgorithm,
                        cipher_mode: CipherMode,
                        iv_generator: IVType) {
    let path = get_path_name(&encryption_alg, &cipher_mode, &iv_generator);
    let mut file = match File::create(&path) {
        Ok(arg) => arg,
        Err(_) => {
            println!("Could not create file");
            panic!();
        }
    };
    match file.set_len(1024*1024*1024)  { // ~262144 blocks
        Ok(_) => (),
        Err(_) => {
            println!("Could not set file size");
            panic!();
        }
    };
    let mut rng = rand::thread_rng();
    let mut password = [0u8; 256];
    rng.fill_bytes(&mut password);

    match BlockEncrypt::open_new_disk(&path, encryption_alg, cipher_mode, iv_generator, &password) {
        Ok(_) => (),
        Err(_) => {
            println!("Could not create block encrypt");
            panic!();
        }
    };

    let mut block_enc = match BlockEncrypt::open_used_disk(&path, &password) {
        Ok(arg) => arg,
        Err(_) => {
            println!("Could not mount block encrypt");
            panic!();
        }
    };

    for i in 1..1000 {
        let sector_id: u64 = rng.gen_range(0, 262140);
        let mut buffer_in = [0u8; 4096];
        rng.fill_bytes(&mut buffer_in);
        block_enc.write_at(sector_id, &buffer_in);
        let mut buffer_out = [0u8; 4096];
        block_enc.read_at(sector_id, &mut buffer_out);
        assert_eq!(buffer_in[..4096], buffer_out[..4096]);
    }

    std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_ecb_plain() {create_mount_read_write(Aes128, ECB, Plain); }
    #[test]
    fn aes128_ecb_plainbe() {create_mount_read_write(Aes128, ECB, PlainBE); }
    #[test]
    fn aes128_ecb_null() {create_mount_read_write(Aes128, ECB, Null); }
    #[test]
    fn aes128_ecb_essiv_sha2_256() {create_mount_read_write(Aes128, ECB, EssivSha2_256); }
    #[test]
    fn aes128_ecb_essiv_sha2_512() {create_mount_read_write(Aes128, ECB, EssivSha2_512); }
    #[test]
    fn aes128_ecb_essiv_sha3_256() {create_mount_read_write(Aes128, ECB, EssivSha3_256); }
    #[test]
    fn aes128_ecb_essiv_sha3_512() {create_mount_read_write(Aes128, ECB, EssivSha3_512); }
    #[test]
    fn aes128_ecb_essiv_blake2b() {create_mount_read_write(Aes128, ECB, EssivBlake2b); }
    #[test]
    fn aes128_ecb_essiv_blake2s() {create_mount_read_write(Aes128, ECB, EssivBlake2s); }
    #[test]
    fn aes128_ecb_essiv_groestl() {create_mount_read_write(Aes128, ECB, EssivGroestl); }

    #[test]
    fn aes128_cbc_plain() {create_mount_read_write(Aes128, CBC, Plain); }
    #[test]
    fn aes128_cbc_plainbe() {create_mount_read_write(Aes128, CBC, PlainBE); }
    #[test]
    fn aes128_cbc_null() {create_mount_read_write(Aes128, CBC, Null); }
    #[test]
    fn aes128_cbc_essiv_sha2_256() {create_mount_read_write(Aes128, CBC, EssivSha2_256); }
    #[test]
    fn aes128_cbc_essiv_sha2_512() {create_mount_read_write(Aes128, CBC, EssivSha2_512); }
    #[test]
    fn aes128_cbc_essiv_sha3_256() {create_mount_read_write(Aes128, CBC, EssivSha3_256); }
    #[test]
    fn aes128_cbc_essiv_sha3_512() {create_mount_read_write(Aes128, CBC, EssivSha3_512); }
    #[test]
    fn aes128_cbc_essiv_blake2b() {create_mount_read_write(Aes128, CBC, EssivBlake2b); }
    #[test]
    fn aes128_cbc_essiv_blake2s() {create_mount_read_write(Aes128, CBC, EssivBlake2s); }
    #[test]
    fn aes128_cbc_essiv_groestl() {create_mount_read_write(Aes128, CBC, EssivGroestl); }

    #[test]
    fn aes128_pcbc_plain() {create_mount_read_write(Aes128, PCBC, Plain); }
    #[test]
    fn aes128_pcbc_plainbe() {create_mount_read_write(Aes128, PCBC, PlainBE); }
    #[test]
    fn aes128_pcbc_null() {create_mount_read_write(Aes128, PCBC, Null); }
    #[test]
    fn aes128_pcbc_essiv_sha2_256() {create_mount_read_write(Aes128, PCBC, EssivSha2_256); }
    #[test]
    fn aes128_pcbc_essiv_sha2_512() {create_mount_read_write(Aes128, PCBC, EssivSha2_512); }
    #[test]
    fn aes128_pcbc_essiv_sha3_256() {create_mount_read_write(Aes128, PCBC, EssivSha3_256); }
    #[test]
    fn aes128_pcbc_essiv_sha3_512() {create_mount_read_write(Aes128, PCBC, EssivSha3_512); }
    #[test]
    fn aes128_pcbc_essiv_blake2b() {create_mount_read_write(Aes128, PCBC, EssivBlake2b); }
    #[test]
    fn aes128_pcbc_essiv_blake2s() {create_mount_read_write(Aes128, PCBC, EssivBlake2s); }
    #[test]
    fn aes128_pcbc_essiv_groestl() {create_mount_read_write(Aes128, PCBC, EssivGroestl); }

    #[test]
    fn aes128_xts_plain() {create_mount_read_write(Aes128, XTS, Plain); }
    #[test]
    fn aes128_xts_plainbe() {create_mount_read_write(Aes128, XTS, PlainBE); }
    #[test]
    fn aes128_xts_null() {create_mount_read_write(Aes128, XTS, Null); }
    #[test]
    fn aes128_xts_essiv_sha2_256() {create_mount_read_write(Aes128, XTS, EssivSha2_256); }
    #[test]
    fn aes128_xts_essiv_sha2_512() {create_mount_read_write(Aes128, XTS, EssivSha2_512); }
    #[test]
    fn aes128_xts_essiv_sha3_256() {create_mount_read_write(Aes128, XTS, EssivSha3_256); }
    #[test]
    fn aes128_xts_essiv_sha3_512() {create_mount_read_write(Aes128, XTS, EssivSha3_512); }
    #[test]
    fn aes128_xts_essiv_blake2b() {create_mount_read_write(Aes128, XTS, EssivBlake2b); }
    #[test]
    fn aes128_xts_essiv_blake2s() {create_mount_read_write(Aes128, XTS, EssivBlake2s); }
    #[test]
    fn aes128_xts_essiv_groestl() {create_mount_read_write(Aes128, XTS, EssivGroestl); }
    // ----------------------------------------------------------------------------------------------------------------------
    #[test]
    fn aes192_ecb_plain() {create_mount_read_write(Aes192, ECB, Plain); }
    #[test]
    fn aes192_ecb_plainbe() {create_mount_read_write(Aes192, ECB, PlainBE); }
    #[test]
    fn aes192_ecb_null() {create_mount_read_write(Aes192, ECB, Null); }
    #[test]
    fn aes192_ecb_essiv_sha2_256() {create_mount_read_write(Aes192, ECB, EssivSha2_256); }
    #[test]
    fn aes192_ecb_essiv_sha2_512() {create_mount_read_write(Aes192, ECB, EssivSha2_512); }
    #[test]
    fn aes192_ecb_essiv_sha3_256() {create_mount_read_write(Aes192, ECB, EssivSha3_256); }
    #[test]
    fn aes192_ecb_essiv_sha3_512() {create_mount_read_write(Aes192, ECB, EssivSha3_512); }
    #[test]
    fn aes192_ecb_essiv_blake2b() {create_mount_read_write(Aes192, ECB, EssivBlake2b); }
    #[test]
    fn aes192_ecb_essiv_blake2s() {create_mount_read_write(Aes192, ECB, EssivBlake2s); }
    #[test]
    fn aes192_ecb_essiv_groestl() {create_mount_read_write(Aes192, ECB, EssivGroestl); }

    #[test]
    fn aes192_cbc_plain() {create_mount_read_write(Aes192, CBC, Plain); }
    #[test]
    fn aes192_cbc_plainbe() {create_mount_read_write(Aes192, CBC, PlainBE); }
    #[test]
    fn aes192_cbc_null() {create_mount_read_write(Aes192, CBC, Null); }
    #[test]
    fn aes192_cbc_essiv_sha2_256() {create_mount_read_write(Aes192, CBC, EssivSha2_256); }
    #[test]
    fn aes192_cbc_essiv_sha2_512() {create_mount_read_write(Aes192, CBC, EssivSha2_512); }
    #[test]
    fn aes192_cbc_essiv_sha3_256() {create_mount_read_write(Aes192, CBC, EssivSha3_256); }
    #[test]
    fn aes192_cbc_essiv_sha3_512() {create_mount_read_write(Aes192, CBC, EssivSha3_512); }
    #[test]
    fn aes192_cbc_essiv_blake2b() {create_mount_read_write(Aes192, CBC, EssivBlake2b); }
    #[test]
    fn aes192_cbc_essiv_blake2s() {create_mount_read_write(Aes192, CBC, EssivBlake2s); }
    #[test]
    fn aes192_cbc_essiv_groestl() {create_mount_read_write(Aes192, CBC, EssivGroestl); }

    #[test]
    fn aes192_pcbc_plain() {create_mount_read_write(Aes192, PCBC, Plain); }
    #[test]
    fn aes192_pcbc_plainbe() {create_mount_read_write(Aes192, PCBC, PlainBE); }
    #[test]
    fn aes192_pcbc_null() {create_mount_read_write(Aes192, PCBC, Null); }
    #[test]
    fn aes192_pcbc_essiv_sha2_256() {create_mount_read_write(Aes192, PCBC, EssivSha2_256); }
    #[test]
    fn aes192_pcbc_essiv_sha2_512() {create_mount_read_write(Aes192, PCBC, EssivSha2_512); }
    #[test]
    fn aes192_pcbc_essiv_sha3_256() {create_mount_read_write(Aes192, PCBC, EssivSha3_256); }
    #[test]
    fn aes192_pcbc_essiv_sha3_512() {create_mount_read_write(Aes192, PCBC, EssivSha3_512); }
    #[test]
    fn aes192_pcbc_essiv_blake2b() {create_mount_read_write(Aes192, PCBC, EssivBlake2b); }
    #[test]
    fn aes192_pcbc_essiv_blake2s() {create_mount_read_write(Aes192, PCBC, EssivBlake2s); }
    #[test]
    fn aes192_pcbc_essiv_groestl() {create_mount_read_write(Aes192, PCBC, EssivGroestl); }

    #[test]
    fn aes192_xts_plain() {create_mount_read_write(Aes192, XTS, Plain); }
    #[test]
    fn aes192_xts_plainbe() {create_mount_read_write(Aes192, XTS, PlainBE); }
    #[test]
    fn aes192_xts_null() {create_mount_read_write(Aes192, XTS, Null); }
    #[test]
    fn aes192_xts_essiv_sha2_256() {create_mount_read_write(Aes192, XTS, EssivSha2_256); }
    #[test]
    fn aes192_xts_essiv_sha2_512() {create_mount_read_write(Aes192, XTS, EssivSha2_512); }
    #[test]
    fn aes192_xts_essiv_sha3_256() {create_mount_read_write(Aes192, XTS, EssivSha3_256); }
    #[test]
    fn aes192_xts_essiv_sha3_512() {create_mount_read_write(Aes192, XTS, EssivSha3_512); }
    #[test]
    fn aes192_xts_essiv_blake2b() {create_mount_read_write(Aes192, XTS, EssivBlake2b); }
    #[test]
    fn aes192_xts_essiv_blake2s() {create_mount_read_write(Aes192, XTS, EssivBlake2s); }
    #[test]
    fn aes192_xts_essiv_groestl() {create_mount_read_write(Aes192, XTS, EssivGroestl); }
    // -----------------------------------------------------------------------------------------------------------------
    #[test]
    fn aes256_ecb_plain() {create_mount_read_write(Aes256, ECB, Plain); }
    #[test]
    fn aes256_ecb_plainbe() {create_mount_read_write(Aes256, ECB, PlainBE); }
    #[test]
    fn aes256_ecb_null() {create_mount_read_write(Aes256, ECB, Null); }
    #[test]
    fn aes256_ecb_essiv_sha2_256() {create_mount_read_write(Aes256, ECB, EssivSha2_256); }
    #[test]
    fn aes256_ecb_essiv_sha2_512() {create_mount_read_write(Aes256, ECB, EssivSha2_512); }
    #[test]
    fn aes256_ecb_essiv_sha3_256() {create_mount_read_write(Aes256, ECB, EssivSha3_256); }
    #[test]
    fn aes256_ecb_essiv_sha3_512() {create_mount_read_write(Aes256, ECB, EssivSha3_512); }
    #[test]
    fn aes256_ecb_essiv_blake2b() {create_mount_read_write(Aes256, ECB, EssivBlake2b); }
    #[test]
    fn aes256_ecb_essiv_blake2s() {create_mount_read_write(Aes256, ECB, EssivBlake2s); }
    #[test]
    fn aes256_ecb_essiv_groestl() {create_mount_read_write(Aes256, ECB, EssivGroestl); }

    #[test]
    fn aes256_cbc_plain() {create_mount_read_write(Aes256, CBC, Plain); }
    #[test]
    fn aes256_cbc_plainbe() {create_mount_read_write(Aes256, CBC, PlainBE); }
    #[test]
    fn aes256_cbc_null() {create_mount_read_write(Aes256, CBC, Null); }
    #[test]
    fn aes256_cbc_essiv_sha2_256() {create_mount_read_write(Aes256, CBC, EssivSha2_256); }
    #[test]
    fn aes256_cbc_essiv_sha2_512() {create_mount_read_write(Aes256, CBC, EssivSha2_512); }
    #[test]
    fn aes256_cbc_essiv_sha3_256() {create_mount_read_write(Aes256, CBC, EssivSha3_256); }
    #[test]
    fn aes256_cbc_essiv_sha3_512() {create_mount_read_write(Aes256, CBC, EssivSha3_512); }
    #[test]
    fn aes256_cbc_essiv_blake2b() {create_mount_read_write(Aes256, CBC, EssivBlake2b); }
    #[test]
    fn aes256_cbc_essiv_blake2s() {create_mount_read_write(Aes256, CBC, EssivBlake2s); }
    #[test]
    fn aes256_cbc_essiv_groestl() {create_mount_read_write(Aes256, CBC, EssivGroestl); }

    #[test]
    fn aes256_pcbc_plain() {create_mount_read_write(Aes256, PCBC, Plain); }
    #[test]
    fn aes256_pcbc_plainbe() {create_mount_read_write(Aes256, PCBC, PlainBE); }
    #[test]
    fn aes256_pcbc_null() {create_mount_read_write(Aes256, PCBC, Null); }
    #[test]
    fn aes256_pcbc_essiv_sha2_256() {create_mount_read_write(Aes256, PCBC, EssivSha2_256); }
    #[test]
    fn aes256_pcbc_essiv_sha2_512() {create_mount_read_write(Aes256, PCBC, EssivSha2_512); }
    #[test]
    fn aes256_pcbc_essiv_sha3_256() {create_mount_read_write(Aes256, PCBC, EssivSha3_256); }
    #[test]
    fn aes256_pcbc_essiv_sha3_512() {create_mount_read_write(Aes256, PCBC, EssivSha3_512); }
    #[test]
    fn aes256_pcbc_essiv_blake2b() {create_mount_read_write(Aes256, PCBC, EssivBlake2b); }
    #[test]
    fn aes256_pcbc_essiv_blake2s() {create_mount_read_write(Aes256, PCBC, EssivBlake2s); }
    #[test]
    fn aes256_pcbc_essiv_groestl() {create_mount_read_write(Aes256, PCBC, EssivGroestl); }

    #[test]
    fn aes256_xts_plain() {create_mount_read_write(Aes256, XTS, Plain); }
    #[test]
    fn aes256_xts_plainbe() {create_mount_read_write(Aes256, XTS, PlainBE); }
    #[test]
    fn aes256_xts_null() {create_mount_read_write(Aes256, XTS, Null); }
    #[test]
    fn aes256_xts_essiv_sha2_256() {create_mount_read_write(Aes256, XTS, EssivSha2_256); }
    #[test]
    fn aes256_xts_essiv_sha2_512() {create_mount_read_write(Aes256, XTS, EssivSha2_512); }
    #[test]
    fn aes256_xts_essiv_sha3_256() {create_mount_read_write(Aes256, XTS, EssivSha3_256); }
    #[test]
    fn aes256_xts_essiv_sha3_512() {create_mount_read_write(Aes256, XTS, EssivSha3_512); }
    #[test]
    fn aes256_xts_essiv_blake2b() {create_mount_read_write(Aes256, XTS, EssivBlake2b); }
    #[test]
    fn aes256_xts_essiv_blake2s() {create_mount_read_write(Aes256, XTS, EssivBlake2s); }
    #[test]
    fn aes256_xts_essiv_groestl() {create_mount_read_write(Aes256, XTS, EssivGroestl); }
}