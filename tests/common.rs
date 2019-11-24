extern crate block_encrypt;

use block_encrypt::*;
use block_encrypt::header::*;
use block_encrypt::header::EncryptionAlgorithm::*;
use block_encrypt::header::CipherMode::*;
use block_encrypt::header::IVType::*;

pub fn get_path_name(encryption_alg: &EncryptionAlgorithm,
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
    s
}