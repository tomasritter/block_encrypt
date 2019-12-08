extern crate redoxfs;
extern crate uuid;
extern crate block_encrypt;
extern crate termion;

use std::{env, process, time};
use std::io::{Write, stdout, stdin};

use termion::input::TermRead;
use redoxfs::FileSystem;
use uuid::Uuid;
use block_encrypt::BlockEncrypt;
use block_encrypt::header::*;

fn parse_encryption_algorithm(s: &str) -> EncryptionAlgorithm {
    match s {
        "aes128" => EncryptionAlgorithm::Aes128,
        "aes192" => EncryptionAlgorithm::Aes192,
        "aes256" => EncryptionAlgorithm::Aes256,
        _ => {
            println!("block_encrypt-mkfs: failed to read encryption algorithm type");
            usage();
            process::exit(1);
        }
    }
}

fn parse_cipher_mode(s: &str) -> CipherMode {
    match s {
        "cbc" => CipherMode::CBC,
        "ecb" => CipherMode::ECB,
        "pcbc" => CipherMode::PCBC,
        "xts" => CipherMode::XTS,
        _ => {
            println!("block_encrypt-mkfs: failed to read cipher mode type");
            usage();
            process::exit(1);
        }
    }
}

fn parse_ivgenerator(s: &str) -> IVType {
    if s.starts_with("essiv") {
        let mut split = s.splitn(2, ':');
        if split.next().unwrap() != "essiv" {
            println!("block_encrypt-mkfs: failed to read iv generator type");
            process::exit(1);
        } else {
            match split.next() {
                Some(arg) => {
                    match arg {
                        "sha2-256" => IVType::EssivSha2_256,
                        "sha2-512" => IVType::EssivSha2_512,
                        "sha3-256" => IVType::EssivSha3_256,
                        "sha3-512" => IVType::EssivSha3_512,
                        "blake2b" => IVType::EssivBlake2b,
                        "blake2s" => IVType::EssivBlake2s,
                        "groestl" => IVType::EssivGroestl,
                        _ => {
                            println!("block_encrypt-mkfs: failed to read iv generator type");
                            usage();
                            process::exit(1);
                        }
                    }
                }
                None => {
                    println!("block_encrypt-mkfs: failed to read iv generator type");
                    usage();
                    process::exit(1);
                }
            }
        }
    } else {
        match s {
            "plain" => IVType::Plain,
            "plainbe" => IVType::PlainBE,
            "null" => IVType::Null,
            _ => {
                println!("block_encrypt-mkfs: failed to read iv generator type");
                usage();
                process::exit(1);
            }
        }
    }
}

fn usage() {
    println!("Usage:");
    println!("block_encrypt-mkfs DISK ENC_ALGORITHM CIPHER_MODE IVGENERATOR");
    println!("encryption algorithms: aes128 | aes192 | aes256");
    println!("cipher modes: ecb | cbc | pcbc | xts");
    println!("initialization vectors: plain | plainbe | null | essiv:[hash function]");
    println!("essiv options: sha2-256 | sha2-512 | sha3-256 | sha3-512 | blake2b | blake2s | groestl");
}

fn main() {
    let mut args = env::args().skip(1);

    let disk_path = if let Some(path) = args.next() {
        path
    } else {
        println!("block_encrypt-mkfs: no disk image provided");
        usage();
        process::exit(1);
    };

    let encryption_alg = match args.next() {
        Some(arg) => parse_encryption_algorithm(&arg),
        None => {
            println!("block_encrypt-mkfs: encryption algorithm type not provided");
            usage();
            process::exit(1);
        }
    };

    let cipher_mode = match args.next() {
        Some(arg) => parse_cipher_mode(&arg),
        None => {
            println!("block_encrypt-mkfs: cipher mode not provided");
            usage();
            process::exit(1);
        }
    };

    let iv_generator = match args.next() {
        Some(arg) => parse_ivgenerator(&arg),
        None => {
            println!("block_encrypt-mkfs: initialization vector generator not provided");
            usage();
            process::exit(1);
        }
    };

    // Read password
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    stdout.write_all(b"Enter password: ").unwrap();
    stdout.flush().unwrap();

    let pass = stdin.read_passwd(&mut stdout);
    let pass1 = match pass {
        Ok(Some(p)) => p,
        _ => {
            eprintln!("\nError entering the password");
            process::exit(1);
        }
    };

    stdout.write_all(b"\nEnter password again: ").unwrap();
    stdout.flush().unwrap();

    let pass = stdin.read_passwd(&mut stdout);

    stdout.write_all(b"\n").unwrap();
    stdout.flush().unwrap();

    let pass2 = match pass {
        Ok(Some(p)) => p,
        _ => {
            eprintln!("\nError entering the password");
            process::exit(1);
        }
    };

    if pass1 != pass2 {
        eprintln!("Error: passwords do not match");
        process::exit(1);
    }

    let p = pass1.as_bytes();

    let disk = match BlockEncrypt::open_new_disk(&disk_path, encryption_alg,
                                                 cipher_mode, iv_generator, p) {
        Ok(disk) => disk,
        Err(err) => {
            println!("block_encrypt-mkfs: failed to open image {}: {}", disk_path, err);
            process::exit(1);
        }
    };

    let ctime = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
    match FileSystem::create_reserved(disk, &[],ctime.as_secs(), ctime.subsec_nanos()) {
        Ok(filesystem) => {
            let uuid = Uuid::from_bytes(&filesystem.header.1.uuid).unwrap();
            println!("block_encrypt-mkfs: created filesystem on {}, reserved {} blocks, size {} MB, uuid {}", disk_path, filesystem.block, filesystem.header.1.size/1000/1000, uuid.hyphenated());
        },
        Err(err) => {
            println!("block_encrypt-mkfs: failed to create filesystem on {}: {}", disk_path, err);
            process::exit(1);
        }
    }
}
