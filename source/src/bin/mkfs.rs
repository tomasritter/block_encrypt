extern crate redoxfs;
extern crate uuid;
extern crate block_encrypt;
extern crate termion;

use std::{env, fs, process, time};
use std::io::{Read, Write, stdout, stdin};
use std::vec::Vec;

use termion::input::TermRead;
use redoxfs::FileSystem;
use uuid::Uuid;
use block_encrypt::BlockEncrypt;
use block_encrypt::header::*;

fn parse_deriv_function(s: &str) -> DerivationFunction {
    match s {
        "argon2i" => DerivationFunction::Argon2i,
        "argon2id" => DerivationFunction::Argon2id,
        _ => {
            println!("redoxfs-mkfs-enc: failed to read derivation function type");
            process::exit(1);
        }
    }
}

fn parse_encryption_algorithm(s: &str) -> EncryptionAlgorithm {
    match s {
        "rust-aes128" => EncryptionAlgorithm::RustAes128,
        "rust-aes192" => EncryptionAlgorithm::RustAes192,
        "rust-aes256" => EncryptionAlgorithm::RustAes256,
        _ => {
            println!("redoxfs-mkfs-enc: failed to read encryption algorithm type");
            process::exit(1);
        }
    }
}

fn parse_cipher_mode(s: &str) -> CipherMode {
    match s {
        "cbc" => CipherMode::CBC,
        "ecb" => CipherMode::ECB,
        "pcbc" => CipherMode::PCBC,
        _ => {
            println!("redoxfs-mkfs-enc: failed to read cipher mode type");
            process::exit(1);
        }
    }
}

// TODO: Error messages
fn parse_ivgenerator(s: &str) -> IVGeneratorEnum {
    if s.starts_with("essiv") {
        let mut split = s.splitn(2, ':');
        if split.next().unwrap() != "essiv" {
            println!("redoxfs-mkfs-enc: failed to read iv generator type");
            process::exit(1);
        } else {
            match split.next() {
                Some(arg) => {
                    match arg {
                        "sha2-256" => IVGeneratorEnum::EssivSha2_256,
                        "sha2-512" => IVGeneratorEnum::EssivSha2_512,
                        "sha3-256" => IVGeneratorEnum::EssivSha3_256,
                        "sha3-512" => IVGeneratorEnum::EssivSha3_512,
                        "blake2b" => IVGeneratorEnum::EssivBlake2b,
                        "blake2s" => IVGeneratorEnum::EssivBlake2s,
                        "groestl" => IVGeneratorEnum::EssivGroestl,
                        _ => {
                            println!("redoxfs-mkfs-enc: failed to read iv generator type");
                            process::exit(1);
                        }
                    }
                }
                None => {
                    println!("redoxfs-mkfs-enc: failed to read iv generator type");
                    process::exit(1);
                }
            }
        }
    } else {
        match s {
            "plain" => IVGeneratorEnum::Plain,
            "plainbe" => IVGeneratorEnum::PlainBE,
            "null" => IVGeneratorEnum::Null,
            _ => {
                println!("redoxfs-mkfs-enc: failed to read iv generator type");
                process::exit(1);
            }
        }
    }
}

fn parse_iterations(s: &str) -> u64 {
    let n = s.parse::<u64>();
    match n {
        Ok(arg) => arg,
        Err(err) => {
            println!("redoxfs-mkfs-enc: wasn't able to parse the number of iterations");
            process::exit(1);
        }
    }
}

fn main() {
    let mut args = env::args().skip(1);

    let disk_path = if let Some(path) = args.next() {
        path
    } else {
        println!("redoxfs-mkfs-enc: no disk image provided");
        println!("redoxfs-mkfs-enc DISK DERIVATION_FUNCTION ENC_ALGORITHM CIPHER_MODE IVGENERATOR USER_KEY_ITER MASTER_KEY_ITER [BOOTLOADER]");
        process::exit(1);
    };

    let deriv_function = match args.next() {
        Some(arg) => parse_deriv_function(&arg),
        None => {
            println!("redoxfs-mkfs-enc: derivation function type not provided");
            process::exit(1);
        }
    };

    let encryption_alg = match args.next() {
        Some(arg) => parse_encryption_algorithm(&arg),
        None => {
            println!("redoxfs-mkfs-enc: encryption algorithm type not provided");
            process::exit(1);
        }
    };

    let cipher_mode = match args.next() {
        Some(arg) => parse_cipher_mode(&arg),
        None => {
            println!("redoxfs-mkfs-enc: cipher mode not provided");
            process::exit(1);
        }
    };

    let iv_generator = match args.next() {
        Some(arg) => parse_ivgenerator(&arg),
        None => {
            println!("redoxfs-mkfs-enc: initialization vector generator not provided");
            process::exit(1);
        }
    };

    let user_key_iterations = match args.next() {
        Some(arg) => parse_iterations(&arg),
        None => 10000 // Default magic values
    };

    let master_key_iterations = match args.next() {
        Some(arg) => parse_iterations(&arg),
        None => 10000
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

    let disk = match BlockEncrypt::open_new_disk(&disk_path, deriv_function, encryption_alg,
                                                 cipher_mode, iv_generator, user_key_iterations,
                                                    master_key_iterations, p) {
        Ok(disk) => disk,
        Err(err) => {
            println!("redoxfs-mkfs-enc: failed to open image {}: {}", disk_path, err);
            process::exit(1);
        }
    };

    let bootloader_path_opt = args.next();

    let mut bootloader = vec![];
    if let Some(bootloader_path) = bootloader_path_opt {
        match fs::File::open(&bootloader_path) {
            Ok(mut file) => match file.read_to_end(&mut bootloader) {
                Ok(_) => (),
                Err(err) => {
                    println!("redoxfs-mkfs-enc: failed to read bootloader {}: {}", bootloader_path, err);
                    process::exit(1);
                }
            },
            Err(err) => {
                println!("redoxfs-mkfs-enc: failed to open bootloader {}: {}", bootloader_path, err);
                process::exit(1);
            }
        }
    };

    let ctime = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
    match FileSystem::create_reserved(disk, &bootloader, ctime.as_secs(), ctime.subsec_nanos()) {
        Ok(filesystem) => {
            let uuid = Uuid::from_bytes(&filesystem.header.1.uuid).unwrap();
            println!("redoxfs-mkfs-enc: created filesystem on {}, reserved {} blocks, size {} MB, uuid {}", disk_path, filesystem.block, filesystem.header.1.size/1000/1000, uuid.hyphenated());
        },
        Err(err) => {
            println!("redoxfs-mkfs-enc: failed to create filesystem on {}: {}", disk_path, err);
            process::exit(1);
        }
    }
}
