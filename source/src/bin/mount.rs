#![cfg_attr(not(target_os = "redox"), feature(libc))]

#[cfg(not(target_os = "redox"))]
extern crate libc;

#[cfg(target_os = "redox")]
extern crate syscall;

extern crate redoxfs;
extern crate block_encrypt;
extern crate uuid;


use std::env;
use std::fs::File;
use std::io::{Read, Write, stdout, stdin};
use std::os::unix::io::{FromRawFd, RawFd};
use std::process;
use uuid::Uuid;

use redoxfs::{Disk, DiskCache, DiskFile, mount};
use block_encrypt::BlockEncrypt;
use block_encrypt::utils::read_password;

#[cfg(target_os = "redox")]
extern "C" fn unmount_handler(_s: usize) {
    use std::sync::atomic::Ordering;
    redoxfs::IS_UMT.store(1, Ordering::SeqCst);
}

#[cfg(target_os = "redox")]
fn setsig() {
    use syscall::{sigaction, SigAction, SIGTERM};

    let sig_action = SigAction {
        sa_handler: unmount_handler,
        sa_mask: [0,0],
        sa_flags: 0,
    };

    sigaction(SIGTERM, Some(&sig_action), None).unwrap();
}

#[cfg(not(target_os = "redox"))]
fn setsig() {
    ()
}

#[cfg(not(target_os = "redox"))]
fn fork() -> isize {
    unsafe { libc::fork() as isize }
}

#[cfg(not(target_os = "redox"))]
fn pipe(pipes: &mut [i32; 2]) -> isize {
    unsafe { libc::pipe(pipes.as_mut_ptr()) as isize }
}

#[cfg(target_os = "redox")]
fn fork() -> isize {
    unsafe { syscall::Error::mux(syscall::clone(0)) as isize }
}

#[cfg(target_os = "redox")]
fn pipe(pipes: &mut [usize; 2]) -> isize {
    syscall::Error::mux(syscall::pipe2(pipes, 0)) as isize
}

fn usage() {
    println!("block-encrypt disk mountpoint password");
}

#[cfg(not(target_os = "redox"))]
fn disk_paths(_paths: &mut Vec<String>) {}

#[cfg(target_os = "redox")]
fn disk_paths(paths: &mut Vec<String>) {
    use std::fs;

    let mut schemes = vec![];
    match fs::read_dir(":") {
        Ok(entries) => for entry_res in entries {
            if let Ok(entry) = entry_res {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    let scheme = path.trim_start_matches(':').trim_matches('/');
                    if scheme.starts_with("disk") {
                        println!("block_encrypt: found scheme {}", scheme);
                        schemes.push(format!("{}:", scheme));
                    }
                }
            }
        },
        Err(err) => {
            println!("block_encrypt: failed to list schemes: {}", err);
        }
    }

    for scheme in schemes {
        match fs::read_dir(&scheme) {
            Ok(entries) => for entry_res in entries {
                if let Ok(entry) = entry_res {
                    if let Ok(path) = entry.path().into_os_string().into_string() {
                        println!("block_encrypt: found path {}", path);
                        paths.push(path);
                    }
                }
            },
            Err(err) => {
                println!("block_encrypt: failed to list '{}': {}", scheme, err);
            }
        }
    }
}

fn daemon_encr(path: &str, mountpoint: &str, mut write: File, password: &[u8]) -> ! {
    setsig();

        println!("block_encrypt: opening {}", path);
        match BlockEncrypt::open_used_disk(&path, password).map(|image| DiskCache::new(image)) {
            Ok(disk) => match redoxfs::FileSystem::open(disk) {
                Ok(filesystem) => {
                    println!("block_encrypt: opened filesystem on {} with uuid {}", path,
                             Uuid::from_bytes(&filesystem.header.1.uuid).unwrap().hyphenated());


                    mount(filesystem, &mountpoint, || {
                        println!("block_encrypt: mounted filesystem on {} to {}", path, mountpoint);
                        let _ = write.write(&[0]); });
                },
                Err(err) => println!("block_encrypt: failed to open filesystem {}: {}", path, err)
            },
            Err(err) => println!("block_encrypt: failed to open image {}: {}", path, err)
        }

    println!("block_encrypt: not able to mount path {}", path);
    let _ = write.write(&[1]);
    process::exit(1);
}

fn main() {
    let mut args = env::args().skip(1);

    let disk_path = match args.next() {
        Some(arg) => arg,
        None => {
            println!("block_encrypt: no disk provided");
            usage();
            process::exit(1);
        }
    };

    let mountpoint = match args.next() {
        Some(arg) => arg,
        None => {
            println!("block_encrypt: no mountpoint provided");
            usage();
            process::exit(1);
        }
    };

    let password = match args.next() {
        Some(arg) => arg,
        None => {
            println!("block_encrypt: no password provided");
            usage();
            process::exit(1);
        }
    };

    let mut pipes = [0; 2];
    if pipe(&mut pipes) == 0 {
        let mut read = unsafe { File::from_raw_fd(pipes[0] as RawFd) };
        let write = unsafe { File::from_raw_fd(pipes[1] as RawFd) };

        let pid = fork();
        if pid == 0 {
            drop(read);

            daemon_encr(&disk_path, &mountpoint, write, password.as_bytes())
        } else if pid > 0 {
            drop(write);

            let mut res = [0];
            read.read(&mut res).unwrap();

            process::exit(res[0] as i32);
        } else {
            panic!("block_encrypt: failed to fork");
        }
    } else {
        panic!("block_encrypt: failed to create pipe");
    }
}
