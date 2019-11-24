extern crate block_encrypt;
extern crate redoxfs;
extern crate rand;

use block_encrypt::*;
use block_encrypt::header::*;
use block_encrypt::header::EncryptionAlgorithm::*;
use block_encrypt::header::CipherMode::*;
use block_encrypt::header::IVType::*;
use std::{fs, sync, thread, time};
use std::ops::DerefMut;
use std::path::Path;
use std::process::Command;
use rand::{RngCore, Rng};
use std::fs::File;

use redoxfs::FileSystem;
use block_encrypt::BlockEncrypt;

pub fn with_redoxfs<T, F>(callback: F,
                      encryption_alg: EncryptionAlgorithm,
                      cipher_mode: CipherMode,
                      iv_generator: IVType,
                      disk_path: &'static str,
                      mount_path: &'static str)
    -> T where
        T: Send + Sync + 'static,
        F: FnMut(&Path) -> T + Send + Sync + 'static
{
    let mut rng = rand::thread_rng();
    let mut password = [0u8; 256];
    rng.fill_bytes(&mut password);

    let res = {
        let mut file = match File::create(&disk_path) {
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

        let disk = BlockEncrypt::open_new_disk(dbg!(disk_path), encryption_alg, cipher_mode, iv_generator, &password).unwrap();

        if cfg!(not(target_os = "redox")) {
            if ! Path::new(mount_path).exists() {
                dbg!(fs::create_dir(dbg!(mount_path))).unwrap();
            }
        }

        let ctime = dbg!(time::SystemTime::now().duration_since(time::UNIX_EPOCH)).unwrap();
        let fs = FileSystem::create_reserved(disk, &[], ctime.as_secs(), ctime.subsec_nanos()).unwrap();

        let callback_mutex = sync::Arc::new(sync::Mutex::new(callback));
        let join_handle = redoxfs::mount(fs, dbg!(mount_path.clone()), move |real_path| {
            let callback_mutex = callback_mutex.clone();
            let real_path = real_path.to_owned();
            thread::spawn(move || {

                let res = {
                    let mut callback_guard = callback_mutex.lock().unwrap();
                    let callback = callback_guard.deref_mut();
                    callback(&real_path)
                };

                if cfg!(target_os = "redox") {
                    dbg!(fs::remove_file(dbg!(format!(":{}", mount_path.clone())))).unwrap();
                } else {
                    let status_res = if cfg!(target_os = "linux") {
                        Command::new("fusermount")
                            .arg("-u")
                            .arg(mount_path)
                            .status()
                    } else {
                        Command::new("umount")
                            .arg(mount_path)
                            .status()
                    };

                    let status = dbg!(status_res).unwrap();
                    if ! status.success() {
                        panic!("umount failed");
                    }
                }

                res
            })
        }).unwrap();

        join_handle.join().unwrap()
    };

    dbg!(fs::remove_file(dbg!(disk_path))).unwrap();

    if cfg!(not(target_os = "redox")) {
        dbg!(fs::remove_dir(dbg!(mount_path))).unwrap();
    }

    res
}

#[cfg(test)]
mod tests_with_fs {
    use super::*;

    #[test]
    fn simple() {
        with_redoxfs(|path| {
            dbg!(fs::create_dir(&path.join("test"))).unwrap();
        }, Aes128, ECB, Plain, "disk_path", "dir_path")
    }
}
