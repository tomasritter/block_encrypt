extern crate termion;

use std::io::{Read, Write, stdout, stdin};
use std::process;
use utils::termion::input::TermRead;
use std::vec::Vec;

pub fn read_password() -> Vec<u8> {
    // Read password
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    stdout.write_all(b"Enter password: ").unwrap();
    stdout.flush().unwrap();

    let pass = stdin.read_passwd(&mut stdout);

    stdout.write_all(b"\n").unwrap();
    stdout.flush().unwrap();

    let password = match pass {
        Ok(Some(p)) => p,
        _ => {
            eprintln!("Error entering the password");
            process::exit(1);
        }
    };
    password.as_bytes().to_vec()
}