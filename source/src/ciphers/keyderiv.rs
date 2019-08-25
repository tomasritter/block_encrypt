//extern crate pbkdf2;
//extern crate scrypt;
extern crate argon2;

//use self::argon2::Self;
use self::argon2::Config as ArgonConfig;
use self::argon2::Variant as ArgonVariant;
use header::DerivationFunction;

// TODO: Add scrypt and PBKDF2 if needed

pub trait KeyDerivationFunction {
    fn hash_password(self, password: &[u8], salt: &[u8]) -> Vec<u8>;
}

pub struct Argon2<'a> {
    config: ArgonConfig<'a>
}

impl <'a> Argon2<'a> {
    pub fn create(variant: &DerivationFunction, hash_length: &u64, iterations: &u64) -> Self {
        let mut config = ArgonConfig::default();
        config.variant = match variant {
            DerivationFunction::Argon2i => ArgonVariant::Argon2i,
            DerivationFunction::Argon2id => ArgonVariant::Argon2id
        };
        config.hash_length = *hash_length as u32;
        config.time_cost = *iterations as u32;
        Argon2 {
            config
        }
    }
}

impl <'a> KeyDerivationFunction for Argon2<'a> {
    fn hash_password(self, password: &[u8], salt: &[u8]) -> Vec<u8> {
        argon2::hash_raw(password, salt, &self.config).unwrap()
    }
}