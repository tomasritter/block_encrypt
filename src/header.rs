pub enum EncryptionAlgorithm {
    Aes128,
    Aes192,
    Aes256
}

pub enum CipherMode {
    CBC,
    ECB,
    PCBC,
    XTS,
}

pub enum IVType {
    Plain,
    PlainBE,
    Null,
    EssivSha2_256,
    EssivSha2_512,
    EssivSha3_256,
    EssivSha3_512,
    EssivBlake2b,
    EssivBlake2s,
    EssivGroestl,
}

#[repr(C, align(4096))] // Align to the size of the block
pub struct EncryptHeader {
    pub encryption_alg: EncryptionAlgorithm,
    pub cipher_mode: CipherMode,
    pub iv_generator: IVType,
    pub user_key_salt: [u8; 32],
    pub master_key_encrypted: [u8; 64],
    pub master_key_digest: [u8; 64],
    pub master_key_salt: [u8; 32]
}

impl EncryptHeader {
    pub fn deserialize(buffer: &[u8]) -> &Self { unsafe {EncryptHeader::u8_as_any_slice(buffer) } }

    pub fn serialize(&self) -> &[u8] {
        unsafe { EncryptHeader::any_as_u8_slice(self) }
    }

    unsafe fn u8_as_any_slice<T: Sized>(p: &[u8]) -> &T {
        &::std::slice::from_raw_parts(
            (p as *const [u8])as *const T,
            ::std::mem::size_of::<T>(),
        )[0]
    }

    unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
        ::std::slice::from_raw_parts(
            (p as *const T) as *const u8,
            ::std::mem::size_of::<T>(),
        )
    }

}