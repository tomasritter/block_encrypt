
pub struct EncryptHeader {
    deriv_function: Enum,
    keysize: u64,
    key: [u8; 64], // 512bit
    salt: [u8; 64], // TODO: Length of salt
    encryption_alg: Enum, //
    iv_generator: Enum // For essiv enum with parameter?
}