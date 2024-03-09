use aes::cipher::{
    crypto_common::generic_array::GenericArray, typenum::U32, BlockDecrypt, BlockEncrypt,
};
use aes::{cipher::KeyInit, Aes256};

impl TryFrom<&str> for Aes256Cryptor {
    type Error = std::io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "The number of bytes of the key shall be 32",
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(value.as_bytes());
        Ok(Aes256Cryptor::new(key))
    }
}

impl TryFrom<String> for Aes256Cryptor {
    type Error = std::io::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Aes256Cryptor::try_from(&value as &str)
    }
}

impl TryFrom<&String> for Aes256Cryptor {
    type Error = std::io::Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Aes256Cryptor::try_from(&value as &str)
    }
}

#[derive(Clone, Debug)]
pub struct Aes256Cryptor {
    key: [u8; 32],
    aes_256: Aes256,
}

impl Aes256Cryptor {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            // Here U32 is not same as u32. U32 creates our GenericArray Key which is 32 byte long. If the key length is not 32 bytes in length, then this from_slice() call fails with assertion error
            key,
            aes_256: Aes256::new(GenericArray::<u8, U32>::from_slice(&key)),
        }
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn encrypt<T, U>(&self, plaintext: T) -> Vec<u8>
    where
        BytesWrapper<BytesWrapper<T>>: IntoBytes<U>,
    {
        let mut blocks =
            super::get_generic_array(BytesWrapper(BytesWrapper(plaintext)).into_bytes(), false);
        // Encrypt the single unit at once (This Unit will contain all the blocks)
        self.aes_256.encrypt_blocks(blocks.as_mut_slice());
        blocks.concat().into_iter().collect()
    }

    pub fn decrypt<T, U>(&self, ciphertext: T) -> std::io::Result<Vec<u8>>
    where
        BytesWrapper<BytesWrapper<T>>: IntoBytes<U>,
    {
        let raw_bytes = BytesWrapper(BytesWrapper(ciphertext)).into_bytes();
        if raw_bytes.len() % 16 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "The number of bytes of the encrypted data shall be multiple of 16",
            ));
        }
        let mut blocks = super::get_generic_array(raw_bytes, true);
        // Decrypt the single unit at once (This Unit will contain all the blocks)
        self.aes_256.decrypt_blocks(blocks.as_mut_slice());
        // Concat the decrypted block which the deref_generic_block hold and turn then in a Vec<u8>
        let decrypted_bytes = blocks.concat().into_iter().collect::<Vec<u8>>();

        if let Some(v) = decrypted_bytes.last() {
            if *v == 16 && decrypted_bytes[decrypted_bytes.len() - 16..] == [16u8; 16] {
                return Ok(decrypted_bytes[..decrypted_bytes.len() - 16].to_vec());
            } else if *v < 16 {
                return Ok(decrypted_bytes[..decrypted_bytes.len() - (*v as usize)].to_vec());
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid encrypted data, the padding number cannot be {}",
                    *v
                ),
            ))
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "The number of bytes of the encrypted data shall be at least 16 even if the original data is empty"))
        }
    }
}

pub struct BytesWrapper<T>(T);

pub trait IntoBytes<T> {
    fn into_bytes(self) -> Vec<u8>;
}

impl<T: Into<Vec<u8>>> IntoBytes<T> for T {
    fn into_bytes(self) -> Vec<u8> {
        self.into()
    }
}

impl<T: IntoBytes<U>, U> IntoBytes<U> for BytesWrapper<T> {
    fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

impl IntoBytes<()> for BytesWrapper<BytesWrapper<&String>> {
    fn into_bytes(self) -> Vec<u8> {
        self.0 .0.to_owned().into_bytes()
    }
}
