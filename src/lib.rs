//! # Byte-AES
//!
//! ### Developer: Omkarium
//!
//! `byte-aes` is a simple wrapper around the popular `aes` crate. The goal is to perform Encrypt and Decrypt operations
//! using the **Advanced Encryption Standard 256 bit** Algorithm conveninent to use instead of use Low level functions of the `aes` crate

// Bringing all of these items into scope so they can be used in the individual modules without declaring full path
use aes::cipher::{
    crypto_common::generic_array::GenericArray,
    typenum::{U16, U32},
    BlockDecrypt, BlockEncrypt,
};
use aes::{
    cipher::{Key, KeyInit},
    Aes256, Block,
};

pub mod decrypt;
pub mod encrypt;

// This will re-export the below Structs
pub use self::decrypt::Decryptor;
pub use self::encrypt::Encryptor;

// This function is for internal use
// It takes those structs which implement the OMFE trait. In this case, the Encryptor and Decryptor structs are implementing it.
// It takes raw_bytes and splits them into chunks of 16 bytes. If any chunk is having less than 16 bytes, this function resize that particular chunk to a
// capacity of 16 bytes filled with data specified by Pkcs7Padding algorithm

fn split_into_16byte_blocks(item: &impl OMFE, is_decrypt: bool) -> Vec<Vec<u8>> {
    let mut origin = item.get_raw_bytes();
    let round = origin.len() % 16;
    if round == 0 && !is_decrypt {
        let extra = [16u8; 16];
        origin.extend_from_slice(&extra[..]);
    } else if !is_decrypt {
        let required_padding = 16 - round;
        let extra = vec![required_padding as u8; required_padding];
        origin.extend_from_slice(&extra[..]);
    }
    origin.chunks(16).map(|v| v.to_vec()).collect()
}

// This function gets us a GenericArray key and blocks(data)
// We need a Box here in the return type because the GenericArray type is not sized because its some kind of linked list
// and we cannot return a type whose size is not known during compilation

fn get_generic_array(item: &impl OMFE, key: &str, is_decrypt: bool) -> (Key<Aes256>, Vec<Block>) {
    // Once the Encrypted or Decrypted Bytes are provided via self we split then into a a Vec<Vec<u8> where the inner Vec is always 16 bytes long
    let blocks = split_into_16byte_blocks(item, is_decrypt);

    // We can't use the Vec<u8> to directly decrypt, so we need to use the GenericArray struct provided by the aes crate

    // Here U32 is not same as u32. U32 creates our GenericArray Key which is 32 byte long. If the key length is not 32 bytes in length, then this from_slice() call fails with assertion error
    let key = GenericArray::<u8, U32>::from_slice(key.as_bytes());

    // Same logic as the above, but the data we are planning to encrypt shall be 16 byte long blocks. Hence the U16 type.
    let generic_block = blocks
        .into_iter()
        .map(|v| GenericArray::<u8, U16>::from_slice(&v[..]).to_owned())
        .collect();

    // deferencing the Generic block from the Vec as a single Unit
    //let deref_generic_block = generic_block.as_mut_slice();

    (key.to_owned(), generic_block)
}

/// I have no idea why you would need this trait for public use, but here you go
pub trait OMFE {
    fn get_raw_bytes(&self) -> Vec<u8>;
}

/// This is my create
#[cfg(test)]
mod tests {
    use crate::{decrypt::Decryptor, encrypt::Encryptor};

    #[test]
    fn test_with_strings() {
        let my_32byte_key = "Thisi$MyKeyT0Encryp!thislastTime".to_owned();
        let original_text = "I am Omkaram Venkatesh and 
        this is my plain text and some random chars 223@#$^$%*%^(!#@%$~@#$[]]'///\\drewe. Lets see if this gets encrypted now)".to_string();

        let encrypt_obj: Encryptor = Encryptor::from(original_text.as_str());
        let encrypted_bytes: Vec<u8> = encrypt_obj.encrypt_with(&my_32byte_key);

        let decrypted_obj: Decryptor = Decryptor::from(encrypted_bytes);
        let decrypted_bytes: Vec<u8> = decrypted_obj
            .decrypt_with(&my_32byte_key)
            .unwrap_or_default();
        let decrypted_text: String = String::from_utf8_lossy(&decrypted_bytes).to_string();

        assert_eq!(original_text, decrypted_text);
    }

    #[test]
    fn test_with_bytes() {
        let my_32byte_key = "Thisi$MyKeyT0Encryp!thislastTime".to_owned();
        let original_bytes = "I am Omkaram Venkatesh and 
        this is my plain text and some random chars 223@#$^$%*%^(!#@%$~@#$[]]'///\\drewe. Lets see if this gets encrypted now)".as_bytes();

        let encrypt_obj: Encryptor = Encryptor::from(original_bytes);
        let encrypted_bytes: Vec<u8> = encrypt_obj.encrypt_with(&my_32byte_key);

        let decrypted_obj: Decryptor = Decryptor::from(encrypted_bytes);
        let decrypted_bytes: Vec<u8> = decrypted_obj
            .decrypt_with(&my_32byte_key)
            .unwrap_or_default();

        assert_eq!(original_bytes, decrypted_bytes);
    }
}
