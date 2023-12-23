//! # Byte-AES
//! 
//! ### Developer: Omkarium
//! 
//! `byte-aes` is a simple wrapper around the popular `aes` crate. The goal is to perform Encrypt and Decrypt operations
//! using the **Advanced Encryption Standard 256 bit** Algorithm conveninent to use instead of use Low level functions of the `aes` crate

// Bringing all of these items into scope so they can be used in the individual modules without declaring full path
use aes::{Aes256, cipher::KeyInit};
use aes::cipher::{
    BlockEncrypt,
    BlockDecrypt,
    crypto_common::generic_array::GenericArray,
    typenum::{U32, U16, B0, B1, UInt, UTerm}
};

pub mod encrypt;
pub mod decrypt;

// This will re-export the below Structs
pub use self::encrypt::Encryptor;
pub use self::decrypt::Decryptor;

// This function is for internal use
// It takes those structs which implement the OMFE trait. In this case, the Encryptor and Decryptor structs are implementing it.
// It takes raw_bytes and splits them into chunks of 16 bytes. If any chunk is having less than 16 bytes, this function resize that particular chunk to a
// capacity of 16 bytes filled with 0's in the empty positions
fn split_into_16byte_blocks(item: &impl OMFE) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();

    for chunk in item.get_raw_bytes().chunks(16) {
        let mut chunk = chunk.to_vec();
        let capacity = chunk.capacity();
        if capacity < 16 {
            let pad_length = capacity + (16 - capacity % 16) % 16;
            chunk.resize(pad_length, 0);
        }
        blocks.push(chunk);
    }

    blocks
}

// This function gets us a GenericArray key and blocks(data)
// We need a Box here in the return type because the GenericArray type is not sized because its some kind of linked list 
// and we cannot return a type whose size is not known during compilation
fn get_generic_array<'a>(item: &impl OMFE, key: &String) -> Box<(GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>, Vec<GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>>)> {
    
    // Once the Encrypted or Decrypted Bytes are provided via self we split then into a a Vec<Vec<u8> where the inner Vec is always 16 bytes long
    let blocks = split_into_16byte_blocks(item);

    // We can't use the Vec<u8> to directly decrypt, so we need to use the GenericArray struct provided by the aes crate
    
    // Here U32 is not same as u32. U32 creates our GenericArray Key which is 32 byte long. If the key length is not 32 bytes in length, then this from_slice() call fails with assertion error
    let key = GenericArray::<u8, U32>::from_slice(key.as_bytes());
    let mut generic_block = Vec::new();

    // Same logic as the above, but the data we are planning to encrypt shall be 16 byte long blocks. Hence the U16 type.
    for each_block in blocks.as_slice() {
        let data = GenericArray::<u8, U16>::from_slice(each_block);
        
        // Storing the GenericArray blocks in a Vec
        generic_block.push(*data);
    }

    // deferencing the Generic block from the Vec as a single Unit
    let deref_generic_block = generic_block.as_mut_slice();

    Box::new((key.to_owned(),deref_generic_block.to_owned()))
}

/// I have no idea why you would need this trait for public use, but here you go
pub trait OMFE {
    fn get_raw_bytes(&self) -> Vec<u8>;
}

/// This is my create
#[cfg(test)]
mod tests {
    use crate::{encrypt::Encryptor, decrypt::Decryptor};

    #[test]
    fn it_works() {
        let my_32byte_key = "Thisi$MyKeyT0Encryp!thislastTime".to_owned();
        let original_text = "I am Omkaram Venkatesh and 
        this is my plain text and some random chars 223@#$^$%*%^(!#@%$~@#$[]]'///\\drewe. Lets see if this gets encrypted now)".to_string();
        
        let mut encrypt_obj: Encryptor = Encryptor::from(&original_text);
        let encrypted_bytes: Vec<u8> = encrypt_obj.encrypt_with(&my_32byte_key);

        let mut decrypted_obj: Decryptor = Decryptor::from(&encrypted_bytes);
        let decrypted_text: String = decrypted_obj.decrypt_with(&my_32byte_key);
        
        assert_eq!(original_text, decrypted_text);
    }
}

