//! # Byte-AES
//!
//! ### Developer: Omkarium
//!
//! `byte-aes` is a simple wrapper around the popular `aes` crate. The goal is to perform Encrypt and Decrypt operations
//! using the **Advanced Encryption Standard 256 bit** Algorithm conveninent to use instead of use Low level functions of the `aes` crate

// Bringing all of these items into scope so they can be used in the individual modules without declaring full path
use aes::{
    cipher::{crypto_common::generic_array::GenericArray, typenum::U16},
    Block,
};

pub mod cryptor;

pub use cryptor::Aes256Cryptor;

// This function is for internal use
// It takes those structs which implement the OMFE trait. In this case, the Encryptor and Decryptor structs are implementing it.
// It takes raw_bytes and splits them into chunks of 16 bytes. If any chunk is having less than 16 bytes, this function resize that particular chunk to a
// capacity of 16 bytes filled with data specified by Pkcs7Padding algorithm

fn split_into_16byte_blocks(mut origin: Vec<u8>, is_decrypt: bool) -> Vec<Vec<u8>> {
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

fn get_generic_array(item: Vec<u8>, is_decrypt: bool) -> Vec<Block> {
    // Once the Encrypted or Decrypted Bytes are provided via self we split then into a a Vec<Vec<u8> where the inner Vec is always 16 bytes long
    let blocks = split_into_16byte_blocks(item, is_decrypt);

    // We can't use the Vec<u8> to directly decrypt, so we need to use the GenericArray struct provided by the aes crate

    // Same logic as the above, but the data we are planning to encrypt shall be 16 byte long blocks. Hence the U16 type.
    let generic_block = blocks
        .into_iter()
        .map(|v| GenericArray::<u8, U16>::from_slice(&v[..]).to_owned())
        .collect();

    // deferencing the Generic block from the Vec as a single Unit
    //let deref_generic_block = generic_block.as_mut_slice();
    generic_block
}

/// This is my create
#[cfg(test)]
mod tests {
    use crate::Aes256Cryptor;

    #[test]
    fn test_with_strings() {
        let my_32byte_key = "Thisi$MyKeyT0Encryp!thislastTime".to_owned();
        let original_text = "I am Omkaram Venkatesh and 
        this is my plain text and some random chars 223@#$^$%*%^(!#@%$~@#$[]]'///\\drewe. Lets see if this gets encrypted now)".to_string();

        let cryptor = Aes256Cryptor::try_from(&my_32byte_key).unwrap();
        let encrypted_bytes: Vec<u8> = cryptor.encrypt(&original_text as &str);

        let decrypted_text: String =
            String::from_utf8_lossy(&cryptor.decrypt(encrypted_bytes).unwrap_or_default())
                .to_string();

        assert_eq!(original_text, decrypted_text);
    }

    #[test]
    fn test_with_bytes() {
        let key = "c4ca4238a0b923820dcc509a6f75849b";
        let cryptor = Aes256Cryptor::try_from(key).unwrap();
        let buf: [u8; 4] = [1, 0, 0, 1];
        let encrypt_buf = cryptor.encrypt(buf);

        let clear_buf = cryptor.decrypt(encrypt_buf);
        let clear_buf = clear_buf.as_ref().map(|v| &v[..]).map_err(|_| ());
        assert_eq!(Ok(&buf[..]), clear_buf);

        let buf: [u8; 16] = [1, 0, 0, 1, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13];
        let encrypt_buf = cryptor.encrypt(buf);

        let clear_buf = cryptor.decrypt(encrypt_buf);
        let clear_buf = clear_buf.as_ref().map(|v| &v[..]).map_err(|_| ());
        assert_eq!(Ok(&buf[..]), clear_buf);

        let buf = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 200]; // invalid data for decrypting
        let clear_buf = cryptor.decrypt(buf);
        assert!(clear_buf.is_err());
    }
}
