use crate::get_generic_array;
use crate::Aes256;
use crate::BlockDecrypt;
use crate::KeyInit;
use crate::OMFE;

/// Initialize the Struct with the encypted bytes `Vec<u8>` using the from() method and perform decryption operations
pub struct Decryptor {
    raw_bytes: Vec<u8>,
}

impl<T> From<T> for Decryptor
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self {
            raw_bytes: value.as_ref().into(),
        }
    }
}

impl Decryptor {
    pub fn new(raw_bytes: Vec<u8>) -> Self {
        Self { raw_bytes }
    }
    /// Takes a Key of 32 bytes in length to Decrypt the text initialized with the Decryptor::from() associated function
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use byte_aes::encrypt::Encryptor;
    /// use byte_aes::decrypt::Decryptor;
    ///
    /// let my_32byte_key = "Thisi$MyKeyT0Encryp!thislastTime";
    /// let original_text = "I am Omkaram Venkatesh and this is my plain text and some random chars 223@#$^$%*%^(!#@%$~@#$[]]'///\\drewe. Lets see if this gets encrypted now)";
    /// let original_bytes = original_text.as_bytes();
    ///
    /// let encrypt_obj: Encryptor = Encryptor::from(original_text);
    /// let encrypted_bytes: Vec<u8> = encrypt_obj.encrypt_with(my_32byte_key);
    ///
    /// //encrypted_bytes is borrowed here
    /// let decrypted_obj: Decryptor = Decryptor::from(&encrypted_bytes);
    /// let decrypted_bytes: Vec<u8>  = decrypted_obj.decrypt_with(my_32byte_key).unwrap_or_default();
    /// let decrypted_text: String = String::from_utf8_lossy(&decrypted_bytes).to_string();
    ///
    /// assert_eq!(original_text, decrypted_text);
    ///
    /// //encrypted_bytes is moved here
    /// let decrypted_obj: Decryptor = Decryptor::from(encrypted_bytes);
    /// let decrypted_bytes: Vec<u8> = decrypted_obj.decrypt_with(&my_32byte_key).unwrap_or_default();
    ///
    /// assert_eq!(original_bytes, decrypted_bytes);
    ///
    /// ````
    ///
    /// The output from the variable 'decrypted_text' would return your orginal text
    pub fn decrypt_with(&self, key: &str) -> std::io::Result<Vec<u8>> {
        if self.raw_bytes.len() % 16 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "The number of bytes of the encrypted data shall be multiple of 16",
            ));
        }
        // I am deferencing the Box returned from the get_generic_array below
        let (key, mut deref_generic_block) = get_generic_array(self, key, true);

        let aes_object = Aes256::new(&key);

        // Decrypt the single unit at once (This Unit will contain all the blocks)
        aes_object.decrypt_blocks(deref_generic_block.as_mut_slice());

        // Concat the decrypted block which the deref_generic_block hold and turn then in a Vec<u8>
        let decrypted_bytes = deref_generic_block
            .concat()
            .into_iter()
            .collect::<Vec<u8>>();

        if let Some(v) = decrypted_bytes.last() {
            if *v == 16 && decrypted_bytes[decrypted_bytes.len() - 16..] == [16u8; 16] {
                return Ok(decrypted_bytes[..decrypted_bytes.len() - 16].to_vec());
            } else if *v < 16 {
                return Ok(decrypted_bytes[..decrypted_bytes.len() - (*v as usize)].to_vec());
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid encrypted data, the padding number cannot be {}",*v),
            ))
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "The number of bytes of the encrypted data shall be at least 16 even if the original data is empty"))
        }
    }
}

impl OMFE for Decryptor {
    fn get_raw_bytes(&self) -> Vec<u8> {
        self.raw_bytes.to_owned()
    }
}
