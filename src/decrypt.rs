use crate::Aes256;
use crate::KeyInit;
use crate::BlockDecrypt;
use crate::get_generic_array;
use crate::OMFE;

/// Initialize the Struct with the encypted bytes `Vec<u8>` using the from() method and perform decryption operations
pub struct Decryptor {
    raw_bytes: Vec<u8>
}

impl From<&Vec<u8>> for Decryptor {
    fn from(value: &Vec<u8>) -> Self {
        Self { raw_bytes: value.to_owned() }
    }
}

impl Decryptor {
    /// Takes a Key of 32 bytes in length to Decrypt the text initialized with the Decryptor::from() associated function
    /// 
    /// # Examples
    /// 
    /// ```
    /// use byte_aes::encrypt::Encryptor;
    /// use byte_aes::decrypt::Decryptor;
    /// 
    /// let my_32byte_key = "Thisi$MyKeyT0Encryp!thislastTime".to_owned();
    /// let original_text = "I am Omkaram Venkatesh and this is my plain text and some random chars 223@#$^$%*%^(!#@%$~@#$[]]'///\\drewe. Lets see if this gets encrypted now)".to_string();
    /// 
    /// let mut encrypt_obj: Encryptor = Encryptor::from(&original_text);
    /// let encrypted_bytes: Vec<u8> = encrypt_obj.encrypt_with(&my_32byte_key);
    /// 
    /// let mut decrypted_obj: Decryptor = Decryptor::from(&encrypted_bytes);
    /// let decrypted_text: String = decrypted_obj.decrypt_with(&my_32byte_key);
    /// 
    /// assert_eq!(original_text, decrypted_text);
    /// 
    /// ````
    /// 
    /// The output from the variable 'decrypted_text' would return your orginal text
    pub fn decrypt_with(&mut self, key: &String) -> String {

        // I am deferencing the Box returned from the get_generic_array below
        let (key, mut deref_generic_block) = *get_generic_array(self, key);

        let aes_object = Aes256::new(&key);

        // Decrypt the single unit at once (This Unit will contain all the blocks)
        aes_object.decrypt_blocks(deref_generic_block.as_mut_slice());

        // Concat the decrypted block which the deref_generic_block hold and turn then in a Vec<u8>
        let decrypted_bytes = deref_generic_block.concat().into_iter().collect::<Vec<u8>>();

        // Stich the Vec<u> by removing the padded 0's we have appended during the encryption opertaion
        let stich_bytes = decrypted_bytes.into_iter().filter(|x| *x != 0).collect::<Vec<u8>>();

        //Convert the raw bytes back to String
        String::from_utf8_lossy(&stich_bytes).to_string()
    }
}

impl OMFE for Decryptor {
    fn get_raw_bytes(&self) -> Vec<u8> {
        self.raw_bytes.to_owned()
    }
}
