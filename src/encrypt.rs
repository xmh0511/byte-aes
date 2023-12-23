use crate::Aes256;
use crate::KeyInit;
use crate::BlockEncrypt;
use crate::get_generic_array;
use crate::OMFE;

/// Initialize the Struct with text as `String` type using the from() method and perform encryption operations
pub struct Encryptor {
    text: String,
    raw_bytes: Vec<u8>
}

impl From<&String> for Encryptor {
    fn from(value: &String) -> Self {
        Self { text: value.to_owned(), raw_bytes: vec![] }
    }
}

impl Encryptor {
    fn convert_into_bytes(&mut self) {
        self.raw_bytes = self.text.as_bytes().to_owned();
    }
    /// Takes a Key of 32 bytes in length to Encrypt the text initialized with the Encryptor::from() associated function
    /// 
    /// # Examples
    /// 
    /// ```
    /// use byte_aes::encrypt::Encryptor;
    /// 
    /// let my_32byte_key = "Thisi$MyKeyT0Encryp!thislastTime".to_owned();
    /// let original_text = "I am Omkaram Venkatesh and this is my plain text and some random chars 223@#$^$%*%^(!#@%$~@#$[]]'///\\drewe. Lets see if this gets encrypted now)".to_string();
    /// 
    /// let mut encrypt_obj: Encryptor = Encryptor::from(&original_text);
    /// let encrypted_bytes: Vec<u8> = encrypt_obj.encrypt_with(&my_32byte_key);
    /// ````
    /// 
    /// The output from the variable 'encrypted_bytes' would return a `Vec<u8>`
    pub fn encrypt_with(&mut self, key: &String) -> Vec<u8> {

        // Convert the String plain text to raw bytes
        self.convert_into_bytes();

        // I am deferencing the Box returned from the get_generic_array below
        let (key, mut deref_generic_block) = *get_generic_array(self, key);

        let aes_object = Aes256::new(&key);

        // Encrypt the single unit at once (This Unit will contain all the blocks)
        aes_object.encrypt_blocks(deref_generic_block.as_mut_slice());
        
        // Stich back the encrypted blocks
        deref_generic_block.concat().into_iter().collect::<Vec<u8>>()
    }
}

impl OMFE for Encryptor {
    fn get_raw_bytes(&self) -> Vec<u8> {
        self.raw_bytes.to_owned()
    }
}