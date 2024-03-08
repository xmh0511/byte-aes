use crate::get_generic_array;
use crate::Aes256;
use crate::BlockEncrypt;
use crate::KeyInit;
use crate::OMFE;

/// Initialize the Struct with text as `String` type using the from() method and perform encryption operations
pub struct Encryptor {
    raw_bytes: Vec<u8>,
}

impl<T> From<T> for Encryptor
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self {
            raw_bytes: value.as_ref().into(),
        }
    }
}

impl Encryptor {
    pub fn new(raw_bytes: Vec<u8>) -> Self {
        Self { raw_bytes }
    }
    /// Takes a Key of 32 bytes in length to Encrypt the text initialized with the Encryptor::from() associated function
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use byte_aes::encrypt::Encryptor;
    ///
    /// let my_32byte_key = "Thisi$MyKeyT0Encryp!thislastTime".to_owned();
    /// let original_text: String = "I am Omkaram Venkatesh and this is my plain text and some random chars 223@#$^$%*%^(!#@%$~@#$[]]'///\\drewe. Lets see if this gets encrypted now)".to_string();
    /// let original_bytes: &[u8] = original_text.as_bytes();
    ///
    /// // You can encrypt your data by providing a slice
    /// let encrypt_obj: Encryptor = Encryptor::from(original_text.as_str());
    ///
    /// // You can encrypt your data by providing a String
    /// let encrypt_obj: Encryptor = Encryptor::from(original_text.as_str());
    ///
    /// // You can encrypt your data by providing raw bytes
    /// let encrypt_obj: Encryptor = Encryptor::from(original_bytes);
    /// let encrypted_bytes: Vec<u8> = encrypt_obj.encrypt_with(&my_32byte_key);
    ///
    /// ````
    ///
    /// The output from the variable 'encrypted_bytes' would return a `Vec<u8>`
    pub fn encrypt_with(&self, key: &str) -> Vec<u8> {
        // I am deferencing the Box returned from the get_generic_array below
        let (key, mut deref_generic_block) = get_generic_array(self, key, false);

        let aes_object = Aes256::new(&key);

        // Encrypt the single unit at once (This Unit will contain all the blocks)
        aes_object.encrypt_blocks(deref_generic_block.as_mut_slice());

        // Stich back the encrypted blocks
        deref_generic_block
            .concat()
            .into_iter()
            .collect::<Vec<u8>>()
    }
}

impl OMFE for Encryptor {
    fn get_raw_bytes(&self) -> Vec<u8> {
        self.raw_bytes.to_owned()
    }
}
