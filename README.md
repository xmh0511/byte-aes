 ## How to use

 ```
#[cfg(test)]
mod tests {
    use byte_aes::Encryptor;
    use byte_aes::Decryptor;

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
```