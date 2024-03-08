use byte_aes::{Decryptor, Encryptor};

fn main() {
    let my_32byte_key = "Thisi$MyKeyT0Encryp!thislastTime";
    let original_text = "I am Omkaram Venkatesh and 
	this is my plain text and some random chars 223@#$^$%*%^(!#@%$~@#$[]]'///\\drewe. Lets see if this gets encrypted now)".to_string();

    let encrypt_obj: Encryptor = Encryptor::from(&original_text);
    let encrypted_bytes: Vec<u8> = encrypt_obj.encrypt_with(my_32byte_key);

    let decrypted_obj: Decryptor = Decryptor::from(&encrypted_bytes);
    let decrypted_text: String = String::from_utf8_lossy(
        &decrypted_obj
            .decrypt_with(my_32byte_key)
            .unwrap_or_default(),
    )
    .to_string();

    assert_eq!(original_text, decrypted_text);
}
