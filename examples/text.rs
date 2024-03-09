use byte_aes::Aes256Cryptor;

fn main() {
    let my_32byte_key = "Thisi$MyKeyT0Encryp!thislastTime";

    let cryptor = Aes256Cryptor::try_from(my_32byte_key).unwrap();
    let original_text = "I am Omkaram Venkatesh and 
	this is my plain text and some random chars 223@#$^$%*%^(!#@%$~@#$[]]'///\\drewe. Lets see if this gets encrypted now)".to_string();

    let encrypted_bytes: Vec<u8> = cryptor.encrypt(&original_text);

    let decrypted_text: String =
        String::from_utf8_lossy(&cryptor.decrypt(encrypted_bytes).unwrap_or_default()).to_string();

    assert_eq!(original_text, decrypted_text);
}
