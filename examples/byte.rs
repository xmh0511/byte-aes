use byte_aes::Aes256Cryptor;
fn main() {
    let key = "c4ca4238a0b923820dcc509a6f75849b";
    let cryptor = Aes256Cryptor::try_from(key).unwrap();
    let buf: [u8; 4] = [1, 0, 0, 1];
    //let buf:[u8;16] = [1, 0, 0, 1, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 0];
    let encrypt_buf = cryptor.encrypt(buf);
    //println!("{encrypt_buf:?}");

    let clear_buf = cryptor.decrypt(encrypt_buf);
    println!("{clear_buf:?}"); // [1,1]

    let buf: [u8; 17] = [
        1, 0, 0, 1, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 0,
    ];
    let encrypt_buf = cryptor.encrypt(buf);
    //println!("{encrypt_buf:?}");

    let clear_buf = cryptor.decrypt(encrypt_buf);
    println!("{clear_buf:?}"); // [1,1]

    let buf = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 200]; // invalid data for decrypting
    let clear_buf = cryptor.decrypt(buf);
    println!("{clear_buf:?}");
}
