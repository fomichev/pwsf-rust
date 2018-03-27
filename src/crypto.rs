extern crate gcrypt;

pub struct HMAC {
    mac: self::gcrypt::mac::Mac,
}

impl HMAC {
    pub fn new(key: &[u8]) -> HMAC {
        use self::gcrypt::mac::{Mac, Algorithm};

        let mut h = Mac::new(Algorithm::HmacSha256).expect("Can't initialize HMAC");
        h.set_key(key).expect("Can't set HMAC key");

        return HMAC {mac: h};
    }

    pub fn update(&mut self, data: &[u8]) {
        self.mac.update(data).expect("Can't update HMAC");
    }

    pub fn verify(&mut self, expected: &[u8]) -> Result<(), gcrypt::Error> {
        return self.mac.verify(expected);
    }

    pub fn get_mac(&mut self) -> [u8; 32] {
        let mut output: [u8; 32] = [0; 32];
        self.mac.get_mac(&mut output).expect("Can't compute HMAC");
        return output;
    }
}

pub fn init() {
    gcrypt::init(|x| { x.disable_secmem(); });
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    use self::gcrypt::digest::{MessageDigest,Algorithm};

    let mut output: [u8; 32] = [0; 32];
    let mut h = MessageDigest::new(Algorithm::Sha256).expect("Can't initialize SHA256");
    h.update(&input);
    h.finish();
    output.copy_from_slice(h.get_only_digest().expect("Can't get SHA256 digest"));

    return output;
}

pub fn stretch(password: &str, salt: &[u8], iter: u32) -> [u8; 32] {
    use self::gcrypt::digest::{MessageDigest,Algorithm};

    let mut h = MessageDigest::new(Algorithm::Sha256).expect("Can't initialize SHA256");
    h.update(password.as_bytes());
    h.update(salt);
    h.finish();

    let mut b: [u8; 32] = [0; 32];
    b.copy_from_slice(h.get_only_digest().expect("Can't get SHA256 digest"));

    for _ in 0..iter {
        h.reset();
        h.update(&b);
        b.copy_from_slice(h.get_only_digest().expect("Can't get SHA256 digest"));
    }

    return b.clone();
}

pub fn decrypt_block_ecb(block: &[u8], key: &[u8]) -> Result<[u8; 32], gcrypt::Error> {
    use self::gcrypt::cipher::{Cipher, Algorithm, Mode};

    let mut ct: [u8; 32] = [0; 32];
    let mut c = Cipher::new(Algorithm::Twofish, Mode::Ecb).expect("Can't initialize ECB Twofish");
    c.set_key(&key).expect("Can't set ECB Twofish key");
    return match c.decrypt(&block, &mut ct) {
        Ok(_) => Ok(ct.clone()),
        Err(e) => Err(e),
    };
}

pub fn decrypt_inplace(data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), gcrypt::Error> {
    use self::gcrypt::cipher::{Cipher, Algorithm, Mode};

    let mut c = Cipher::new(Algorithm::Twofish, Mode::Cbc).expect("Can't initialize CBC Twofish");
    c.set_iv(iv).expect("Can't set CBC Twofish IV");
    c.set_key(key).expect("Can't set CBC Twofish key");
    return c.decrypt_inplace(data);
}

pub fn encrypt_block_ecb(block: &[u8], key: &[u8]) -> Result<[u8; 32], gcrypt::Error> {
    use self::gcrypt::cipher::{Cipher, Algorithm, Mode};

    let mut ct: [u8; 32] = [0; 32];
    let mut c = Cipher::new(Algorithm::Twofish, Mode::Ecb).expect("Can't initialize ECB Twofish");
    c.set_key(&key).expect("Can't set ECB Twofish key");
    return match c.encrypt(&block, &mut ct) {
        Ok(_) => Ok(ct.clone()),
        Err(e) => Err(e),
    };
}

pub fn encrypt_inplace(data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), gcrypt::Error> {
    use self::gcrypt::cipher::{Cipher, Algorithm, Mode};

    let mut c = Cipher::new(Algorithm::Twofish, Mode::Cbc).expect("Can't initialize CBC Twofish");
    c.set_iv(iv).expect("Can't set CBC Twofish IV");
    c.set_key(key).expect("Can't set CBC Twofish key");
    return c.encrypt_inplace(data);
}
