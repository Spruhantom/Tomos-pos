use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};

fn cipher() -> Result<Aes256Gcm, &'static str> {
    let key = std::env::var("TOMOS_INTEGRATION_ENCRYPTION_KEY")
        .map_err(|_| "integration encryption key is not configured")?;
    let bytes = hex::decode(key).map_err(|_| "integration encryption key must be 64 hex characters")?;
    if bytes.len() != 32 {
        return Err("integration encryption key must be 32 bytes");
    }
    Aes256Gcm::new_from_slice(&bytes).map_err(|_| "integration encryption key is invalid")
}

pub fn encrypt(plaintext: &str) -> Result<String, &'static str> {
    let cipher = cipher()?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| "integration credential encryption failed")?;
    let mut payload = nonce_bytes.to_vec();
    payload.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(payload))
}

pub fn decrypt(encoded: &str) -> Result<String, &'static str> {
    let cipher = cipher()?;
    let payload = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "stored integration credential is invalid")?;
    if payload.len() < 13 {
        return Err("stored integration credential is invalid");
    }
    let (nonce, ciphertext) = payload.split_at(12);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "stored integration credential could not be decrypted")?;
    String::from_utf8(plaintext).map_err(|_| "stored integration credential is invalid")
}
