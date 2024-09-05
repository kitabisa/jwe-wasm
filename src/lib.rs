use wasm_bindgen::prelude::*;
use biscuit::Empty;
use biscuit::jwk::JWK;
use biscuit::jwe;
use biscuit::jwa::{EncryptionOptions, KeyManagementAlgorithm, ContentEncryptionAlgorithm};
use num_bigint::BigUint;
use base64;
use serde_json;

#[wasm_bindgen]
pub fn encrypt(payload: &str, key: &str) -> Result<JsValue, JsValue> {
  let jwk_key: JWK<Empty> = serde_json::from_str(key).map_err(|e| e.to_string())?;
  
  let jwe = jwe::Compact::new_decrypted(
    From::from(jwe::RegisteredHeader {
      cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
      enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
      ..Default::default()
    }),
    payload.as_bytes().to_vec(),
  );

  let nonce_counter = BigUint::from_bytes_le(&vec![0; 96 / 8]);
  assert!(nonce_counter.bits() <= 96);
  let mut nonce_bytes = nonce_counter.to_bytes_le();
  nonce_bytes.resize(96 / 8, 0);
  let options = EncryptionOptions::AES_GCM { nonce: nonce_bytes };

  let encrypted_jwe = jwe.encrypt(&jwk_key, &options).map_err(|e| e.to_string())?;
  let encrypted_jwe_str = serde_json::to_string(&encrypted_jwe).map_err(|e| e.to_string())?;
  let encrypted_jwe_base64 = base64::encode(&encrypted_jwe_str);

  Ok(JsValue::from_str(&encrypted_jwe_base64))
}

#[wasm_bindgen]
pub fn decrypt(encrypted_jwe: &str, key: &str) -> Result<String, JsValue> {
  let encrypted_jwe_str = base64::decode(encrypted_jwe).map_err(|e| e.to_string())?;
  let encrypted_jwe_json = String::from_utf8(encrypted_jwe_str).map_err(|e| e.to_string())?;
  
  let jwk_key: JWK<Empty> = serde_json::from_str(key).map_err(|e| e.to_string())?;
  let encrypted_jwe: jwe::Compact<Vec<u8>, Empty> = serde_json::from_str(&encrypted_jwe_json).map_err(|e| e.to_string())?;

  let decrypted_jwe = encrypted_jwe
    .decrypt(
      &jwk_key,
      KeyManagementAlgorithm::A256GCMKW,
      ContentEncryptionAlgorithm::A256GCM,
    )
    .map_err(|e| e.to_string())?;

  let decrypted_payload: &Vec<u8> = decrypted_jwe.payload().unwrap();
  let decrypted_str = std::str::from_utf8(&*decrypted_payload).map_err(|e| e.to_string())?;
  
  Ok(decrypted_str.to_string())
}
