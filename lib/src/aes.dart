part of tiny_crypt;

enum CipherType {
  ecb,
  cbc,
  ccm,
  ctr,
  cbcHmac,
}

enum CipherMacType {
  cmac,
}

class AesCipher {
  Uint8List   key;
  CipherType  type;

  AesCipher(this.key, this.type);

  Uint8List encrypt(Uint8List data, Uint8List? nonce, { Uint8List? aad, int? micSize, bool? aadIncludeNonce, }) {
    switch(type) {
      case CipherType.ecb: return aesEcbEncrypt(key, data);
      case CipherType.cbc: return aesCbcEncrypt(key, nonce!, data);
      case CipherType.ctr: return aesCtrMode(key, nonce!, data);
      case CipherType.ccm: return aesCcmEncrypt(key, nonce!, aad, data, micSize!);
      case CipherType.cbcHmac: return aesCbcHMacEncrypt(key, nonce!, aad!, data, micSize!, aadIncludeNonce: aadIncludeNonce);

      default: throw new UnsupportedError("cipher not support: $type");
    }
  }

  Uint8List decrypt(Uint8List data, Uint8List? nonce, { Uint8List? aad, int? micSize, bool? aadIncludeNonce,  }) {
    switch(type) {
      case CipherType.ecb: return aesEcbDecrypt(key, data);
      case CipherType.cbc: return aesCbcDecrypt(key, nonce!, data);
      case CipherType.ctr: return aesCtrMode(key, nonce!, data);
      case CipherType.ccm: return aesCcmDecrypt(key, nonce!, aad, data, micSize!);
      case CipherType.cbcHmac: return aesCbcHMacDecrypt(key, nonce!, aad!, data, micSize!, aadIncludeNonce: aadIncludeNonce);

      default: throw new UnsupportedError("cipher not support: $type");
    }
  }
}

class PkcsPadding {

  static Uint8List pkcs7(Uint8List bytes) {
    var padding = TC_AES_BLOCK_SIZE - bytes.length % TC_AES_BLOCK_SIZE;
    // Log.d(_TAG, () => 'padding: $padding, length: ${bytes.length.hex}');
    return ByteUtils.concatAll([bytes, Uint8List(padding)..fill(padding)]);
  }

  static Uint8List pkcs7Remove(Uint8List bytes) {
    return bytes.sublist(0, bytes.length - bytes[bytes.length - 1]);
  }

}

class AesMac {
  Uint8List       key;
  CipherMacType   type;

  AesMac(this.key, this.type);

  Uint8List mac(Uint8List data) {
    if (type != CipherMacType.cmac)
      throw UnsupportedError("only support aes-cmac now.");

    TCCmacState_t state = TCCmacState_t();
    TCAesKeySched_t sched = TCAesKeySched_t();

    if (tc_cmac_setup(state, key, sched) != TC_CRYPTO_SUCCESS)
      throw CryptoError("tc_cmac_setup error");

    const CMAC_LEN = TC_AES_BLOCK_SIZE;
    Uint8List tag = Uint8List(CMAC_LEN);

    if (tc_cmac_init(state) != TC_CRYPTO_SUCCESS)
      throw CryptoError("tc_cmac_init error");

    if (tc_cmac_update(state, data, data.length) != TC_CRYPTO_SUCCESS)
      throw CryptoError("tc_cmac_update error");

    if (tc_cmac_final(tag, state) != TC_CRYPTO_SUCCESS)
      throw CryptoError("tc_cmac_final error");

    if (logCrypto) Log.d(_TAG, () => "AesMac key: ${key.hexString()}, type: $type, data: ${data.hexString()}, tag: ${tag.hexString()}.");

    return tag;
  }
}

void _checkEcbParam(Uint8List key, Uint8List data) {
  if (key.length != TC_AES_KEY_SIZE)
    throw CryptoError('AES/ECB key length should be $TC_AES_KEY_SIZE, not: ${key.length}.');

  if (data.length != TC_AES_BLOCK_SIZE)
    throw CryptoError('AES/ECB data length should be $TC_AES_BLOCK_SIZE, not: ${data.length}.');
}

void _checkCtrParam(Uint8List key, Uint8List nonce, Uint8List data) {
  if (key.length != TC_AES_KEY_SIZE)
    throw CryptoError('AES/CTR key length should be $TC_AES_KEY_SIZE, not: ${key.length}.');

  if (nonce.length != TC_AES_BLOCK_SIZE)
    throw CryptoError('AES/CTR data length should be $TC_AES_BLOCK_SIZE, not: ${data.length}.');
}

void _checkCbcParam(Uint8List key, Uint8List nonce, Uint8List data) {
  if (key.length != TC_AES_KEY_SIZE)
    throw CryptoError('AES/CBC key length should be $TC_AES_KEY_SIZE, not: ${key.length}.');

  if (nonce.length != TC_AES_KEY_SIZE)
    throw CryptoError('AES/CBC nonce length should be $TC_AES_KEY_SIZE, not: ${nonce.length}.');

  if (data.length % TC_AES_BLOCK_SIZE != 0)
    throw CryptoError('AES/CBC data length should be ${TC_AES_BLOCK_SIZE}X, not: ${data.length}.');
}

void _checkCcmParam(Uint8List key, Uint8List nonce, Uint8List? hdr, Uint8List data, int micSize) {
  if (key.length != TC_AES_KEY_SIZE)
    throw CryptoError('AES/CCM key length should be $TC_AES_KEY_SIZE, not: ${key.length}.');

  if (nonce.length != 13)
    throw CryptoError('AES/CCM nonce length should be 13, not: ${nonce.length}.');

  const availSize = [4,6,8,10,12];
  if (!availSize.contains(micSize))
    throw CryptoError('AES/CCM data length should be 4/6/8/10/12, not: ${micSize}.');
}

bool logCrypto = false;

Uint8List aesCcmEncrypt(Uint8List key, Uint8List nonce, Uint8List? hdr, Uint8List data, int micSize) {
  TCCcmMode_t       mode = TCCcmMode_t();
  TCAesKeySched_t   schd = TCAesKeySched_t();

  if (tc_aes128_set_encrypt_key(schd, key) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_aes128_set_encrypt_key error");

  if (tc_ccm_config(mode, schd, nonce, nonce.length, micSize) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_ccm_config error");

  Uint8List ciphertext = Uint8List(data.length + micSize);

  if (tc_ccm_generation_encryption(ciphertext, ciphertext.length, hdr, hdr?.length ?? 0, data, data.length, mode) != TC_CRYPTO_SUCCESS) {
    if (logCrypto) Log.e(_TAG, () => "aesCcmEncrypt error: key: ${key.hexString()}, nonce: ${nonce.hexString()}, aad: ${hdr?.hex}, data: ${data.hexString()}, micSize: $micSize, ciphertext: ${ciphertext.hexString()}.");

    throw CryptoError("tc_ccm_generation_encryption error");
  }

  if (logCrypto)
    Log.d(_TAG, () => "aesCcmEncrypt: key: ${key.hexString()}, nonce: ${nonce.hex}, aad: ${hdr?.hexString()}, data: ${data.hexString()}, micSize: $micSize, ciphertext: ${ciphertext.hexString()}.");

  return ciphertext;
}

Uint8List aesCcmDecrypt(Uint8List key, Uint8List nonce, Uint8List? hdr, Uint8List data, int micSize) {
  TCCcmMode_t       mode = TCCcmMode_t();
  TCAesKeySched_t   schd = TCAesKeySched_t();

  _checkCcmParam(key, nonce, hdr, data, micSize);

  if (tc_aes128_set_decrypt_key(schd, key) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_aes128_set_decrypt_key error");

  if (tc_ccm_config(mode, schd, nonce, nonce.length, micSize) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_ccm_config error");

  Uint8List plain = Uint8List(data.length - micSize);

  if (tc_ccm_decryption_verification(plain, plain.length, hdr, hdr?.length ?? 0, data, data.length, mode) != TC_CRYPTO_SUCCESS) {
    if (logCrypto) Log.e(_TAG, () => "aesCcmDecrypt error: key: ${key.hexString()}, nonce: ${nonce.hexString()}, aad: ${hdr?.hex}, micSize: $micSize, ciphertext: ${data.hexString()}.");

    throw CryptoError("tc_ccm_decryption_verification error");
  }

  if (logCrypto)
    Log.d(_TAG, () => "aesCcmDecrypt: key: ${key.hexString()}, nonce: ${nonce.hexString()}, aad: ${hdr?.hex}, data: ${plain.hexString()}, micSize: $micSize, ciphertext: ${data.hexString()}.");

  return plain;
}

Uint8List aesCbcHMacEncrypt(Uint8List key, Uint8List nonce, Uint8List hdr, Uint8List data, int micSize, { bool? aadIncludeNonce, }) {
  var keyHash = sha256(key);
  var keyE = keyHash.sublist(0, TC_AES_KEY_SIZE);
  var keyM = keyHash.sublist(TC_AES_KEY_SIZE, TC_AES_KEY_SIZE*2);

  data = PkcsPadding.pkcs7(data);
  var enc = aesCbcEncrypt(keyE, nonce, data);
  var mic = hmac(sha256, keyM, ByteUtils.concatAll([if (aadIncludeNonce != true) nonce, hdr, enc]));

  mic = mic.sublist(0, micSize);

  if (logCrypto)
    Log.d(_TAG, () => "aesCbcHMacEncrypt: key: ${key.hexString()}/E:${keyE.hex}/M:${keyM.hex}, nonce: ${nonce.hexString()}, aad: ${hdr.hexString()}, data: ${data.hexString()}, micSize: $micSize, mic: ${mic.hex}, ciphertext: ${enc.hexString()}.");

  return ByteUtils.concatAll([enc, mic]);
}

Uint8List aesCbcHMacDecrypt(Uint8List key, Uint8List nonce, Uint8List hdr, Uint8List data, int micSize, { bool? aadIncludeNonce, }) {
  var keyHash = sha256(key);
  var keyE = keyHash.sublist(0, TC_AES_KEY_SIZE);
  var keyM = keyHash.sublist(TC_AES_KEY_SIZE, TC_AES_KEY_SIZE*2);

  var enc = data.sublist(0, data.length - micSize);
  var mic = data.sublist(data.length - micSize);

  var hash = hmac(sha256, keyM, ByteUtils.concatAll([if (aadIncludeNonce != true) nonce, hdr, enc])).bytes.bytes;
  hash = hash.sublist(0, micSize);

  if (!hash.equals(mic)) {
    if (logCrypto)
      Log.e(_TAG, () => "aesCbcHMacDecrypt: key: ${key.hexString()}/E:${keyE.hex}/M:${keyM.hex}, nonce: ${nonce.hexString()}, aad: ${hdr.hexString()}, mic: ${mic.hex}, calcMic: ${hash.hex}.");

    throw CryptoError('Aes/Cbc HMac mic not match');
  }

  var dec = aesCbcDecrypt(keyE, nonce, enc);
  dec = PkcsPadding.pkcs7Remove(dec);

  if (logCrypto)
    Log.d(_TAG, () => "aesCbcHMacDecrypt: key: ${key.hexString()}/E:${keyE.hex}/M:${keyM.hex}, nonce: ${nonce.hexString()}, aad: ${hdr.hexString()}, mic: ${mic.hex}, ciphertext: ${dec.hex}.");

  return dec;
}

Uint8List aesEcbEncrypt(Uint8List key, Uint8List data) {
  TCAesKeySched_t   schd = TCAesKeySched_t();

  _checkEcbParam(key, data);

  if (tc_aes128_set_encrypt_key(schd, key) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_aes128_set_encrypt_key error");

  Uint8List ciphertext = Uint8List(data.length);

  if (tc_aes_encrypt(ciphertext, data, schd) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_ecb_mode_encrypt error");

  if (logCrypto)
    Log.d(_TAG, () => "aesEcbEncrypt: key: ${key.hexString()}, data: ${data.hexString()}, ciphertext: ${ciphertext.hexString()}.");

  return ciphertext;
}

Uint8List aesEcbDecrypt(Uint8List key, Uint8List data) {
  TCAesKeySched_t   schd = TCAesKeySched_t();

  _checkEcbParam(key, data);

  if (tc_aes128_set_decrypt_key(schd, key) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_aes128_set_decrypt_key error");

  Uint8List plain = Uint8List(data.length);

  if (tc_aes_decrypt(plain, data, schd) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_ecb_mode_decrypt error");

  if (logCrypto)
    Log.d(_TAG, () => "aesCbcDecrypt: key: ${key.hexString()}, data: ${plain.hexString()}, ciphertext: ${data.hexString()}.");

  return plain;
}

Uint8List aesCbcEncrypt(Uint8List key, Uint8List nonce, Uint8List data) {
  TCAesKeySched_t   schd = TCAesKeySched_t();

  _checkCbcParam(key, nonce, data);
  
  if (tc_aes128_set_encrypt_key(schd, key) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_aes128_set_encrypt_key error");

  Uint8List ciphertext = Uint8List(data.length + TC_AES_BLOCK_SIZE);

  if (tc_cbc_mode_encrypt(ciphertext, ciphertext.length, data, data.length, nonce, schd) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_cbc_mode_encrypt error");

  ciphertext = ciphertext.sublist(nonce.length);

  if (logCrypto)
    Log.d(_TAG, () => "aesCbcEncrypt: key: ${key.hexString()}, nonce: ${nonce.hexString()}, data: ${data.hexString()}, ciphertext: ${ciphertext.hexString()}.");

  return ciphertext;
}

Uint8List aesCbcDecrypt(Uint8List key, Uint8List nonce, Uint8List data) {
  TCAesKeySched_t   schd = TCAesKeySched_t();

  _checkCbcParam(key, nonce, data);

  if (tc_aes128_set_decrypt_key(schd, key) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_aes128_set_decrypt_key error");

  Uint8List plain = Uint8List(data.length);

  if (tc_cbc_mode_decrypt(plain, plain.length, data, data.length, nonce, schd) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_cbc_mode_decrypt error");

  if (logCrypto)
    Log.d(_TAG, () => "aesCbcDecrypt: key: ${key.hexString()}, nonce: ${nonce.hexString()}, data: ${plain.hexString()}, ciphertext: ${data.hexString()}.");

  return plain;
}


Uint8List aesCtrMode(Uint8List key, Uint8List nonce, Uint8List data) {
  TCAesKeySched_t   schd = TCAesKeySched_t();

  _checkCtrParam(key, nonce, data);

  if (tc_aes128_set_encrypt_key(schd, key) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_aes128_set_encrypt_key error");

  Uint8List result = Uint8List(data.length);

  if (tc_ctr_mode(result, result.length, data, data.length, nonce, schd) != TC_CRYPTO_SUCCESS)
    throw CryptoError("tc_ctr_mode_encrypt error");

  if (logCrypto)
    Log.d(_TAG, () => "aesCtrEncrypt: key: ${key.hexString()}, nonce: ${nonce.hexString()}, data: ${data.hexString()}, result: ${result.hexString()}.");

  return result;
}

