
part of tiny_crypt;


class tc_hmac_state_struct {
/* the internal state required by h */
  var hash_state = tc_sha256_state_struct();

/* HMAC key schedule */
  var key = Uint8List(2 * TC_SHA256_BLOCK_SIZE);

  void clear() {
    hash_state.clear();
    key.fill(0);
  }
}

typedef TCHmacState_t = tc_hmac_state_struct;


Uint8List hmac(Uint8List hash(Uint8List data), Uint8List key, Uint8List data) {
  var h = tc_hmac_state_struct();
  var digest = Uint8List(32);
  tc_hmac_set_key(h, key, sizeof(key));

  tc_hmac_init(h);
  tc_hmac_update(h, data, data.length);
  tc_hmac_final(digest, TC_SHA256_DIGEST_SIZE, h);
  return digest;
}
