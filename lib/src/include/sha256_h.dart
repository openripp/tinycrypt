
part of tiny_crypt;

const TC_SHA256_BLOCK_SIZE = (64);
const TC_SHA256_DIGEST_SIZE = (32);
const TC_SHA256_STATE_BLOCKS = (TC_SHA256_DIGEST_SIZE~/4);

class tc_sha256_state_struct {
  var iv = unsigned_int_List(TC_SHA256_STATE_BLOCKS);
  uint64_t bits_hashed = 0.to_uint64_t;
  var leftover = Uint8List(TC_SHA256_BLOCK_SIZE);
  size_t leftover_offset = 0;

  void clear() {
    iv = unsigned_int_List(TC_SHA256_STATE_BLOCKS);
    bits_hashed = 0.to_uint64_t;
    leftover = Uint8List(TC_SHA256_BLOCK_SIZE);
    leftover_offset = 0;
  }
}

typedef TCSha256State_t =  tc_sha256_state_struct;



Uint8List sha256(Uint8List data) {
  var digest = Uint8List(32);
  var s = tc_sha256_state_struct();

  tc_sha256_init(s);
  tc_sha256_update(s, data, sizeof(data));
  tc_sha256_final(digest, s);

  return digest;
}
