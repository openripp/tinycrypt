
part of tiny_crypt;


const TC_HMAC_PRNG_RESEED_REQ = -1;

class tc_hmac_prng_struct {
/* the HMAC instance for this PRNG */
  var h = tc_hmac_state_struct();

/* the PRNG key */
  var key = Uint8List(TC_SHA256_DIGEST_SIZE);

/* PRNG state */
  var v = Uint8List(TC_SHA256_DIGEST_SIZE);

/* calls to tc_hmac_prng_generate left before re-seed */
  late unsigned countdown;
}

typedef TCHmacPrng_t = tc_hmac_prng_struct;
