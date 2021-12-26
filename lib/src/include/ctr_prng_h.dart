
part of tiny_crypt;

const TC_CTR_PRNG_RESEED_REQ = -1;

class TCCtrPrng_t {
/* updated each time another BLOCKLEN_BYTES bytes are produced */
var V = Uint8List(TC_AES_BLOCK_SIZE);

/* updated whenever the PRNG is reseeded */
var key = tc_aes_key_sched_struct();

/* number of requests since initialization/reseeding */
var reseedCount = 0.to_uint64_t;
}