
part of tiny_crypt;

typedef int8_t = int;
typedef uint8_t = int;
typedef int16_t = int;
typedef uint64_t = Int64;
typedef unsigned = int;
typedef size_t = int;
typedef uint32_t = int;

const UINT32_MAX = 4294967295;


const Nb = 4;  /* number of columns (32-bit words) comprising the state */
const Nk = 4;  /* number of 32-bit words comprising the key */
const Nr = 10; /* number of rounds */
const TC_AES_BLOCK_SIZE = (Nb*Nk);
const TC_AES_KEY_SIZE = (Nb*Nk);

class TCAesKeySched_t {
  Uint32List words = Uint32List(Nb*(Nr+1));
}

typedef tc_aes_key_sched_struct = TCAesKeySched_t;

/* max additional authenticated size in bytes: 2^16 - 2^8 = 65280 */
const TC_CCM_AAD_MAX_BYTES = 0xff00;

/* max message size in bytes: 2^(8L) = 2^16 = 65536 */
const TC_CCM_PAYLOAD_MAX_BYTES = 0x10000;

/* struct tc_ccm_mode_struct represents the state of a CCM computation */
class TCCcmMode_t {
  late TCAesKeySched_t sched; /* AES key schedule */
  late Uint8List nonce; /* nonce required by CCM */
  late int mlen; /* mac length in bytes (parameter t in SP-800 38C) */
}



const TC_CRYPTO_SUCCESS = 1;
const TC_CRYPTO_FAIL = 0;

const TC_ZERO_BYTE = 0x00;
