
part of tiny_crypt;

/* padding for last message block */

final TC_CMAC_PADDING = 0x80;

/* struct tc_cmac_struct represents the state of a CMAC computation */
class TCCmacState_t {
  /* initialization vector */
  Uint8List iv = Uint8List(TC_AES_BLOCK_SIZE);
  /* used if message length is a multiple of block_size bytes */
  Uint8List K1 = Uint8List(TC_AES_BLOCK_SIZE);
  /* used if message length isn't a multiple block_size bytes */
  Uint8List K2 = Uint8List(TC_AES_BLOCK_SIZE);
  /* where to put bytes that didn't fill a block */
  Uint8List leftover = Uint8List(TC_AES_BLOCK_SIZE);
  /* identifies the encryption key */
  late int keyid;
  /* next available leftover location */
  late int leftover_offset;
  /* AES key schedule */
  TCAesKeySched_t sched = TCAesKeySched_t();
  /* calls to tc_cmac_update left before re-key */
  int countdown = 0;

  setZero() {
    iv.fillZero();
    K1.fillZero();
    K2.fillZero();
    leftover.fillZero();
    keyid = 0;
    leftover_offset = 0;
    sched.words.fillZero();
    countdown = 0;
  }
}








/* max number of calls until change the key (2^48).*/
final Int64 MAX_CALLS = Int64(1) << 48;

/*
 *  gf_wrap -- In our implementation, GF(2^128) is represented as a 16 byte
 *  array with byte 0 the most significant and byte 15 the least significant.
 *  High bit carry reduction is based on the primitive polynomial
 *
 *                     X^128 + X^7 + X^2 + X + 1,
 *
 *  which leads to the reduction formula X^128 = X^7 + X^2 + X + 1. Indeed,
 *  since 0 = (X^128 + X^7 + X^2 + 1) mod (X^128 + X^7 + X^2 + X + 1) and since
 *  addition of polynomials with coefficients in Z/Z(2) is just XOR, we can
 *  add X^128 to both sides to get
 *
 *       X^128 = (X^7 + X^2 + X + 1) mod (X^128 + X^7 + X^2 + X + 1)
 *
 *  and the coefficients of the polynomial on the right hand side form the
 *  string 1000 0111 = 0x87, which is the value of gf_wrap.
 *
 *  This gets used in the following way. Doubling in GF(2^128) is just a left
 *  shift by 1 bit, except when the most significant bit is 1. In the latter
 *  case, the relation X^128 = X^7 + X^2 + X + 1 says that the high order bit
 *  that overflows beyond 128 bits can be replaced by addition of
 *  X^7 + X^2 + X + 1 <-. 0x87 to the low order 128 bits. Since addition
 *  in GF(2^128) is represented by XOR, we therefore only have to XOR 0x87
 *  into the low order byte after a left shift when the starting high order
 *  bit is 1.
 */
final int gf_wrap = 0x87;

/*
 *  assumes: out != NULL and points to a GF(2^n) value to receive the
 *            doubled value;
 *           in != NULL and points to a 16 byte GF(2^n) value
 *            to double;
 *           the in and out buffers do not overlap.
 *  effects: doubles the GF(2^n) value pointed to by "in" and places
 *           the result in the GF(2^n) value pointed to by "out."
 */
void gf_double(Uint8List out, Uint8List inData) {

  /* start with low order byte */
  int xOffs = TC_AES_BLOCK_SIZE - 1;

  /* if msb == 1, we need to add the gf_wrap value, otherwise add 0 */
  int carry = (inData[0] >> 7) != 0 ? gf_wrap : 0;

  int outOffs = (TC_AES_BLOCK_SIZE - 1);

  for (;;) {
    out[outOffs--] = (inData[xOffs] << 1) ^ carry;
    if (xOffs == 0) {
      break;
    }
    carry = inData[xOffs--] >> 7;
  }
}

int tc_cmac_setup(TCCmacState_t s, final Uint8List key, TCAesKeySched_t sched) {

  /* input sanity check: */
  if (s == null ||
      key == null) {
    return TC_CRYPTO_FAIL;
  }

  /* put s into a known state */
  s.setZero();
  s.sched = sched;

  /* configure the encryption key used by the underlying block cipher */
  tc_aes128_set_encrypt_key(s.sched, key);

  /* compute s.K1 and s.K2 from s.iv using s.keyid */
  _set(s.iv, 0, TC_AES_BLOCK_SIZE);
  tc_aes_encrypt(s.iv, s.iv, s.sched);
  gf_double(s.K1, s.iv);
  gf_double(s.K2, s.K1);

  /* reset s.iv to 0 in case someone wants to compute now */
  tc_cmac_init(s);

  return TC_CRYPTO_SUCCESS;
}

int tc_cmac_erase(TCCmacState_t s)
{
  if (s == null) {
    return TC_CRYPTO_FAIL;
  }

  /* destroy the current state */
  s.setZero();

  return TC_CRYPTO_SUCCESS;
}

int tc_cmac_init(TCCmacState_t s) {
  /* input sanity check: */
  if (s == null) {
    return TC_CRYPTO_FAIL;
  }

  /* CMAC starts with an all zero initialization vector */
  _set(s.iv, 0, TC_AES_BLOCK_SIZE);

  /* and the leftover buffer is empty */
  _set(s.leftover, 0, TC_AES_BLOCK_SIZE);
  s.leftover_offset = 0;

  /* Set countdown to max number of calls allowed before re-keying: */
  s.countdown = MAX_CALLS.toInt();

  return TC_CRYPTO_SUCCESS;
}

int tc_cmac_update(TCCmacState_t s, Uint8List data, int data_length) {
  int i;

  /* input sanity check: */
  if (s == null) {
    return TC_CRYPTO_FAIL;
  }
  if (data_length == 0) {
    return TC_CRYPTO_SUCCESS;
  }
  if (data == null) {
    return TC_CRYPTO_FAIL;
  }

  if (s.countdown == 0) {
    return TC_CRYPTO_FAIL;
  }

  s.countdown--;

  int dataOffs = 0;
  if (s.leftover_offset > 0) {
    /* last data added to s didn't end on a TC_AES_BLOCK_SIZE byte boundary */
    int remaining_space = TC_AES_BLOCK_SIZE - s.leftover_offset;

    if (data_length < remaining_space) {
      /* still not enough data to encrypt this time either */
      _copy(s.leftover.subView(s.leftover_offset), data_length, data.subView(dataOffs),
          data_length);
      s.leftover_offset += data_length;
      return TC_CRYPTO_SUCCESS;
    }
    /* leftover block is now full; encrypt it first */
    _copy(s.leftover.subView(s.leftover_offset),
        remaining_space,
        data.subView(dataOffs),
        remaining_space);
    data_length -= remaining_space;
    dataOffs += remaining_space;
    s.leftover_offset = 0;

    for (i = 0; i < TC_AES_BLOCK_SIZE; ++i) {
      s.iv[i] ^= s.leftover[i];
    }
    tc_aes_encrypt(s.iv, s.iv, s.sched);
  }

  /* CBC encrypt each (except the last) of the data blocks */
  while (data_length > TC_AES_BLOCK_SIZE) {
    for (i = 0; i < TC_AES_BLOCK_SIZE; ++i) {
      s.iv[i] ^= data[dataOffs + i];
    }
    tc_aes_encrypt(s.iv, s.iv, s.sched);
    dataOffs += TC_AES_BLOCK_SIZE;
    data_length -= TC_AES_BLOCK_SIZE;
  }

  if (data_length > 0) {
    /* save leftover data for next time */
    _copy(s.leftover, data_length, data.subView(dataOffs), data_length);
    s.leftover_offset = data_length;
  }

  return TC_CRYPTO_SUCCESS;
}

int tc_cmac_final(Uint8List tag, TCCmacState_t s) {
  Uint8List k;
  int i;

  /* input sanity check: */
  if (tag == null ||
      s == null) {
    return TC_CRYPTO_FAIL;
  }

  if (s.leftover_offset == TC_AES_BLOCK_SIZE) {
    /* the last message block is a full-sized block */
    k = s.K1;
  } else {
    /* the final message block is not a full-sized  block */
    int remaining = TC_AES_BLOCK_SIZE - s.leftover_offset;

    _set(s.leftover.subView(s.leftover_offset), 0, remaining);
    s.leftover[s.leftover_offset] = TC_CMAC_PADDING;
    k = s.K2;
  }
  for (i = 0; i < TC_AES_BLOCK_SIZE; ++i) {
    s.iv[i] ^= s.leftover[i] ^ k[i];
  }

  tc_aes_encrypt(tag, s.iv, s.sched);

  /* erasing state: */
  tc_cmac_erase(s);

  return TC_CRYPTO_SUCCESS;
}
