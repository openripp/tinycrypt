part of tiny_crypt;

int tc_ccm_config(TCCcmMode_t c, TCAesKeySched_t sched, Uint8List nonce,
  int nlen, int mlen) {

  /* input sanity check: */
  if (c == null ||
      sched == null ||
      nonce == null) {
    return TC_CRYPTO_FAIL;
  } else if (nlen != 13) {
    return TC_CRYPTO_FAIL; /* The allowed nonce size is: 13. See documentation.*/
  } else if ((mlen < 4) || (mlen > 16) || (mlen & 1) != 0) {
    return TC_CRYPTO_FAIL; /* The allowed mac sizes are: 4, 6, 8, 10, 12, 14, 16.*/
  }

  c.mlen = mlen;
  c.sched = sched;
  c.nonce = nonce;

  return TC_CRYPTO_SUCCESS;
}

/**
 * Variation of CBC-MAC mode used in CCM.
 */
void ccm_cbc_mac(Uint8List T, Uint8List data, int dlen,
  int flag, TCAesKeySched_t sched) {
  int i;

  if (flag > 0) {
    T[0] ^= (dlen >> 8);
    T[1] ^= (dlen);
    dlen += 2;
    i = 2;
  } else {
    i = 0;
  }


  int dOffs = 0;

  while (i < dlen) {
    T[i++ % (Nb * Nk)] ^= data[dOffs++];

    if (((i % (Nb * Nk)) == 0) || dlen == i) {
      tc_aes_encrypt(T, T, sched);
    }
  }
}

/**
 * Variation of CTR mode used in CCM.
 * The CTR mode used by CCM is slightly different than the conventional CTR
 * mode (the counter is increased before encryption, instead of after
 * encryption). Besides, it is assumed that the counter is stored in the last
 * 2 bytes of the nonce.
 */
int ccm_ctr_mode(Uint8List out, int outlen, final Uint8List inData,
int inlen, Uint8List ctr, final TCAesKeySched_t sched) {
  Uint8List buffer = Uint8List(TC_AES_BLOCK_SIZE);
  Uint8List nonce = Uint8List(TC_AES_BLOCK_SIZE);
  int block_num;

  int i;

  /* input sanity check: */
  if (out == null ||
      inData == null ||
      ctr == null ||
      sched == null ||
      inlen == 0 ||
      outlen == 0 ||
      outlen != inlen) {
    return TC_CRYPTO_FAIL;
  }

  /* copy the counter to the nonce */
  _copy(nonce, nonce.length, ctr, nonce.length);

  var oOffs = 0,
      iOffs = 0;
  /* select the last 2 bytes of the nonce to be incremented */
  block_num = ((nonce[14] << 8) | (nonce[15])) & 0xFFFF;
  for (i = 0; i < inlen; ++i) {
    if ((i % (TC_AES_BLOCK_SIZE)) == 0) {
      block_num++;
      nonce[14] = (block_num >> 8) & 0xFF;
      nonce[15] = (block_num) & 0xFF;
      if (tc_aes_encrypt(buffer, nonce, sched) != TC_CRYPTO_SUCCESS) {
        return TC_CRYPTO_FAIL;
      }
    }
    /* update the output */
    out[oOffs++] = buffer[i % (TC_AES_BLOCK_SIZE)] ^ inData[iOffs++];
  }

  /* update the counter */
  ctr[14] = nonce[14];
  ctr[15] = nonce[15];

  return TC_CRYPTO_SUCCESS;
}

int tc_ccm_generation_encryption(Uint8List out, int olen,
final Uint8List? associated_data,
int alen, final Uint8List payload,
int plen, TCCcmMode_t c) {
  /* input sanity check: */
  if ((out == null) ||
      (c == null) ||
      ((plen > 0) && (payload == null)) ||
      ((alen > 0) && (associated_data == null)) ||
      (alen >= TC_CCM_AAD_MAX_BYTES) || /* associated data size unsupported */
      (plen >= TC_CCM_PAYLOAD_MAX_BYTES) || /* payload size unsupported */
      (olen < (plen + c.mlen))) {
    /* invalid output buffer size */
    return TC_CRYPTO_FAIL;
  }

  Uint8List b = Uint8List(Nb * Nk);
  Uint8List tag = Uint8List(Nb * Nk);
  int i;

  /* GENERATING THE AUTHENTICATION TAG: */

  /* formatting the sequence b for authentication: */
  b[0] = ((alen > 0) ? 0x40 : 0) | ((((c.mlen - 2) ~/ 2) << 3)) | (1);
  for (i = 1; i <= 13; ++i) {
    b[i] = c.nonce[i - 1];
  }
  b[14] = (plen >> 8) & 0xFF;
  b[15] = (plen) & 0xFF;

  /* computing the authentication tag using cbc-mac: */
  tc_aes_encrypt(tag, b, c.sched);
  if (alen > 0) {
    ccm_cbc_mac(tag, associated_data!, alen, 1, c.sched);
  }
  if (plen > 0) {
    ccm_cbc_mac(tag, payload, plen, 0, c.sched);
  }

  /* ENCRYPTION: */

  /* formatting the sequence b for encryption: */
  b[0] = 1; /* q - 1 = 2 - 1 = 1 */
  b[14] = b[15] = TC_ZERO_BYTE;

  /* encrypting payload using ctr mode: */
  ccm_ctr_mode(out, plen, payload, plen, b, c.sched);

  b[14] = b[15] = TC_ZERO_BYTE; /* restoring initial counter for ctr_mode (0):*/

  /* encrypting b and adding the tag to the output: */
  tc_aes_encrypt(b, b, c.sched);

  int oOffs = plen;
  for (i = 0; i < c.mlen; ++i) {
    out[oOffs++] = tag[i] ^ b[i];
  }

  return TC_CRYPTO_SUCCESS;
}

int tc_ccm_decryption_verification(Uint8List out, int olen,
final Uint8List? associated_data,
int alen, final Uint8List payload,
int plen, TCCcmMode_t c) {

  /* input sanity check: */
  if ((out == null) ||
      (c == null) ||
      ((plen > 0) && (payload == null)) ||
      ((alen > 0) && (associated_data == null)) ||
      (alen >= TC_CCM_AAD_MAX_BYTES) || /* associated data size unsupported */
      (plen >= TC_CCM_PAYLOAD_MAX_BYTES) || /* payload size unsupported */
      (olen < plen - c.mlen)) {
    /* invalid output buffer size */
    return TC_CRYPTO_FAIL;
  }

  Uint8List b = Uint8List(Nb * Nk);
  Uint8List tag = Uint8List(Nb * Nk);
  int i;

  /* DECRYPTION: */

  /* formatting the sequence b for decryption: */
  b[0] = 1; /* q - 1 = 2 - 1 = 1 */
  for (i = 1; i < 14; ++i) {
    b[i] = c.nonce[i - 1];
  }
  b[14] = b[15] = TC_ZERO_BYTE; /* initial counter value is 0 */

  /* decrypting payload using ctr mode: */
  ccm_ctr_mode(out, plen - c.mlen, payload, plen - c.mlen, b, c.sched);

  b[14] = b[15] = TC_ZERO_BYTE; /* restoring initial counter value (0) */

  /* encrypting b and restoring the tag from input: */
  tc_aes_encrypt(b, b, c.sched);
  for (i = 0; i < c.mlen; ++i) {
    tag[i] = payload[plen - c.mlen + i] ^ b[i];
  }

  /* VERIFYING THE AUTHENTICATION TAG: */

  /* formatting the sequence b for authentication: */
  b[0] = ((alen > 0) ? 0x40 : 0) | ((((c.mlen - 2) ~/ 2) << 3)) | (1);
  for (i = 1; i < 14; ++i) {
    b[i] = c.nonce[i - 1];
  }
  b[14] = ((plen - c.mlen) >> 8) & 0xFF;
  b[15] = (plen - c.mlen) & 0xFF;

  /* computing the authentication tag using cbc-mac: */
  tc_aes_encrypt(b, b, c.sched);
  if (alen > 0) {
    ccm_cbc_mac(b, associated_data!, alen, 1, c.sched);
  }
  if (plen > 0) {
    ccm_cbc_mac(b, out, plen - c.mlen, 0, c.sched);
  }

  /* comparing the received tag and the computed one: */
  if (_compare(b, tag, c.mlen) == 0) {
    return TC_CRYPTO_SUCCESS;
  } else {
    /* erase the decrypted buffer in case of mac validation failure: */
    _set(out, 0, plen - c.mlen);
    return TC_CRYPTO_FAIL;
  }
}

