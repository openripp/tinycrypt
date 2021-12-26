part of tiny_crypt;

int tc_cbc_mode_encrypt(Uint8List out, int outlen, final Uint8List inData,
    int inlen, final Uint8List iv,
    final TCAesKeySched_t sched) {
  Uint8List buffer = Uint8List(TC_AES_BLOCK_SIZE);
  int n, m;

  /* input sanity check: */
  if (out == null ||
      inData == null ||
      sched == null ||
      inlen == 0 ||
      outlen == 0 ||
      (inlen % TC_AES_BLOCK_SIZE) != 0 ||
      (outlen % TC_AES_BLOCK_SIZE) != 0 ||
      outlen != inlen + TC_AES_BLOCK_SIZE) {
    return TC_CRYPTO_FAIL;
  }

  /* copy iv to the buffer */
  _copy(buffer, TC_AES_BLOCK_SIZE, iv, TC_AES_BLOCK_SIZE);
  /* copy iv to the output buffer */
  _copy(out, TC_AES_BLOCK_SIZE, iv, TC_AES_BLOCK_SIZE);

  var outOffs = TC_AES_BLOCK_SIZE;
  var inOffs = 0;

  for (n = m = 0; n < inlen; ++n) {
    buffer[m++] ^= inData[inOffs++];
    if (m == TC_AES_BLOCK_SIZE) {
      tc_aes_encrypt(buffer, buffer, sched);
      _copy(out.subView(outOffs), TC_AES_BLOCK_SIZE,
          buffer, TC_AES_BLOCK_SIZE);
      outOffs += TC_AES_BLOCK_SIZE;
      m = 0;
    }
  }

  return TC_CRYPTO_SUCCESS;
}

int tc_cbc_mode_decrypt(Uint8List out, int outlen, Uint8List inData,
int inlen, Uint8List iv,
final TCAesKeySched_t sched) {
  Uint8List buffer = Uint8List(TC_AES_BLOCK_SIZE);
  Uint8List p;
  int n, m;

  /* sanity check the inputs */
  if (out == null ||
      inData == null ||
      sched == null ||
      inlen == 0 ||
      outlen == 0 ||
      (inlen % TC_AES_BLOCK_SIZE) != 0 ||
      (outlen % TC_AES_BLOCK_SIZE) != 0 ||
      outlen != inlen) {
    return TC_CRYPTO_FAIL;
  }

  /*
	 * Note that in == iv + ciphertext, i.e. the iv and the ciphertext are
	 * contiguous. This allows for a very efficient decryption algorithm
	 * that would not otherwise be possible.
	 */
  p = inlen == TC_AES_BLOCK_SIZE ? iv : iv.concat([inData]);

  int inOffs = 0;
  int outOffs = 0;
  int pOffs = 0;

  for (n = m = 0; n < outlen; ++n) {
    if ((n % TC_AES_BLOCK_SIZE) == 0) {
      tc_aes_decrypt(buffer, inData.subView(inOffs), sched);
      // print("\n in: ${inData.subView(inOffs).sublist(0, 8).hexString()}, buffer: ${buffer.hexString()}");
      inOffs += TC_AES_BLOCK_SIZE;
      m = 0;
    }

    out[outOffs++] = buffer[m++] ^ p[pOffs++];
  }

  return TC_CRYPTO_SUCCESS;
}
