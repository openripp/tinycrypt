
part of tiny_crypt;


int tc_ctr_mode(Uint8List out, int outlen, Uint8List inData,
int inlen, Uint8List nonceCtr, TCAesKeySched_t sched)
{
	var buffer = Uint8List(TC_AES_BLOCK_SIZE);
  var nonce = Uint8List(TC_AES_BLOCK_SIZE);

	int block_num;
	int i;

	/* input sanity check: */
	if (out == null ||
	    inData == null ||
	    nonceCtr == null ||
	    sched == null ||
	    inlen == 0 ||
	    outlen == 0 ||
	    outlen != inlen) {
		return TC_CRYPTO_FAIL;
	}

	/* copy the ctr to the nonce */
	_copy(nonce, nonce.length, nonceCtr, nonce.length);

	/* select the last 4 bytes of the nonce to be incremented */
	block_num = (nonce[12] << 24) | (nonce[13] << 16) |
		    (nonce[14] << 8) | (nonce[15]);
	for (i = 0; i < inlen; ++i) {
		if ((i % (TC_AES_BLOCK_SIZE)) == 0) {
			/* encrypt data using the current nonce */
			if (tc_aes_encrypt(buffer, nonce, sched) == TC_CRYPTO_SUCCESS) {
				block_num++;
				nonce[12] = (block_num >> 24) & 0xFF;
				nonce[13] = (block_num >> 16) & 0xFF;
				nonce[14] = (block_num >> 8) & 0xFF;
				nonce[15] = (block_num) & 0xFF;
			} else {
				return TC_CRYPTO_FAIL;
			}
		}
		/* update the output */
		out[i] = buffer[i%(TC_AES_BLOCK_SIZE)] ^ inData[i];
	}

	/* update the counter */
	nonceCtr[12] = nonce[12]; nonceCtr[13] = nonce[13];
	nonceCtr[14] = nonce[14]; nonceCtr[15] = nonce[15];

	return TC_CRYPTO_SUCCESS;
}

