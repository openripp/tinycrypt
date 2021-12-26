part of tiny_crypt;


 void rekey(Uint8List key,  Uint8List new_key, unsigned key_size)
{
	 uint8_t inner_pad = 0x36;
	 uint8_t outer_pad = 0x5c;
	unsigned i;

	for (i = 0; i < key_size; ++i) {
		key[i] = inner_pad ^ new_key[i];
		key[i + TC_SHA256_BLOCK_SIZE] = outer_pad ^ new_key[i];
	}
	for (; i < TC_SHA256_BLOCK_SIZE; ++i) {
		key[i] = inner_pad; key[i + TC_SHA256_BLOCK_SIZE] = outer_pad;
	}
}

int tc_hmac_set_key(TCHmacState_t ctx,  Uint8List key,
		    unsigned key_size)
{
	/* Input sanity check */
	if (ctx == null ||
	    key == null ||
	    key_size == 0) {
		return TC_CRYPTO_FAIL;
	}

	 var dummy_key = Uint8List(TC_SHA256_BLOCK_SIZE);
	var dummy_state = tc_hmac_state_struct();

	if (key_size <= TC_SHA256_BLOCK_SIZE) {
		/*
		 * The next three calls are dummy calls just to avoid
		 * certain timing attacks. Without these dummy calls,
		 * adversaries would be able to learn whether the key_size is
		 * greater than TC_SHA256_BLOCK_SIZE by measuring the time
		 * consumed in this process.
		 */
		tc_sha256_init(dummy_state.hash_state);
		tc_sha256_update(dummy_state.hash_state,
				       dummy_key,
				       key_size);
		tc_sha256_final(dummy_state.key.subView(TC_SHA256_DIGEST_SIZE),
				      dummy_state.hash_state);

		/* Actual code for when key_size <= TC_SHA256_BLOCK_SIZE: */
		rekey(ctx.key, key, key_size);
	} else {
		tc_sha256_init(ctx.hash_state);
		tc_sha256_update(ctx.hash_state, key, key_size);
		tc_sha256_final(ctx.key.subView(TC_SHA256_DIGEST_SIZE),
				      ctx.hash_state);
		rekey(ctx.key,
		      ctx.key.subView(TC_SHA256_DIGEST_SIZE),
		      TC_SHA256_DIGEST_SIZE);
	}

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_init(TCHmacState_t? ctx)
{

	/* input sanity check: */
	if (ctx == null) {
		return TC_CRYPTO_FAIL;
	}

   tc_sha256_init(ctx.hash_state);
   tc_sha256_update(ctx.hash_state, ctx.key, TC_SHA256_BLOCK_SIZE);

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_update(TCHmacState_t? ctx,
		    Uint8List data,
		   unsigned data_length)
{

	/* input sanity check: */
	if (ctx == null) {
		return TC_CRYPTO_FAIL;
	}

	tc_sha256_update(ctx.hash_state, data, data_length);

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_final(Uint8List? tag, unsigned taglen, TCHmacState_t? ctx)
{

	/* input sanity check: */
	if (tag == null ||
	    taglen != TC_SHA256_DIGEST_SIZE ||
	    ctx == null) {
		return TC_CRYPTO_FAIL;
	}

	 tc_sha256_final(tag, ctx.hash_state);

	tc_sha256_init(ctx.hash_state);
	tc_sha256_update(ctx.hash_state,
			       ctx.key.subView(TC_SHA256_BLOCK_SIZE),
				TC_SHA256_BLOCK_SIZE);
	tc_sha256_update(ctx.hash_state, tag, TC_SHA256_DIGEST_SIZE);
	tc_sha256_final(tag, ctx.hash_state);

	/* destroy the current state */
  ctx.clear();

	return TC_CRYPTO_SUCCESS;
}

