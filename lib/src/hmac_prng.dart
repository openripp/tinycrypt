part of tiny_crypt;


/*
 * min bytes in the seed string.
 * MIN_SLEN*8 must be at least the expected security level.
 */
  unsigned MIN_SLEN = 32;

/*
 * max bytes in the seed string;
 * SP800-90A specifies a maximum of 2^35 bits (i.e., 2^32 bytes).
 */
  unsigned MAX_SLEN = UINT32_MAX;

/*
 * max bytes in the personalization string;
 * SP800-90A specifies a maximum of 2^35 bits (i.e., 2^32 bytes).
 */
  unsigned MAX_PLEN = UINT32_MAX;

/*
 * max bytes in the additional_info string;
 * SP800-90A specifies a maximum of 2^35 bits (i.e., 2^32 bytes).
 */
  unsigned MAX_ALEN = UINT32_MAX;

/*
 * max number of generates between re-seeds;
 * TinyCrypt accepts up to (2^32 - 1) which is the maximal value of
 * a 32-bit unsigned variable, while SP800-90A specifies a maximum of 2^48.
 */
  unsigned MAX_GENS = UINT32_MAX;

/*
 * maximum bytes per generate call;
 * SP800-90A specifies a maximum up to 2^19.
 */
  unsigned  MAX_OUT = (1 << 19);

/*
 * Assumes: prng != NULL
 */
 void update(TCHmacPrng_t prng,  Uint8List? data, unsigned datalen,  Uint8List? additional_data, unsigned additional_datalen)
{
	 var separator0 = [0x00].bytes;
	 var separator1 = [0x01].bytes;

	/* configure the new prng key into the prng's instance of hmac */
	tc_hmac_set_key(prng.h, prng.key, sizeof(prng.key));

	/* use current state, e and separator 0 to compute a new prng key: */
	tc_hmac_init(prng.h);
	tc_hmac_update(prng.h, prng.v, sizeof(prng.v));
	tc_hmac_update(prng.h, separator0, sizeof(separator0));

	if (data != null && datalen > 0)
		tc_hmac_update(prng.h, data, datalen);
	if (additional_data != null && additional_datalen > 0)
		tc_hmac_update(prng.h, additional_data, additional_datalen);

	tc_hmac_final(prng.key, sizeof(prng.key), prng.h);

	/* configure the new prng key into the prng's instance of hmac */
	tc_hmac_set_key(prng.h, prng.key, sizeof(prng.key));

	/* use the new key to compute a new state variable v */
	tc_hmac_init(prng.h);
	tc_hmac_update(prng.h, prng.v, sizeof(prng.v));
	tc_hmac_final(prng.v, sizeof(prng.v), prng.h);

	if (data == null || datalen == 0)
		return;

	/* configure the new prng key into the prng's instance of hmac */
	tc_hmac_set_key(prng.h, prng.key, sizeof(prng.key));

	/* use current state, e and separator 1 to compute a new prng key: */
	tc_hmac_init(prng.h);
	tc_hmac_update(prng.h, prng.v, sizeof(prng.v));
	tc_hmac_update(prng.h, separator1, sizeof(separator1));
	tc_hmac_update(prng.h, data, datalen);
	if (additional_data != null && additional_datalen > 0)
		tc_hmac_update(prng.h, additional_data, additional_datalen);
	tc_hmac_final(prng.key, sizeof(prng.key), prng.h);

	/* configure the new prng key into the prng's instance of hmac */
	tc_hmac_set_key(prng.h, prng.key, sizeof(prng.key));

	/* use the new key to compute a new state variable v */
	tc_hmac_init(prng.h);
	tc_hmac_update(prng.h, prng.v, sizeof(prng.v));
	tc_hmac_final(prng.v, sizeof(prng.v), prng.h);
}

int tc_hmac_prng_init(TCHmacPrng_t? prng,
		       Uint8List? personalization,
		      unsigned plen)
{

	/* input sanity check: */
	if (prng == null ||
	    personalization == null ||
	    plen > MAX_PLEN) {
		return TC_CRYPTO_FAIL;
	}

	/* put the generator into a known state: */
	_set(prng.key, 0x00, sizeof(prng.key));
	_set(prng.v, 0x01, sizeof(prng.v));

	update(prng, personalization, plen, null, 0);

	/* force a reseed before allowing tc_hmac_prng_generate to succeed: */
	prng.countdown = 0;

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_prng_reseed(TCHmacPrng_t? prng,
			 Uint8List? seed,
			unsigned seedlen,
			 Uint8List? additional_input,
			unsigned additionallen)
{

	/* input sanity check: */
	if (prng == null ||
	    seed == null ||
	    seedlen < MIN_SLEN ||
	    seedlen > MAX_SLEN) {
		return TC_CRYPTO_FAIL;
	}

	if (additional_input != null) {
		/*
		 * Abort if additional_input is provided but has inappropriate
		 * length
		 */
		if (additionallen == 0 ||
		    additionallen > MAX_ALEN) {
			return TC_CRYPTO_FAIL;
		} else {
			/* call update for the seed and additional_input */
			update(prng, seed, seedlen, additional_input, additionallen);
		}
	} else {
		/* call update only for the seed */
		update(prng, seed, seedlen, null, 0);
	}

	/* ... and enable hmac_prng_generate */
	prng.countdown = MAX_GENS;

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_prng_generate(Uint8List? out, unsigned outlen, TCHmacPrng_t? prng)
{
	unsigned bufferlen;

	/* input sanity check: */
	if (out == null ||
	    prng == null ||
	    outlen == 0 ||
	    outlen > MAX_OUT) {
		return TC_CRYPTO_FAIL;
	} else if (prng.countdown == 0) {
		return TC_HMAC_PRNG_RESEED_REQ;
	}

	prng.countdown--;
	var offs = 0;

	while (outlen != 0) {
		/* configure the new prng key into the prng's instance of hmac */
		tc_hmac_set_key(prng.h, prng.key, sizeof(prng.key));

		/* operate HMAC in OFB mode to create "random" outputs */
		tc_hmac_init(prng.h);
		tc_hmac_update(prng.h, prng.v, sizeof(prng.v));
		tc_hmac_final(prng.v, sizeof(prng.v), prng.h);

		bufferlen = (TC_SHA256_DIGEST_SIZE > outlen) ?
			outlen : TC_SHA256_DIGEST_SIZE;
		_copy(out.subView(offs), bufferlen, prng.v, bufferlen);

		offs += bufferlen;
		outlen = (outlen > TC_SHA256_DIGEST_SIZE) ?
			(outlen - TC_SHA256_DIGEST_SIZE) : 0;
	}

	/* block future PRNG compromises from revealing past state */
	update(prng, null, 0, null, 0);

	return TC_CRYPTO_SUCCESS;
}

