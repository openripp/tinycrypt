
part of test_tinycrypt;

const TC_FAIL = false;
const TC_PASS = true;

bool check_ecc_result(int num, String name,
		      unsigned_int_List expected32,
    unsigned_int_List computed32,
		      unsigned num_word32, bool verbose) {
  uint32_t num_bytes = 4 * num_word32;

  var expected = expected32.bytesView;
  var computed = computed32.bytesView;
  if (memcmp(computed, expected, num_bytes).boolValue) {
    print("\n  Vector #$num check $name - FAILURE:\n\n");
    print("Expected: ${expected.hex}");
    print("Computed: ${computed.hex}");
    return false;
  }

  if (verbose) {
    print("  Vector #$num check $name - success\n",);
  }

  return true;
}



var _0 = '0'.codeUnits[0];
var _9 = '9'.codeUnits[0];
var _a = 'a'.codeUnits[0];
var _f = 'f'.codeUnits[0];
var _A = 'A'.codeUnits[0];
var _F = 'F'.codeUnits[0];

int hex2int (int hex)
{
	uint8_t dec;

	if (_0 <= hex && hex <= _9) dec = hex - _0;
	else if (_a <= hex && hex <= _f) dec = hex - _a + 10;
	else if (_A <= hex && hex <= _F) dec = hex - _A + 10;
	else return -1;

	return dec;
}

/*
 * Convert hex string to byte string
 * Return number of bytes written to buf, or 0 on error
 */
int hex2bin(Uint8List buf, size_t buflen, String hexStr,
	    size_t hexlen)
{

	int dec;
	var hex = hexStr.codeUnits;

	if (buflen < hexlen / 2 + hexlen % 2)
	{
		return 0;
	}

	var offs = 0;
	/* if hexlen is uneven, insert leading zero nibble */
	if ((hexlen % 2).boolValue)
	{
		dec = hex2int(hex[0]);
		if (dec == -1)
			return 0;
		buf[offs] = dec;
    offs++;
	}

	/* regular hex conversion */
	for (size_t i = 0; i < hexlen / 2; i++)
	{
		dec = hex2int(hex[2 * i]);
		if (dec == -1)
		{
			return 0;
		}
		buf[offs + i] = dec << 4;

		dec = hex2int(hex[ 2 * i + 1]);
		if (dec == -1)
		{
			return 0;
		}
		buf[offs + i] += dec;
	}
	return hexlen ~/ 2 + hexlen % 2;
}

/*
 * Convert hex string to zero-padded nanoECC scalar
 */
void string2scalar(unsigned_int_List scalar, unsigned num_word32, String str)
{

	unsigned num_bytes = 4 * num_word32;
	var tmp = Uint8List(num_bytes);
	size_t hexlen = strlen(str);

	int padding;

	if (0 > (padding = 2 * num_bytes - strlen(str)))
	{
		throw Exception("Error: 2 * num_bytes(${2 * num_bytes}) < strlen(hex) (${strlen(str)})\n");
	}

	memset(tmp, 0, padding ~/ 2);

	if (false == hex2bin(tmp.subView(padding ~/ 2), num_bytes, str, hexlen))
	{
	  throw Exception('hex2bin error');
	}

	uECC_vli_bytesToNative(scalar, tmp, num_bytes);
	// print('string2scalar: $str => ${tmp.hex} / ${scalar.bytesView.hex}');
}


bool ecdh_vectors(List<String> qx_vec, List<String> qy_vec, List<String> d_vec, List<String> z_vec,
    int tests, bool verbose)
{

	var pub = unsigned_int_List(2*NUM_ECC_WORDS);
	var prv = unsigned_int_List(NUM_ECC_WORDS);
	var z = unsigned_int_List(NUM_ECC_WORDS);
	bool result = true;

	int rc;
  var exp_z = unsigned_int_List(NUM_ECC_WORDS);

	var curve = uECC_secp256r1();

	for (int i = 0;  i < tests; i++) {
		string2scalar(pub.subView(NUM_ECC_WORDS), NUM_ECC_WORDS, qx_vec[i]);
		string2scalar(pub, NUM_ECC_WORDS, qy_vec[i]);
		string2scalar(exp_z, NUM_ECC_WORDS, z_vec[i]);
    string2scalar(prv, NUM_ECC_WORDS, d_vec[i]);

		var pub_bytes = Uint8List(2*NUM_ECC_BYTES);
		uECC_vli_nativeToBytes(pub_bytes, 2*NUM_ECC_BYTES, pub);
		var private_bytes = Uint8List(NUM_ECC_BYTES);
		uECC_vli_nativeToBytes(private_bytes, NUM_ECC_BYTES, prv);
		var z_bytes = Uint8List(NUM_ECC_BYTES);
		uECC_vli_nativeToBytes(z_bytes, NUM_ECC_BYTES, exp_z);

		if (verbose) {
      print('x: ${qx_vec[i]}, y: ${qy_vec[i]}, z: ${z_vec[i]}, d: ${d_vec[i]}'
          "\n pub: ${pub.bytesView.hex}"
          "\n pub_bytes: ${pub_bytes.hex}"
          "\n pri_bytes: ${private_bytes.hex}"
          "\n exp_z: ${exp_z.bytesView.hex}"
          "\n z_bytes: ${z_bytes.hex}"
      );
    }

		rc = uECC_shared_secret(pub_bytes, private_bytes, z_bytes, curve);

		if (rc == TC_CRYPTO_FAIL) {
			print("ECDH failure, exit.\n");
			result = false;
			return result;
		}

		uECC_vli_bytesToNative(z, z_bytes, NUM_ECC_BYTES);

		result = check_ecc_result(i, "Z", exp_z, z, NUM_ECC_WORDS, verbose);
		if (!result) {
		  return result;
		}
  }
	return result;
}

/* Test ecc_make_keys, and also as keygen part of other tests */
bool keygen_vectors(List<String> d_vec, List<String> qx_vec, List<String> qy_vec, int tests,
		    bool verbose)
{

  var pub = unsigned_int_List(2*NUM_ECC_WORDS);
  var prv = unsigned_int_List(NUM_ECC_WORDS);
  var d = unsigned_int_List(NUM_ECC_WORDS);
	bool result = true;

	/* expected outputs (converted input vectors) */
  var exp_pub = unsigned_int_List(2*NUM_ECC_WORDS);
  var exp_prv = unsigned_int_List(NUM_ECC_WORDS);


  for (int i = 0; i < tests; i++) {
		string2scalar(exp_prv, NUM_ECC_WORDS, d_vec[i]);
		string2scalar(exp_pub, NUM_ECC_WORDS, qx_vec[i]);
		string2scalar(exp_pub.subView(NUM_ECC_WORDS), NUM_ECC_WORDS, qy_vec[i]);

		/*
		 * Feed prvkey vector as padded random seed into ecc_make_key.
		 * Internal mod-reduction will be zero-op and generate correct prv/pub
		 */
		memset(d.bytesView, 0, sizeof(d));
		string2scalar(d, NUM_ECC_WORDS, d_vec[i]);

    var pub_bytes = Uint8List(2*NUM_ECC_BYTES);
    var prv_bytes = Uint8List(NUM_ECC_BYTES);

		uECC_make_key_with_d(pub_bytes, prv_bytes, d, uECC_secp256r1());

		uECC_vli_bytesToNative(prv, prv_bytes, NUM_ECC_BYTES);
		uECC_vli_bytesToNative(pub, pub_bytes, NUM_ECC_BYTES);
		uECC_vli_bytesToNative(pub.subView(NUM_ECC_WORDS), pub_bytes.subView(NUM_ECC_BYTES), NUM_ECC_BYTES);

		/* validate correctness of vector conversion and make_key() */
		result = check_ecc_result(i, "prv  ", exp_prv, prv,  NUM_ECC_WORDS, verbose);
		if (result == TC_FAIL) {
		  return result;
		}
		result = check_ecc_result(i, "pub.x", exp_pub, pub,  NUM_ECC_WORDS, verbose);
		if (result == TC_FAIL) {
		  return result;
		}
		result = check_ecc_result(i, "pub.y", exp_pub.subView(NUM_ECC_WORDS), pub.subView(NUM_ECC_WORDS),  NUM_ECC_WORDS, verbose);
		if (result == TC_FAIL) {
		  return result;
		}
	}
	return result;
}



bool check_code(int num, String name, int expected,
		int computed, bool verbose)
{

	if (expected != computed) {
    print("\n  Vector #${num.toStringAligned(2)} check $name - FAILURE:\n");
    print("\n  Expected: $expected, computed: $computed\n\n");
		return TC_FAIL;
	}

	if (verbose) {
		print("  Vector #${num.toStringAligned(2)} check $name - success ($expected=$computed)\n");
	}

	return TC_PASS;
}


/* Test ecc_make_keys, and also as keygen part of other tests */
bool pkv_vectors(List<String> qx_vec, List<String> qy_vec, List<String> res_vec, int tests,
		 bool verbose) {
  var pub = unsigned_int_List(2 * NUM_ECC_WORDS);
  var _public = Uint8List(2 * NUM_ECC_BYTES);

  int rc;
  int exp_rc;
  uint8_t tmp;
  var result = TC_PASS;
  var curve = uECC_secp256r1();

  for (int i = 0; i < tests; i++) {
    var rv = res_vec[i];
    if (!RegExp(r'^[\w] \([\d]').hasMatch(rv)) {
      throw Exception("Error: failed to parse CAVP response: $rv.\n");
    }
    tmp = rv[0].codeUnits[0];
    exp_rc = int.parse(rv[3]);

    if (strlen(qx_vec[i]) > 2 * NUM_ECC_BYTES ||
        strlen(qy_vec[i]) > 2 * NUM_ECC_BYTES) {
      /* invalid input to ECC digit conversion (string2native()) */
      rc = -2;
    } else {
      string2scalar(pub, NUM_ECC_WORDS, qx_vec[i]);
      string2scalar(pub.subView(NUM_ECC_WORDS), NUM_ECC_WORDS, qy_vec[i]);

      uECC_vli_nativeToBytes(_public, NUM_ECC_BYTES, pub);
      uECC_vli_nativeToBytes(
          _public.subView(NUM_ECC_BYTES), NUM_ECC_BYTES, pub.subView(NUM_ECC_WORDS));

      rc = uECC_valid_public_key(_public, curve);
    }

    /*
	 * map to CAVP error codes
 	 *  0 => 0 - success
	 * -1 => ? - (x,y) = (0,0) (not covered)
	 * -2 => 1 - out of bounds (pubverify or ecc import)
	 * -3 => 2 - not on curve
	 * -4 => ? - public key is the group generator
	 */

    if (rc == -3) rc = 2;
    if (rc == -2) rc = 1;

    result = check_code(i, res_vec[i], exp_rc, rc, verbose);
    if (result == TC_FAIL) {
      return result;
    }
  }

  return true;
}

const TC_PRINT = print;
void TC_ERROR(String s) => throw Exception(s);
void vli_print_bytes(Uint8List bytes, len) => print(bytes.subView(0, len).hex);

bool montecarlo_ecdh(int num_tests, bool verbose)
{
	int i;
  var private1 = Uint8List(NUM_ECC_BYTES);
  var private2 = Uint8List(NUM_ECC_BYTES);
  var public1 = Uint8List(2 * NUM_ECC_BYTES);
  var public2 = Uint8List(2 * NUM_ECC_BYTES);
  var secret1 = Uint8List(NUM_ECC_BYTES);
  var secret2 = Uint8List(NUM_ECC_BYTES);

    var result = TC_PASS;

	var curve = uECC_secp256r1();

	print("Test #4: Monte Carlo ($num_tests Randomized EC-DH key-exchange) ");
  print("NIST-p256\n  ");

	for (i = 0; i < num_tests; ++i) {
		if (verbose) {
			print(".");
		}

		if (!uECC_make_key(public1, private1, curve).boolValue ||
		    !uECC_make_key(public2, private2, curve).boolValue) {
			throw Exception("uECC_make_key() failed\n");
		}

		if (!uECC_shared_secret(public2, private1, secret1, curve).boolValue) {
      throw Exception("shared_secret() failed (1)\n");
		}

		if (!uECC_shared_secret(public1, private2, secret2, curve).boolValue) {
      throw Exception("shared_secret() failed (2)\n");
		}

		if (memcmp(secret1, secret2, sizeof(secret1)) != 0) {
			TC_PRINT("Shared secrets are not identical!\n");
			TC_PRINT("Private key 1 = ");
			vli_print_bytes(private1, 32);
			TC_PRINT("\nPrivate key 2 = ");
			vli_print_bytes(private2, 32);
			TC_PRINT("\nPublic key 1 = ");
			vli_print_bytes(public1, 64);
			TC_PRINT("\nPublic key 2 = ");
			vli_print_bytes(public2, 64);
			TC_PRINT("\nShared secret 1 = ");
			vli_print_bytes(secret1, 32);
			TC_PRINT("\nShared secret 2 = ");
			vli_print_bytes(secret2, 32);
			TC_PRINT("\n");
		}
	}

	TC_PRINT("\n");

  return result;
}





/* Maximum size of message to be signed. */
const BUF_SIZE = 256;

bool sign_vectors(TCSha256State_t hash, List<String> d_vec, List<String> k_vec,
		 List<String> msg_vec, List<String> qx_vec, List<String> qy_vec, List<String> r_vec,
		 List<String> s_vec, int tests, bool verbose)
{

	var k = unsigned_int_List(NUM_ECC_WORDS);
	var private = unsigned_int_List(NUM_ECC_WORDS);

	var private_bytes = Uint8List(NUM_ECC_BYTES);
	var sig = unsigned_int_List(2 * NUM_ECC_WORDS);
	var sig_bytes = Uint8List(2 * NUM_ECC_BYTES);

  var digest = unsigned_int_List(TC_SHA256_DIGEST_SIZE ~/ 4);
	var digest_bytes = Uint8List(TC_SHA256_DIGEST_SIZE);

	var result = TC_PASS;

	/* expected outputs (converted input vectors) */
  var exp_r = unsigned_int_List(NUM_ECC_WORDS);
  var exp_s = unsigned_int_List(NUM_ECC_WORDS);

  var msg = Uint8List(BUF_SIZE);
	size_t msglen;

	for (int i = 0; i < tests; i++) {

    /* use keygen test to generate and validate pubkey */
    keygen_vectors(
        d_vec.subView(i), qx_vec.subView(i), qy_vec.subView(i), 1, false);
    string2scalar(private, NUM_ECC_WORDS, d_vec[i]);
    uECC_vli_nativeToBytes(private_bytes, NUM_ECC_BYTES, private);

    /* validate ECDSA: hash message, sign digest, check r+s */
    memset(k.bytesView, 0, NUM_ECC_BYTES);
    string2scalar(k, NUM_ECC_WORDS, k_vec[i]);
    string2scalar(exp_r, NUM_ECC_WORDS, r_vec[i]);
    string2scalar(exp_s, NUM_ECC_WORDS, s_vec[i]);

    msglen = hex2bin(msg, BUF_SIZE, msg_vec[i], strlen(msg_vec[i]));

    if (msglen == false) {
      TC_ERROR("failed to import message!\n");
      result = TC_FAIL;
      break;
    }

    tc_sha256_init(hash);
    tc_sha256_update(hash, msg, msglen);
    tc_sha256_final(digest_bytes, hash);

    /* if digest larger than ECC scalar, drop the end
		 * if digest smaller than ECC scalar, zero-pad front */
    int hash_dwords = TC_SHA256_DIGEST_SIZE ~/ 4;
    if (NUM_ECC_WORDS < hash_dwords) {
      hash_dwords = NUM_ECC_WORDS;
    }

    memset(digest.bytesView, 0, NUM_ECC_BYTES - 4 * hash_dwords);
    uECC_vli_bytesToNative(digest.subView(NUM_ECC_WORDS - hash_dwords),
        digest_bytes, TC_SHA256_DIGEST_SIZE);

    if (uECC_sign_with_k(private_bytes, digest_bytes,
        sizeof(digest_bytes), k, sig_bytes, uECC_secp256r1()) == 0) {
      TC_ERROR("ECDSA_sign failed!\n");
      result = TC_FAIL;
      break;
    }

    uECC_vli_bytesToNative(sig, sig_bytes, NUM_ECC_BYTES);
    uECC_vli_bytesToNative(
        sig.subView(NUM_ECC_WORDS), sig_bytes.subView(NUM_ECC_BYTES),
        NUM_ECC_BYTES);

    result = check_ecc_result(i, "sig.r", exp_r, sig, NUM_ECC_WORDS, verbose);
    if (result == TC_FAIL) {
      break;
    }
    result = check_ecc_result(
        i, "sig.s", exp_s, sig.subView(NUM_ECC_WORDS), NUM_ECC_WORDS, verbose);
    if (result == TC_FAIL) {
      break;
    }
  }

	return result;
}



bool do_hmac_test(TCHmacState_t h, unsigned testnum, Uint8List data,
		          size_t datalen, Uint8List expected,
		          size_t expectedlen)
{
        var digest = Uint8List(32);
        var result = TC_PASS;

        tc_hmac_init(h);
        tc_hmac_update(h, data, datalen);
        tc_hmac_final(digest, TC_SHA256_DIGEST_SIZE, h);
        result = check_result(testnum, expected, expectedlen,
			      digest, sizeof(digest));
        return result;
}



class hmac_prng_test_vector {
	uint8_t entropyinputlen = 0;
	uint8_t noncelen = 0;
	uint8_t personalizationstringlen = 0;
	uint8_t additionalinputlen = 0;
	uint8_t returnedbitslen = 0;
	var entropyinput = Uint8List(32);
	var nonce = Uint8List(16);
	var personalizationstring = Uint8List(32);
	var entropyinputreseed = Uint8List(32);
	var additionalinputreseed = Uint8List(32);
	var returnedbits = Uint8List(128);
}

bool do_hmac_prng_pr_false_test(unsigned testnum,
					hmac_prng_test_vector vec)
{
	var h = tc_hmac_prng_struct();
	var random = Uint8List(128);
	uint32_t seed_material_size;
	var seed_material = Uint8List(32 + 16 + 32); /*entropyinput || nonce || personalizationstring */
	var result = TC_PASS;

	var p = seed_material;

	if (vec.entropyinputlen > 0) {
		memcpy(p, vec.entropyinput, vec.entropyinputlen);
		p = p.subView(vec.entropyinputlen);
	}

	if (vec.noncelen > 0) {
		memcpy(p, vec.nonce, vec.noncelen);
		p = p.subView(vec.noncelen);
	}

	if (vec.personalizationstringlen > 0) {
		memcpy(p, vec.personalizationstring, vec.personalizationstringlen);
	}

	seed_material_size = vec.entropyinputlen + vec.noncelen + vec.personalizationstringlen;
	tc_hmac_prng_init(h, seed_material, seed_material_size);
	tc_hmac_prng_reseed(h, vec.entropyinputreseed, vec.entropyinputlen, null, 0);
	tc_hmac_prng_generate(random, vec.returnedbitslen, h);
	tc_hmac_prng_generate(random, vec.returnedbitslen, h);
	result = check_result(testnum, vec.returnedbits, vec.returnedbitslen, random, vec.returnedbitslen);
	return result;
}



/* 
 * Convert a string of characters representing a hex buffer into a series of 
 * bytes of that real value 
 */
Uint8List hexStringToBytes(String inhex)
{
  return inhex.hexDecodedBytes;
}

class PRNG_Vector {
  late String entropyString;
	String? personalizationString;  /* may be null */
	String? additionalInputString1; /* may be null */
	String? additionalInputString2; /* may be null */
	late String expectedString;
}


bool executePRNG_TestVector(PRNG_Vector vector, unsigned idx)
{
	var result = TC_PASS;
	var entropy    = hexStringToBytes(vector.entropyString);
	unsigned  entropylen = strlen(vector.entropyString) ~/ 2;

	var expected    = hexStringToBytes(vector.expectedString);
	unsigned  expectedlen = strlen(vector.expectedString) ~/ 2;

	Uint8List? personalization;
	unsigned  plen              = 0;

  Uint8List? additional_input1;
	unsigned  additionallen1    = 0;

  Uint8List? additional_input2;
	unsigned  additionallen2    = 0;

  Uint8List output = Uint8List(expectedlen);

	unsigned i;
	var ctx = TCCtrPrng_t();

	if (null != vector.personalizationString) {
		personalization = hexStringToBytes(vector.personalizationString!);
		plen = strlen(vector.personalizationString!) ~/ 2;
	}

	if (null != vector.additionalInputString1) {
		additional_input1 = hexStringToBytes(vector.additionalInputString1!);
		additionallen1 = strlen(vector.additionalInputString1!) ~/ 2;
	}

	if (null != vector.additionalInputString2) {
		additional_input2 = hexStringToBytes(vector.additionalInputString2!);
		additionallen2 = strlen(vector.additionalInputString2!) ~/ 2;
	}

	tc_ctr_prng_init(ctx, entropy, entropylen, personalization, plen);

	tc_ctr_prng_generate(ctx, additional_input1, additionallen1, output, expectedlen);
	tc_ctr_prng_generate(ctx, additional_input2, additionallen2, output, expectedlen);

	for (i = 0; i < expectedlen; i++) {
		if (output[i] != expected[i]) {
			TC_ERROR("CTR PRNG test #$idx failed\n");
			result = TC_FAIL;
			break;
		}
	}

	return result;
}

