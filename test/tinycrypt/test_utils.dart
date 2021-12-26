
part of test_tinycrypt;

/*
 */

void show_str(String label, Uint8List s, size_t len)
{
        unsigned i;

        TC_PRINT("$label = ");
        for (i = 0; i < len; ++i) {
                TC_PRINT(s[i].toStringAligned(2));
        }
        TC_PRINT("\n");
}


void fatal(unsigned testnum, Uint8List expected, size_t expectedlen,
    Uint8List computed, size_t computedlen)
{

        TC_ERROR("\tTest #$testnum Failed!\n");
        show_str("\t\tExpected", expected, expectedlen);
        show_str("\t\tComputed  ", computed, computedlen);
        TC_PRINT("\n");
}

bool check_result(unsigned testnum, Uint8List expected, size_t expectedlen,
    Uint8List computed, size_t computedlen)
{
	var result = TC_PASS;

        if (expectedlen != computedlen) {
                TC_ERROR("The length of the computed buffer ($computedlen)");
                TC_ERROR("does not match the expected length ($expectedlen).");
                result = TC_FAIL;
        } else if (memcmp(computed, expected, computedlen) != 0) {
                fatal(testnum, expected, expectedlen, computed, computedlen);
                result = TC_FAIL;
        }

        return result;
}

