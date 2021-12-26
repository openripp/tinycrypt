
part of tiny_crypt;

const MASK_TWENTY_SEVEN = 0x1b;

int sizeof(TypedData d) => d.lengthInBytes;

int strlen(String s) => s.length;

int memcpy(Uint8List to, Uint8List from, int len) {
  from.copyTo(to, 0, len);
  return len;
}

int memcmp(Uint8List l, Uint8List r, int len) {
  var c = 0;
  for (var idx = 0; idx < len; ++idx) {
    c = l[idx] - r[idx];
    if (c != 0) break;
  }

  return c;
}

int memset(Uint8List to, int val, int len) {
  to.fillRange(0, len, val);
  return len;
}

int _copy(Uint8List to, int to_len, final Uint8List from, int from_len) {
  if (from_len <= to_len) {
    memcpy(to, from, from_len);
    return from_len;
  } else {
    return TC_CRYPTO_FAIL;
  }
}

void _set(Uint8List to, int val, int len)
{
  memset(to, val, len);
}

/*
 * Doubles the value of a byte for values up to 127.
 */
int _double_byte(int a) {
  return ((a << 1) ^ ((a >> 7) * MASK_TWENTY_SEVEN)) & 0xFF;
}

int _compare(final Uint8List a, final Uint8List b, int size) {
  final Uint8List tempa = a;
  final Uint8List tempb = b;
  int result = 0;

  for (int i = 0; i < size; i++) {
    result |= tempa[i] ^ tempb[i];
  }

  return result & 0xFF;
}

void _set_secure(Uint8List to, uint8_t val, unsigned len)
{
  memset(to, val, len);
}



extension EccInt64Ext on Int64 {
  int get to_uECC_word_t => toInt().uint32;
}

extension EccIntExt on int {
  /*

typedef int8_t = int;
typedef int16_t = int;
typedef uint64_t = Int64;

/* defining data types to store word and bit counts: */
typedef wordcount_t = int8_t;
typedef bitcount_t = int16_t;
/* defining data type for comparison result: */
typedef cmpresult_t = int8_t;
/* defining data type to store ECC coordinate/point in 32bits words: */
typedef uECC_word_t = int;
/* defining data type to store an ECC coordinate/point in 64bits words: */
typedef uECC_dword_t = uint64_t;

   */
  bool get boolValue => this != 0;

  int get to_uECC_word_t => uint32;
  int get to_wordcount_t => this & 0xFF;
  int get to_bitcount_t => this & 0xFFFF;
  int get to_cmpresult_t => this & 0xFF;
  Int64 get to_uECC_dword_t => to_uint64_t;

  int get to_uint8_t => this & 0xFF;
  int get to_int8_t => this & 0xFF;
  int get to_int16_t => this & 0xFFFF;
  Int64 get to_uint64_t => Int64(uint32);
}

extension IntOfBoolExt on bool {
  int get boolInt => this ? 1 : 0;
}


extension EccListIntExt<E> on List<int> {
  uECC_word_t_List to_uECC_word_t_List() => uECC_word_t_List.fromList(this);
}

typedef uECC_word_t_List = Uint32List;
typedef unsigned_int_List = Uint32List;

Uint32List listOfuECC_word_t(int length, [int? fill]) {
  return Uint32List(length);
}
