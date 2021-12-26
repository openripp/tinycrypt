part of tiny_crypt;

const _zeroStr = "0000000000000000000000000000000000000000000000000000000000000000";

/// JS cannot exceed 53bit for bit-op, we use 48 bits.
const MAX_SAFE_INT_SIZE = 6;
int utc() => DateTime.now().millisecondsSinceEpoch;

extension Int64ExtUtils on Int64 {

  Uint8List toBytesSize(int size) {
    var bytes = toBytes();
    return bytes.sublist(0, size).reversed.toList().bytes;
  }

  String get hex => '0x' + toHexString();

}

extension Int64Utils on Int64 {
  BigInt toBigInt() => BigInt.parse(toHexString(), radix: 16);
}

extension EccBigIntExt on BigInt {
  Int64 get int64 => Int64.parseHex(toSigned(64).toRadixString(16));
  int get uint32 => toUnsigned(32).toInt().uint32;
  int get int32 => toSigned(32).toInt();
}

extension IntUtils on int {

  int get uint32 => toUnsigned(32);
  int get int32 => toSigned(32);

  String toStringAligned(int width, { int radix = 10, }) {
    return radixString(leading: false, width: width, radix: radix);
  }

  /// width is the code unit width, not byte width
  String radixString({ bool leading = true, int width = -1, int radix = 16, }) {
    var str = this.toRadixString(radix);

    if (width > str.length && (width - str.length) < _zeroStr.length)
      str = _zeroStr.substring(0, width - str.length) + str;

    if (leading) {
      var lStr;
      switch (radix) {
        case 2: lStr = '0b'; break;
        case 16: lStr = '0x'; break;
        default: lStr = '[Radix $radix]'; break;
      }
      return "$lStr$str";
    } else
      return str;
  }

}

extension ByteUtils on Uint8List {

  int toSignedInt(){
    var offset = length * 8;
    var val = toInt();

    if (offset <= 0)
      return val;

    if (this[0] & 0x80 != 0) {
      val &= ~(0x1 << (offset - 1));
      var s = -1 << offset;
      return val | s;
    } else {
      return val | (0x1 << (offset - 1));
    }
  }

  Int64 toInt64(){
    var bytes = this;

    var length = bytes.length;
    if (length == 0 || length > 8) {
      throw IllegalArgumentException("bytes length must be > 0 & < 8, not: $length.");
    }

    Int64 value = Int64(0);
    for (int i = 0; i < length; i++) {
      value |= bytes[i] << ((length - i - 1) * 8);
    }
    return value;
  }

  int toInt(){
    var length = this.length;
    if (length == 0 || length > MAX_SAFE_INT_SIZE) {
      throw IllegalArgumentException("bytes length must be > 0 & < $MAX_SAFE_INT_SIZE, not: $length.");
    }

    return toInt64().toInt();
  }

  void copyTo(Uint8List dest, int destOffset, [int? len]) {
    len = len ?? length;

    for (int idx = 0; idx < len; ++idx)
      dest[destOffset + idx] = this[idx];
  }

  bool equals(List<int>? other) {
    if (other == null || other.length != length)
      return false;

    for (var idx = 0; idx < length; ++idx) {
      if (other[idx] != this[idx])
        return false;
    }

    return true;
  }

  String hexString({ bool withOx = true, }) {
    return withOx ? "0x${HEX.encode(this)}" : HEX.encode(this);
  }

  String get hex => hexString();

  static Uint8List fromHexString(String hex) {
    return Uint8List.fromList(HEX.decode(hex));
  }

  static Uint8List concatAll(List<List<int>> lists) {
    return Uint8List(0).concat(lists);
  }

  Uint8List concat(List<List<int>> lists) {
    var r = <int> [...this];
    for (var list in lists) {
      r.addAll(list);
    }

    return Uint8List.fromList(r);
  }

}

extension StringExt on String {

  Uint8List get hexDecodedBytes => ByteUtils.fromHexString(this);
  Uint8List get codeBytes => codeUnits.bytes;

}

extension IntListExt on List<int> {

  void fill(int val) {
    fillRange(0, length, val);
  }

  void fillZero() { fill(0); }

  Uint8List get bytes => this is Uint8List ? this as Uint8List : Uint8List.fromList(this);

}

extension Uint8Ext on Uint8List {
  static const size = 1;

  Uint8List subView([int? start, int? end]) {
    start ??= 0;
    var len = end != null ? (end - start) : null;

    return Uint8List.view(buffer, offsetInBytes + start*size, len);
  }
}

extension Uint32Ext on Uint32List {
  static const size = 4;

  Uint32List subView([int? start, int? end]) {
    start ??= 0;
    var len = end != null ? (end - start) : null;

    return Uint32List.view(buffer, offsetInBytes + start*size, len);
  }

  Uint8List get bytesView => Uint8List.view(buffer, offsetInBytes, lengthInBytes);

}


class NoneCopyList<E> extends ListMixin<E> {
  List<E> under;
  late int start;
  late int end;

  @override
  late int length;

  NoneCopyList(this.under, [int? start, int? end]) {
    this.start = start ??= 0;
    this.end = end ??= under.length;

    if (start < 0) throw IllegalArgumentException('start($start) should > 0');
    if (end < start) throw IllegalArgumentException('end($end) should larger than start($start).');
    if (end > under.length) throw IllegalArgumentException('end($end) should less than under.length(${under.length}).');

    length = end - start;
  }

  @override
  operator [](int index) {
    return under[start + index];
  }

  @override
  void operator []=(int index, value) {
    under[start + index] = value;
  }

}

extension ListExt<E> on List<E> {

  List<E> subView([int? start, int? end]) {
    return NoneCopyList(this, start, end);
  }

}


void copyTo(Uint8List src, Uint8List dest, destOffset) {
  for (int idx = 0; idx < src.length; ++idx)
    dest[destOffset + idx] = src[idx];
}

var rand = Random();
Uint8List randomBytes(int len, { Uint8List? bytes,  bool noDuplicates = false, }) {
  bytes ??= Uint8List(len);

  if (noDuplicates) {
    if (len > 128) throw IllegalArgumentException('randomBytes() with noDuplicates = true, len should <= 128, not: $len.');

    Set<int> duplicates = {};
    for (len--; len >= 0; --len) {
      var v = rand.nextInt(0xFF);
      while (duplicates.contains(v)) {
        v = rand.nextInt(0xFF);
      }

      duplicates.add(v);
      bytes[len] = v;
    }
  } else {
    for (len--; len >= 0; --len) {
      bytes[len] = rand.nextInt(0xFF);
    }
  }

  return bytes;
}

abstract class ExceptionWithMessage<T> extends Error {
  final String?   msg;
  final T?        data;

  ExceptionWithMessage(this.msg, { this.data, });

  @override
  String toString() => "$runtimeType: $msg";
}

String errorMsg(e, [StackTrace? trace]) {
  if (e is Error) return "$e\n${e.stackTrace}\nWhere:\n${trace ?? StackTrace.current}";
  else return "${e is Exception ? "[tips: Use Error, Not Exception]" : ""}$e\nWhere:\n${trace ?? StackTrace.current}";
}

class IllegalArgumentException extends ExceptionWithMessage {
  IllegalArgumentException(String msg) : super(msg);
}


class CryptoError<T> extends ExceptionWithMessage<T> {
  CryptoError(String msg, { T? data }) : super(msg, data: data);
}


_utc() { return DateTime.now().toIso8601String(); }

class Log {

  static bool enable = false;

  static const int
    VERBOSE = 2,
    DEBUG = 3,
    INFO = 4,
    WARN = 5,
    ERROR = 6,
    ASSERT = 7
  ;

  static const _levelStr = [ "VERBOSE", "DEBUG", "INFO", "WARN", "ERROR", "ASSERT" ];

  static log(String tag, String m, int? level) {
    level = level ?? VERBOSE;
    if (level < VERBOSE) level = VERBOSE;
    else if (level > ASSERT) level = ASSERT;

    var s = _levelStr[level - 2];
    print("[${_utc()}] [$s] $tag $m");
  }

  static a(String tag, String Function() m, [dynamic e, dynamic stacktrace]) { if (enable) log(tag, e != null ? '${m()} ${errorMsg(e, stacktrace)}' : m(), ASSERT); }
  static d(String tag, String Function() m, [dynamic e, dynamic stacktrace]) { if (enable) log(tag, e != null ? '${m()} ${errorMsg(e, stacktrace)}' : m(), DEBUG); }
  static v(String tag, String Function() m, [dynamic e, dynamic stacktrace]) { if (enable) log(tag, e != null ? '${m()} ${errorMsg(e, stacktrace)}' : m(), VERBOSE); }
  static i(String tag, String Function() m, [dynamic e, dynamic stacktrace]) { if (enable) log(tag, e != null ? '${m()} ${errorMsg(e, stacktrace)}' : m(), INFO); }
  static w(String tag, String Function() m, [dynamic e, dynamic stacktrace]) { if (enable) log(tag, e != null ? '${m()} ${errorMsg(e, stacktrace)}' : m(), WARN); }
  static e(String tag, String Function() m, [dynamic e, dynamic stacktrace]) { if (enable) log(tag, e != null ? '${m()} ${errorMsg(e, stacktrace)}' : m(), ERROR); }

}