
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';
import 'package:tinycrypt/tinycrypt.dart';


void main() {

  test("AES-CBC test", () {
    var key = Uint8List.fromList([1,2,3,4,5,6,7,8,9,0,6,5,4,3,2,1]);
    var iv = Uint8List.fromList("ABCDEFGHIJKLMNOPQRSTUVWXYZ".substring(0, 16).codeUnits);

    var data = [
      [
        Uint8List.fromList("1234567890123456".codeUnits),
        Uint8List.fromList(HEX.decode("92d6b5681b5d96603f4ce365c1edebe6"))
      ],
      [
        Uint8List.fromList([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,]),
        Uint8List.fromList(HEX.decode("7faf7031f08242283f098ce908cb77fb"))
      ],
    ];

    print("AES key: ${key.hexString()}, iv: ${iv.hexString()}");

    for (var sp in data) {
      var inData = sp[0];
      var outData = sp[1];
      var enc = aesCbcEncrypt(key, iv, inData);
      var dec = aesCbcDecrypt(key, iv, enc);

      print("in: ${inData.hexString()}, out: ${outData.hexString()}, enc: ${enc.hexString()}, dec: ${dec.hexString()}");

      assert(enc.equals(outData));
      assert(dec.equals(inData));
    }


  });

  test("AES-CCM test", () {
    // key, iv, data, aad, enc, mic.
    List<List<String>> tis = [
      [
        "52e23937b957a45b6f5298c5f379c694",
        "b405f4e09a0695390cf81a7c90",
        "0000000000000000000000000000000016ea",
        '',
        "eabe2243288c356f57e7ec90d4c7f672db78",
        "f18e095a",
      ],
      [
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
        "00000003020100a0a1a2a3a4a5",
        "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
        "0001020304050607",
        "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384",
        "17e8d12cfdf926e0",
      ],
    ];

    for (var ti in tis) {
      var key = Uint8List.fromList(HEX.decode(ti[0]));
      var iv = Uint8List.fromList(HEX.decode(ti[1]));
      var data = Uint8List.fromList(HEX.decode(ti[2]));
      var aad = ti[3] != '' ? Uint8List.fromList(HEX.decode(ti[3])) : null;

      var encData = Uint8List.fromList(HEX.decode(ti[4]));
      var tag = Uint8List.fromList(HEX.decode(ti[5]));
      var cipherText = encData.concat([tag]);

      // print("key: ${_h(key)}, iv: ${_h(iv)}, data: ${_h(data)}, cipherText: ${_h(cipherText)}.");

      var enc = aesCcmEncrypt(key, iv, aad, data, tag.length);
      print("enc: ${enc.hexString()}");

      assert(enc.equals(cipherText));

      var dec = aesCcmDecrypt(key, iv, aad, enc, tag.length);
      print("dec: ${dec.hexString()}");
      assert(dec.equals(data));
    }
  });



  test("AesCcm", () {
    var key = ByteUtils.fromHexString("8507bb37df0d11a6bbc2c45c4a414f47");
    var nonce = ByteUtils.fromHexString("0210007c00005fb5dae6000e00");
    var aad = ByteUtils.fromHexString("12110c250cf5a849b79ee7fa66e7006f8710007c000010007e0000005fb5dae6000e524e4b31037000");
    var data = ByteUtils.fromHexString("45c401c1091101800888080100fd69c2e2ad7688088888c10d0e020c4107ad01a13ebb2869ad3e13c1110102c1490100c14c0120c14a0120c110020208c10403014f45c105084f4538383838383800");
    var enc = ByteUtils.fromHexString("cbec5b6f477452b8376e82239f07c644783efb825a550306b155ad862bf362837ab48aabd4f1dec36b08ba5f560d7d1396fd03cc495c42b4898160bfada974e2335b312735e89561e9fa8a8736e17e");
    var mic = ByteUtils.fromHexString("5617a60a1286ef0f");
    var micSize = mic.length;

    assert(aesCcmEncrypt(key, nonce, aad, data, micSize).equals(ByteUtils.concatAll([enc, mic])));
    assert(aesCcmDecrypt(key, nonce, aad, ByteUtils.concatAll([enc, mic]), micSize).equals(data));
  });



  test("AesCbc", () {
    var key = ByteUtils.fromHexString("a607367488dca0958f89d06b39ca0da1");
    var nonce = ByteUtils.fromHexString("006c32caf655d90c927d8b63d38a3f07");
    var data = ByteUtils.fromHexString("20110c250cf5a849b79ee7fa66e7006f8710007e000010007c0010000000007f0000000000000100000000005fb634000060524e4b3101703f0217c0e87310476d8e0c7db10b0b0b0b0b0b0b0b0b0b0b");
    var enc = ByteUtils.fromHexString("b0598981dc572ed01056e8dcb2456f95114d9980e58b808da1c922aa082d4f18625c23d1ee0cefe5de40ed372c410eeaa177565eeef838099100b91a6628b5593ae35d0d1c1c5c88f70865e62fd65dde");

    assert(aesCbcEncrypt(key, nonce, data).equals(enc));
    assert(aesCbcDecrypt(key, nonce, enc).equals(data));
  });




}