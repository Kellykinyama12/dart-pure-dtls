import 'dart:typed_data';
import 'dart:math';
import 'package:dart_dtls_final/record_header.dart';
import 'package:pointycastle/export.dart';

const int gcmTagLength = 16;
const int gcmNonceLength = 12;
const int headerSize = 13;

class GCM {
  final AEADBlockCipher localGCM;
  final AEADBlockCipher remoteGCM;
  final Uint8List localWriteIV;
  final Uint8List remoteWriteIV;

  GCM(this.localGCM, this.localWriteIV, this.remoteGCM, this.remoteWriteIV);

  static Future<GCM> create(Uint8List localKey, Uint8List localWriteIV,
      Uint8List remoteKey, Uint8List remoteWriteIV) async {
    final localCipher = GCMBlockCipher(AESEngine());
    final remoteCipher = GCMBlockCipher(AESEngine());

    localCipher.init(
        true,
        AEADParameters(KeyParameter(localKey), gcmTagLength * 8, localWriteIV,
            Uint8List(0)));
    remoteCipher.init(
        false,
        AEADParameters(KeyParameter(remoteKey), gcmTagLength * 8, remoteWriteIV,
            Uint8List(0)));

    return GCM(localCipher, localWriteIV, remoteCipher, remoteWriteIV);
  }

  Future<Uint8List> encrypt(RecordHeader header, Uint8List raw) async {
    final nonce = Uint8List(gcmNonceLength);
    nonce.setRange(0, 4, localWriteIV.sublist(0, 4));
    final random = Random.secure();
    for (int i = 4; i < gcmNonceLength; i++) {
      nonce[i] = random.nextInt(256);
    }

    final additionalData = generateAEADAdditionalData(header, raw.length);
    localGCM.init(
        true,
        AEADParameters(KeyParameter(localWriteIV), gcmTagLength * 8, nonce,
            additionalData));

    // final encryptedPayload = Uint8List(localGCM.getOutputSize(raw.length));
    final encryptedPayload = Uint8List(raw.length);
    final len = localGCM.processBytes(raw, 0, raw.length, encryptedPayload, 0);
    localGCM.doFinal(encryptedPayload, len);

    final result = Uint8List(nonce.length - 4 + encryptedPayload.length);
    result.setRange(0, nonce.length - 4, nonce.sublist(4));
    result.setRange(nonce.length - 4, result.length, encryptedPayload);

    return result;
  }

  Future<Uint8List> decrypt(RecordHeader header, Uint8List inData) async {
    if (header.contentType == ContentType.ChangeCipherSpec) {
      return inData;
    }

    final nonce = Uint8List(gcmNonceLength);
    nonce.setRange(0, 4, remoteWriteIV.sublist(0, 4));
    nonce.setRange(4, gcmNonceLength, inData.sublist(0, 8));

    final out = inData.sublist(8);
    final additionalData =
        generateAEADAdditionalData(header, out.length - gcmTagLength);

    remoteGCM.init(
        false,
        AEADParameters(KeyParameter(remoteWriteIV), gcmTagLength * 8, nonce,
            additionalData));

    // final decryptedPayload = Uint8List(remoteGCM.getOutputSize(out.length));
    final decryptedPayload = Uint8List(out.length);
    final len = remoteGCM.processBytes(out, 0, out.length, decryptedPayload, 0);
    remoteGCM.doFinal(decryptedPayload, len);

    return decryptedPayload;
  }
}

Uint8List generateAEADAdditionalData(RecordHeader header, int length) {
  // Implement your logic to generate AEAD additional data
  return Uint8List(0);
}
