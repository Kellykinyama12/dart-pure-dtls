import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

class SignatureHashAlgorithm {
  final int hash;
  final int signature;

  SignatureHashAlgorithm({required this.hash, required this.signature});
}

class HandshakeMessageCertificateVerify {
  final SignatureHashAlgorithm algorithm;
  final List<int> signature;

  HandshakeMessageCertificateVerify({
    required this.algorithm,
    required this.signature,
  });

  static HandshakeMessageCertificateVerify unmarshal(Uint8List data) {
    // Implement the unmarshalling logic here
    // This is a placeholder implementation
    return HandshakeMessageCertificateVerify(
      algorithm: SignatureHashAlgorithm(
        hash: data,
        signature: data,
      ),
      signature: data.sublist(4),
    );
  }

  Uint8List marshal() {
    // Implement the marshalling logic here
    // This is a placeholder implementation
    return Uint8List.fromList([
      algorithm.hash,
      algorithm.signature,
      0x00, 0x47, // Placeholder for the length
      ...signature,
    ]);
  }
}

void testHandshakeMessageCertificateVerify() {
  List<int> rawCertificateVerify = [
    0x04,
    0x03,
    0x00,
    0x47,
    0x30,
    0x45,
    0x02,
    0x20,
    0x6b,
    0x63,
    0x17,
    0xad,
    0xbe,
    0xb7,
    0x7b,
    0x0f,
    0x86,
    0x73,
    0x39,
    0x1e,
    0xba,
    0xb3,
    0x50,
    0x9c,
    0xce,
    0x9c,
    0xe4,
    0x8b,
    0xe5,
    0x13,
    0x07,
    0x59,
    0x18,
    0x1f,
    0xe5,
    0xa0,
    0x2b,
    0xca,
    0xa6,
    0xad,
    0x02,
    0x21,
    0x00,
    0xd3,
    0xb5,
    0x01,
    0xbe,
    0x87,
    0x6c,
    0x04,
    0xa1,
    0xdc,
    0x28,
    0xaa,
    0x5f,
    0xf7,
    0x1e,
    0x9c,
    0xc0,
    0x1e,
    0x00,
    0x2c,
    0xe5,
    0x94,
    0xbb,
    0x03,
    0x0e,
    0xf1,
    0xcb,
    0x28,
    0x22,
    0x33,
    0x23,
    0x88,
    0xad,
  ];

  HandshakeMessageCertificateVerify parsedCertificateVerify =
      HandshakeMessageCertificateVerify(
    algorithm: SignatureHashAlgorithm(
      hash: rawCertificateVerify,
      signature: rawCertificateVerify,
    ),
    signature: rawCertificateVerify.sublist(4),
  );

  Uint8List raw = Uint8List.fromList(rawCertificateVerify);
  HandshakeMessageCertificateVerify c =
      HandshakeMessageCertificateVerify.unmarshal(raw);
  assert(c.algorithm.hash == parsedCertificateVerify.algorithm.hash);
  assert(c.algorithm.signature == parsedCertificateVerify.algorithm.signature);
  assert(
      c.signature.toString() == parsedCertificateVerify.signature.toString());

  Uint8List marshalled = c.marshal();
  assert(marshalled.toString() == rawCertificateVerify.toString());
}

void main() {
  testHandshakeMessageCertificateVerify();
}
