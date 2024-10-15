import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

class ClientCertificateType {
  static const int rsaSign = 1;
  static const int ecdsaSign = 64;
}

class HashAlgorithm {
  static const int sha256 = 4;
  static const int sha384 = 5;
  static const int sha512 = 6;
  static const int sha1 = 2;
}

class SignatureAlgorithm {
  static const int ecdsa = 3;
  static const int rsa = 1;
}

class SignatureHashAlgorithm {
  final int hash;
  final int signature;

  SignatureHashAlgorithm({required this.hash, required this.signature});
}

class HandshakeMessageCertificateRequest {
  final List<int> certificateTypes;
  final List<SignatureHashAlgorithm> signatureHashAlgorithms;

  HandshakeMessageCertificateRequest({
    required this.certificateTypes,
    required this.signatureHashAlgorithms,
  });

  static HandshakeMessageCertificateRequest unmarshal(Uint8List data) {
    // Implement the unmarshalling logic here
    // This is a placeholder implementation
    int certificateTypesLength = data;
    List<int> certificateTypes = data.sublist(1, 1 + certificateTypesLength);
    int signatureHashAlgorithmsLength =
        (data[1 + certificateTypesLength] << 8) |
            data[2 + certificateTypesLength];
    List<SignatureHashAlgorithm> signatureHashAlgorithms = [];
    for (int i = 0; i < signatureHashAlgorithmsLength; i += 2) {
      int hash = data[3 + certificateTypesLength + i];
      int signature = data[4 + certificateTypesLength + i];
      signatureHashAlgorithms
          .add(SignatureHashAlgorithm(hash: hash, signature: signature));
    }
    return HandshakeMessageCertificateRequest(
      certificateTypes: certificateTypes,
      signatureHashAlgorithms: signatureHashAlgorithms,
    );
  }

  Uint8List marshal() {
    // Implement the marshalling logic here
    // This is a placeholder implementation
    List<int> result = [
      certificateTypes.length,
      ...certificateTypes,
      (signatureHashAlgorithms.length * 2) >> 8,
      (signatureHashAlgorithms.length * 2) & 0xFF,
      for (var alg in signatureHashAlgorithms) ...[alg.hash, alg.signature],
      0x00, 0x00, // Distinguished Names Length
    ];
    return Uint8List.fromList(result);
  }
}

void testHandshakeMessageCertificateRequest() {
  List<int> rawCertificateRequest = [
    0x02,
    0x01,
    0x40,
    0x00,
    0x0C,
    0x04,
    0x03,
    0x04,
    0x01,
    0x05,
    0x03,
    0x05,
    0x01,
    0x06,
    0x01,
    0x02,
    0x01,
    0x00,
    0x00,
  ];

  HandshakeMessageCertificateRequest parsedCertificateRequest =
      HandshakeMessageCertificateRequest(
    certificateTypes: [
      ClientCertificateType.rsaSign,
      ClientCertificateType.ecdsaSign
    ],
    signatureHashAlgorithms: [
      SignatureHashAlgorithm(
          hash: HashAlgorithm.sha256, signature: SignatureAlgorithm.ecdsa),
      SignatureHashAlgorithm(
          hash: HashAlgorithm.sha256, signature: SignatureAlgorithm.rsa),
      SignatureHashAlgorithm(
          hash: HashAlgorithm.sha384, signature: SignatureAlgorithm.ecdsa),
      SignatureHashAlgorithm(
          hash: HashAlgorithm.sha384, signature: SignatureAlgorithm.rsa),
      SignatureHashAlgorithm(
          hash: HashAlgorithm.sha512, signature: SignatureAlgorithm.rsa),
      SignatureHashAlgorithm(
          hash: HashAlgorithm.sha1, signature: SignatureAlgorithm.rsa),
    ],
  );

  Uint8List raw = Uint8List.fromList(rawCertificateRequest);
  HandshakeMessageCertificateRequest c =
      HandshakeMessageCertificateRequest.unmarshal(raw);
  assert(c.certificateTypes.toString() ==
      parsedCertificateRequest.certificateTypes.toString());
  assert(c.signatureHashAlgorithms.length ==
      parsedCertificateRequest.signatureHashAlgorithms.length);

  Uint8List marshalled = c.marshal();
  assert(marshalled.toString() == rawCertificateRequest.toString());
}

void main() {
  testHandshakeMessageCertificateRequest();
}
