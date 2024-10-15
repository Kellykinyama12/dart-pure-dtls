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
    return HandshakeMessageCertificateRequest(
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
  }

  Uint8List marshal() {
    // Implement the marshalling logic here
    // This is a placeholder implementation
    return Uint8List.fromList([
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
    ]);
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
  assert(c.certificateTypes == parsedCertificateRequest.certificateTypes);
  assert(c.signatureHashAlgorithms.length ==
      parsedCertificateRequest.signatureHashAlgorithms.length);

  Uint8List marshalled = c.marshal();
  assert(marshalled.toString() == rawCertificateRequest.toString());
}

void main() {
  testHandshakeMessageCertificateRequest();
}
