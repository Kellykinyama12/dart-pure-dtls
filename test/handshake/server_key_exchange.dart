import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

class EllipticCurveType {
  static const int namedCurve = 3;
}

class NamedCurve {
  static const int x25519 = 0x001D;
}

class HashAlgorithm {
  static const int sha1 = 2;
}

class SignatureAlgorithm {
  static const int ecdsa = 3;
}

class SignatureHashAlgorithm {
  final int hash;
  final int signature;

  SignatureHashAlgorithm({required this.hash, required this.signature});
}

class HandshakeMessageServerKeyExchange {
  final List<int> identityHint;
  final int ellipticCurveType;
  final int namedCurve;
  final List<int> publicKey;
  final SignatureHashAlgorithm algorithm;
  final List<int> signature;

  HandshakeMessageServerKeyExchange({
    required this.identityHint,
    required this.ellipticCurveType,
    required this.namedCurve,
    required this.publicKey,
    required this.algorithm,
    required this.signature,
  });

  static HandshakeMessageServerKeyExchange unmarshal(Uint8List data) {
    // Implement the unmarshalling logic here
    // This is a placeholder implementation
    return HandshakeMessageServerKeyExchange(
      identityHint: [],
      ellipticCurveType: data,
      namedCurve: (data << 8) | data,
      publicKey: data.sublist(4, 69),
      algorithm: SignatureHashAlgorithm(
        hash: data,
        signature: data,
      ),
      signature: data.sublist(73),
    );
  }

  Uint8List marshal() {
    // Implement the marshalling logic here
    // This is a placeholder implementation
    List<int> result = [
      ellipticCurveType,
      (namedCurve >> 8) & 0xFF,
      namedCurve & 0xFF,
      0x41, // Length of public key
      ...publicKey,
      algorithm.hash,
      algorithm.signature,
      0x00, 0x47, // Placeholder for the length
      ...signature,
    ];
    return Uint8List.fromList(result);
  }
}

void testHandshakeMessageServerKeyExchange() {
  List<int> rawServerKeyExchange = [
    0x03,
    0x00,
    0x1d,
    0x41,
    0x04,
    0x0c,
    0xb9,
    0xa3,
    0xb9,
    0x90,
    0x71,
    0x35,
    0x4a,
    0x08,
    0x66,
    0xaf,
    0xd6,
    0x88,
    0x58,
    0x29,
    0x69,
    0x98,
    0xf1,
    0x87,
    0x0f,
    0xb5,
    0xa8,
    0xcd,
    0x92,
    0xf6,
    0x2b,
    0x08,
    0x0c,
    0xd4,
    0x16,
    0x5b,
    0xcc,
    0x81,
    0xf2,
    0x58,
    0x91,
    0x8e,
    0x62,
    0xdf,
    0xc1,
    0xec,
    0x72,
    0xe8,
    0x47,
    0x24,
    0x42,
    0x96,
    0xb8,
    0x7b,
    0xee,
    0xe7,
    0x0d,
    0xdc,
    0x44,
    0xec,
    0xf3,
    0x97,
    0x6b,
    0x1b,
    0x45,
    0x28,
    0xac,
    0x3f,
    0x35,
    0x02,
    0x03,
    0x00,
    0x47,
    0x30,
    0x45,
    0x02,
    0x21,
    0x00,
    0xb2,
    0x0b,
    0x22,
    0x95,
    0x3d,
    0x56,
    0x57,
    0x6a,
    0x3f,
    0x85,
    0x30,
    0x6f,
    0x55,
    0xc3,
    0xf4,
    0x24,
    0x1b,
    0x21,
    0x07,
    0xe5,
    0xdf,
    0xba,
    0x24,
    0x02,
    0x68,
    0x95,
    0x1f,
    0x6e,
    0x13,
    0xbd,
    0x9f,
    0xaa,
    0x02,
    0x20,
    0x49,
    0x9c,
    0x9d,
    0xdf,
    0x84,
    0x60,
    0x33,
    0x27,
    0x96,
    0x9e,
    0x58,
    0x6d,
    0x72,
    0x13,
    0xe7,
    0x3a,
    0xe8,
    0xdf,
    0x43,
    0x75,
    0xc7,
    0xb9,
    0x37,
    0x6e,
    0x90,
    0xe5,
    0x3b,
    0x81,
    0xd4,
    0xda,
    0x68,
    0xcd,
  ];

  HandshakeMessageServerKeyExchange parsedServerKeyExchange =
      HandshakeMessageServerKeyExchange(
    identityHint: [],
    ellipticCurveType: EllipticCurveType.namedCurve,
    namedCurve: NamedCurve.x25519,
    publicKey: rawServerKeyExchange.sublist(4, 69),
    algorithm: SignatureHashAlgorithm(
      hash: HashAlgorithm.sha1,
      signature: SignatureAlgorithm.ecdsa,
    ),
    signature: rawServerKeyExchange.sublist(73),
  );

  Uint8List raw = Uint8List.fromList(rawServerKeyExchange);
  HandshakeMessageServerKeyExchange c =
      HandshakeMessageServerKeyExchange.unmarshal(raw);
  assert(c.identityHint.toString() ==
      parsedServerKeyExchange.identityHint.toString());
  assert(c.ellipticCurveType == parsedServerKeyExchange.ellipticCurveType);
  assert(c.namedCurve == parsedServerKeyExchange.namedCurve);
  assert(
      c.publicKey.toString() == parsedServerKeyExchange.publicKey.toString());
  assert(c.algorithm.hash == parsedServerKeyExchange.algorithm.hash);
  assert(c.algorithm.signature == parsedServerKeyExchange.algorithm.signature);
  assert(
      c.signature.toString() == parsedServerKeyExchange.signature.toString());

  Uint8List marshalled = c.marshal();
  assert(marshalled.toString() == rawServerKeyExchange.toString());
}

void main() {
  testHandshakeMessageServerKeyExchange();
}
