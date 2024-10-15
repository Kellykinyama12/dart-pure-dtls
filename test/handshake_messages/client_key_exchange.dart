import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

class HandshakeMessageClientKeyExchange {
  final List<int> identityHint;
  final List<int> publicKey;

  HandshakeMessageClientKeyExchange({
    required this.identityHint,
    required this.publicKey,
  });

  static HandshakeMessageClientKeyExchange unmarshal(Uint8List data) {
    // Implement the unmarshalling logic here
    // This is a placeholder implementation
    if (data.length > 2) {
      int pskLength = (data << 8) | data;
      if (data.length == pskLength + 2) {
        return HandshakeMessageClientKeyExchange(
          identityHint: data.sublist(2),
          publicKey: [],
        );
      }
    }
    int publicKeyLength = data;
    if (data.length != publicKeyLength + 1) {
      throw Exception('Buffer too small');
    }
    return HandshakeMessageClientKeyExchange(
      identityHint: [],
      publicKey: data.sublist(1),
    );
  }

  Uint8List marshal() {
    // Implement the marshalling logic here
    // This is a placeholder implementation
    if (identityHint.isNotEmpty && publicKey.isNotEmpty) {
      throw Exception('Invalid Client Key Exchange');
    }
    if (publicKey.isNotEmpty) {
      return Uint8List.fromList([publicKey.length, ...publicKey]);
    } else {
      return Uint8List.fromList([
        (identityHint.length >> 8) & 0xFF,
        identityHint.length & 0xFF,
        ...identityHint,
      ]);
    }
  }
}

void testHandshakeMessageClientKeyExchange() {
  List<int> rawClientKeyExchange = [
    0x20,
    0x26,
    0x78,
    0x4a,
    0x78,
    0x70,
    0xc1,
    0xf9,
    0x71,
    0xea,
    0x50,
    0x4a,
    0xb5,
    0xbb,
    0x00,
    0x76,
    0x02,
    0x05,
    0xda,
    0xf7,
    0xd0,
    0x3f,
    0xe3,
    0xf7,
    0x4e,
    0x8a,
    0x14,
    0x6f,
    0xb7,
    0xe0,
    0xc0,
    0xff,
    0x54,
  ];

  HandshakeMessageClientKeyExchange parsedClientKeyExchange =
      HandshakeMessageClientKeyExchange(
    identityHint: [],
    publicKey: rawClientKeyExchange.sublist(1),
  );

  Uint8List raw = Uint8List.fromList(rawClientKeyExchange);
  HandshakeMessageClientKeyExchange c =
      HandshakeMessageClientKeyExchange.unmarshal(raw);
  assert(c.identityHint.toString() ==
      parsedClientKeyExchange.identityHint.toString());
  assert(
      c.publicKey.toString() == parsedClientKeyExchange.publicKey.toString());

  Uint8List marshalled = c.marshal();
  assert(marshalled.toString() == rawClientKeyExchange.toString());
}

void main() {
  testHandshakeMessageClientKeyExchange();
}
