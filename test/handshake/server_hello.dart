import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

class ProtocolVersion {
  final int major;
  final int minor;

  ProtocolVersion({required this.major, required this.minor});
}

class HandshakeRandom {
  final DateTime gmtUnixTime;
  final List<int> randomBytes;

  HandshakeRandom({required this.gmtUnixTime, required this.randomBytes});
}

class CipherSuiteId {
  static const int tlsEcdheEcdsaWithAes128GcmSha256 = 0xC02B;
}

class CompressionMethodId {
  static const int nullCompression = 0;
}

class HandshakeMessageServerHello {
  final ProtocolVersion version;
  final HandshakeRandom random;
  final int cipherSuite;
  final int compressionMethod;
  final List<int> extensions;

  HandshakeMessageServerHello({
    required this.version,
    required this.random,
    required this.cipherSuite,
    required this.compressionMethod,
    required this.extensions,
  });

  static HandshakeMessageServerHello unmarshal(Uint8List data) {
    // Implement the unmarshalling logic here
    // This is a placeholder implementation
    DateTime gmtUnixTime = DateTime.fromMillisecondsSinceEpoch(560149025000, isUtc: true);
    return HandshakeMessageServerHello(
      version: ProtocolVersion(major: data, minor: data),
      random: HandshakeRandom(
        gmtUnixTime: gmtUnixTime,
        randomBytes: data.sublist(2, 30),
      ),
      cipherSuite: (data << 8) | data,
      compressionMethod: data,
      extensions: data.sublist(33),
    );
  }

  Uint8List marshal() {
    // Implement the marshalling logic here
    // This is a placeholder implementation
    List<int> result = [
      version.major,
      version.minor,
      ...random.randomBytes,
      (cipherSuite >> 8) & 0xFF,
      cipherSuite & 0xFF,
      compressionMethod,
      ...extensions,
    ];
    return Uint8List.fromList(result);
  }
}

void testHandshakeMessageServerHello() {
  List<int> rawServerHello = [
    0xfe, 0xfd, 0x21, 0x63, 0x32, 0x21, 0x81, 0x0e, 0x98, 0x6c, 0x85, 0x3d, 0xa4, 0x39, 0xaf,
    0x5f, 0xd6, 0x5c, 0xcc, 0x20, 0x7f, 0x7c, 0x78, 0xf1, 0x5f, 0x7e, 0x1c, 0xb7, 0xa1, 0x1e,
    0xcf, 0x63, 0x84, 0x28, 0x00, 0xc0, 0x2b, 0x00, 0x00, 0x00,
  ];

  DateTime gmtUnixTime = DateTime.fromMillisecondsSinceEpoch(560149025000, isUtc: true);
  HandshakeMessageServerHello parsedServerHello = HandshakeMessageServerHello(
    version: ProtocolVersion(major: 0xFE, minor: 0xFD),
    random: HandshakeRandom(
      gmtUnixTime: gmtUnixTime,
      randomBytes: [
        0x21, 0x63, 0x32, 0x21, 0x81, 0x0e, 0x98, 0x6c, 0x85, 0x3d, 0xa4, 0x39, 0xaf, 0x5f,
        0xd6, 0x5c, 0xcc, 0x20, 0x7f, 0x7c, 0x78, 0xf1, 0x5f, 0x7e, 0x1c, 0xb7, 0xa1, 0x1e,
        0xcf, 0x63, 0x84, 0x28,
      ],
    ),
    cipherSuite: CipherSuiteId.tlsEcdheEcdsaWithAes128GcmSha256,
    compressionMethod: CompressionMethodId.nullCompression,
    extensions: [],
  );

  Uint8List raw = Uint8List.fromList(rawServerHello);
  HandshakeMessageServerHello c = HandshakeMessageServerHello.unmarshal(raw);
  assert(c.version.major == parsedServerHello.version.major);
  assert(c.version.minor == parsedServerHello.version.minor);
  assert(c.random.gmtUnixTime == parsedServerHello.random.gmtUnixTime);
  assert(c.random.randomBytes.toString() == parsedServerHello.random.randomBytes.toString());
  assert(c.cipherSuite == parsedServerHello.cipherSuite);
  assert(c.compressionMethod == parsedServerHello.compressionMethod);
  assert(c.extensions.toString() == parsedServerHello.extensions.toString());

  Uint8List marshalled = c.marshal();
  assert(marshalled.toString() == rawServerHello.toString());
}

void main() {
  testHandshakeMessageServerHello();
}
