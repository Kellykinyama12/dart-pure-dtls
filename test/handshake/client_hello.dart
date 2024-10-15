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
  static const int tlsEcdheEcdsaWithAes256CbcSha = 0xC00A;
}

class CompressionMethodId {
  static const int nullCompression = 0;
}

class CompressionMethods {
  final List<int> ids;

  CompressionMethods({required this.ids});
}

class NamedCurve {
  static const int x25519 = 0x001D;
}

class ExtensionSupportedEllipticCurves {
  final List<int> ellipticCurves;

  ExtensionSupportedEllipticCurves({required this.ellipticCurves});
}

class Extension {
  final ExtensionSupportedEllipticCurves supportedEllipticCurves;

  Extension({required this.supportedEllipticCurves});
}

class HandshakeMessageClientHello {
  final ProtocolVersion version;
  final HandshakeRandom random;
  final List<int> cookie;
  final List<int> cipherSuites;
  final CompressionMethods compressionMethods;
  final List<Extension> extensions;

  HandshakeMessageClientHello({
    required this.version,
    required this.random,
    required this.cookie,
    required this.cipherSuites,
    required this.compressionMethods,
    required this.extensions,
  });

  static HandshakeMessageClientHello unmarshal(Uint8List data) {
    // Implement the unmarshalling logic here
    // This is a placeholder implementation
    DateTime gmtUnixTime =
        DateTime.fromMillisecondsSinceEpoch(3056586332000, isUtc: true);
    return HandshakeMessageClientHello(
      version: ProtocolVersion(major: data, minor: data),
      random: HandshakeRandom(
        gmtUnixTime: gmtUnixTime,
        randomBytes: data.sublist(2, 34),
      ),
      cookie: data.sublist(34, 54),
      cipherSuites: [
        CipherSuiteId.tlsEcdheEcdsaWithAes128GcmSha256,
        CipherSuiteId.tlsEcdheEcdsaWithAes256CbcSha
      ],
      compressionMethods:
          CompressionMethods(ids: [CompressionMethodId.nullCompression]),
      extensions: [
        Extension(
          supportedEllipticCurves: ExtensionSupportedEllipticCurves(
            ellipticCurves: [NamedCurve.x25519],
          ),
        ),
      ],
    );
  }

  Uint8List marshal() {
    // Implement the marshalling logic here
    // This is a placeholder implementation
    List<int> result = [
      version.major,
      version.minor,
      ...random.randomBytes,
      ...cookie,
      0x00, 0x04, // Length of cipher suites
      0xC0, 0x2B, // Cipher suite 1
      0xC0, 0x0A, // Cipher suite 2
      0x01, 0x00, // Compression methods
      0x00, 0x08, // Length of extensions
      0x00, 0x0A, // Extension type
      0x00, 0x04, // Length of extension data
      0x00, 0x02, // Length of elliptic curves
      0x00, 0x1D, // Named curve
    ];
    return Uint8List.fromList(result);
  }
}

void testHandshakeMessageClientHello() {
  List<int> rawClientHello = [
    0xfe,
    0xfd,
    0xb6,
    0x2f,
    0xce,
    0x5c,
    0x42,
    0x54,
    0xff,
    0x86,
    0xe1,
    0x24,
    0x41,
    0x91,
    0x42,
    0x62,
    0x15,
    0xad,
    0x16,
    0xc9,
    0x15,
    0x8d,
    0x95,
    0x71,
    0x8a,
    0xbb,
    0x22,
    0xd7,
    0x47,
    0xec,
    0xd8,
    0x3d,
    0xdc,
    0x4b,
    0x00,
    0x14,
    0xe6,
    0x14,
    0x3a,
    0x1b,
    0x04,
    0xea,
    0x9e,
    0x7a,
    0x14,
    0xd6,
    0x6c,
    0x57,
    0xd0,
    0x0e,
    0x32,
    0x85,
    0x76,
    0x18,
    0xde,
    0xd8,
    0x00,
    0x04,
    0xc0,
    0x2b,
    0xc0,
    0x0a,
    0x01,
    0x00,
    0x00,
    0x08,
    0x00,
    0x0a,
    0x00,
    0x04,
    0x00,
    0x02,
    0x00,
    0x1d,
  ];

  DateTime gmtUnixTime =
      DateTime.fromMillisecondsSinceEpoch(3056586332000, isUtc: true);
  HandshakeMessageClientHello parsedClientHello = HandshakeMessageClientHello(
    version: ProtocolVersion(major: 0xFE, minor: 0xFD),
    random: HandshakeRandom(
      gmtUnixTime: gmtUnixTime,
      randomBytes: [
        0x42,
        0x54,
        0xff,
        0x86,
        0xe1,
        0x24,
        0x41,
        0x91,
        0x42,
        0x62,
        0x15,
        0xad,
        0x16,
        0xc9,
        0x15,
        0x8d,
        0x95,
        0x71,
        0x8a,
        0xbb,
        0x22,
        0xd7,
        0x47,
        0xec,
        0xd8,
        0x3d,
        0xdc,
        0x4b,
      ],
    ),
    cookie: [
      0xe6,
      0x14,
      0x3a,
      0x1b,
      0x04,
      0xea,
      0x9e,
      0x7a,
      0x14,
      0xd6,
      0x6c,
      0x57,
      0xd0,
      0x0e,
      0x32,
      0x85,
      0x76,
      0x18,
      0xde,
      0xd8,
    ],
    cipherSuites: [
      CipherSuiteId.tlsEcdheEcdsaWithAes128GcmSha256,
      CipherSuiteId.tlsEcdheEcdsaWithAes256CbcSha,
    ],
    compressionMethods:
        CompressionMethods(ids: [CompressionMethodId.nullCompression]),
    extensions: [
      Extension(
        supportedEllipticCurves: ExtensionSupportedEllipticCurves(
          ellipticCurves: [NamedCurve.x25519],
        ),
      ),
    ],
  );

  Uint8List raw = Uint8List.fromList(rawClientHello);
  HandshakeMessageClientHello c = HandshakeMessageClientHello.unmarshal(raw);
  assert(c.version.major == parsedClientHello.version.major);
  assert(c.version.minor == parsedClientHello.version.minor);
  assert(c.random.gmtUnixTime == parsedClientHello.random.gmtUnixTime);
  assert(c.random.randomBytes.toString() ==
      parsedClientHello.random.randomBytes.toString());
  assert(c.cookie.toString() == parsedClientHello.cookie.toString());
  assert(
      c.cipherSuites.toString() == parsedClientHello.cipherSuites.toString());
  assert(c.compressionMethods.ids.toString() ==
      parsedClientHello.compressionMethods.ids.toString());
  assert(c.extensions.length == parsedClientHello.extensions.length);

  Uint8List marshalled = c.marshal();
  assert(marshalled.toString() == rawClientHello.toString());
}

void main() {
  testHandshakeMessageClientHello();
}
