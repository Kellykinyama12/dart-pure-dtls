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

  static HandshakeRandom unmarshal(Uint8List data, int offset) {
    DateTime gmtUnixTime = DateTime.fromMillisecondsSinceEpoch(
      (data[offset] << 24) |
          (data[offset + 1] << 16) |
          (data[offset + 2] << 8) |
          data[offset + 3],
      isUtc: true,
    );
    List<int> randomBytes = data.sublist(offset + 4, offset + 32);
    return HandshakeRandom(gmtUnixTime: gmtUnixTime, randomBytes: randomBytes);
  }

  Uint8List marshal() {
    int gmtUnixTimeInt = gmtUnixTime.millisecondsSinceEpoch ~/ 1000;
    List<int> result = [
      (gmtUnixTimeInt >> 24) & 0xFF,
      (gmtUnixTimeInt >> 16) & 0xFF,
      (gmtUnixTimeInt >> 8) & 0xFF,
      gmtUnixTimeInt & 0xFF,
      ...randomBytes,
    ];
    return Uint8List.fromList(result);
  }
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

  static CompressionMethods unmarshal(Uint8List data, int offset) {
    int length = data[offset];
    List<int> ids = data.sublist(offset + 1, offset + 1 + length);
    return CompressionMethods(ids: ids);
  }

  Uint8List marshal() {
    List<int> result = [ids.length, ...ids];
    return Uint8List.fromList(result);
  }
}

class NamedCurve {
  static const int x25519 = 0x001D;
}

class ExtensionSupportedEllipticCurves {
  final List<int> ellipticCurves;

  ExtensionSupportedEllipticCurves({required this.ellipticCurves});

  static ExtensionSupportedEllipticCurves unmarshal(
      Uint8List data, int offset) {
    int length = (data[offset] << 8) | data[offset + 1];
    List<int> ellipticCurves = data.sublist(offset + 2, offset + 2 + length);
    return ExtensionSupportedEllipticCurves(ellipticCurves: ellipticCurves);
  }

  Uint8List marshal() {
    List<int> result = [
      (ellipticCurves.length >> 8) & 0xFF,
      ellipticCurves.length & 0xFF,
      ...ellipticCurves,
    ];
    return Uint8List.fromList(result);
  }
}

class Extension {
  final ExtensionSupportedEllipticCurves supportedEllipticCurves;

  Extension({required this.supportedEllipticCurves});

  static Extension unmarshal(Uint8List data, int offset) {
    return Extension(
      supportedEllipticCurves:
          ExtensionSupportedEllipticCurves.unmarshal(data, offset),
    );
  }

  Uint8List marshal() {
    return supportedEllipticCurves.marshal();
  }
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
    int offset = 0;
    ProtocolVersion version =
        ProtocolVersion(major: data[offset], minor: data[offset + 1]);
    offset += 2;
    HandshakeRandom random = HandshakeRandom.unmarshal(data, offset);
    offset += 32;
    int sessionIdLength = data[offset];
    offset += 1 + sessionIdLength;
    int cookieLength = data[offset];
    List<int> cookie = data.sublist(offset + 1, offset + 1 + cookieLength);
    offset += 1 + cookieLength;
    int cipherSuitesLength = (data[offset] << 8) | data[offset + 1];
    List<int> cipherSuites = [];
    for (int i = 0; i < cipherSuitesLength; i += 2) {
      cipherSuites.add((data[offset + 2 + i] << 8) | data[offset + 3 + i]);
    }
    offset += 2 + cipherSuitesLength;
    CompressionMethods compressionMethods =
        CompressionMethods.unmarshal(data, offset);
    offset += 1 + compressionMethods.ids.length;
    int extensionsLength = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    List<Extension> extensions = [];
    while (offset < data.length) {
      extensions.add(Extension.unmarshal(data, offset));
      offset +=
          4 + extensions.last.supportedEllipticCurves.ellipticCurves.length;
    }
    return HandshakeMessageClientHello(
      version: version,
      random: random,
      cookie: cookie,
      cipherSuites: cipherSuites,
      compressionMethods: compressionMethods,
      extensions: extensions,
    );
  }

  Uint8List marshal() {
    List<int> result = [
      version.major,
      version.minor,
      ...random.marshal(),
      0x00, // Session ID length
      cookie.length,
      ...cookie,
      (cipherSuites.length * 2) >> 8,
      (cipherSuites.length * 2) & 0xFF,
      for (var suite in cipherSuites) ...[(suite >> 8) & 0xFF, suite & 0xFF],
      ...compressionMethods.marshal(),
      (extensions.fold(
                  0,
                  (sum, ext) =>
                      sum +
                      ext.supportedEllipticCurves.ellipticCurves.length +
                      4) >>
              8) &
          0xFF,
      extensions.fold(
              0,
              (sum, ext) =>
                  sum + ext.supportedEllipticCurves.ellipticCurves.length + 4) &
          0xFF,
      for (var ext in extensions) ...ext.marshal(),
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
          randomBytes: [0x42, 0x54, 0xff, 0x86, 0xe1, 0x24, 0x41, 0x91, 0]));
}
