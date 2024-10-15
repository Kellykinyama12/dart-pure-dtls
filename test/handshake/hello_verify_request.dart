import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

class ProtocolVersion {
  final int major;
  final int minor;

  ProtocolVersion({required this.major, required this.minor});
}

class HandshakeMessageHelloVerifyRequest {
  final ProtocolVersion version;
  final List<int> cookie;

  HandshakeMessageHelloVerifyRequest({
    required this.version,
    required this.cookie,
  });

  static HandshakeMessageHelloVerifyRequest unmarshal(Uint8List data) {
    // Implement the unmarshalling logic here
    // This is a placeholder implementation
    return HandshakeMessageHelloVerifyRequest(
      version: ProtocolVersion(major: data, minor: data),
      cookie: data.sublist(2),
    );
  }

  Uint8List marshal() {
    // Implement the marshalling logic here
    // This is a placeholder implementation
    return Uint8List.fromList([version.major, version.minor, ...cookie]);
  }
}

void testHandshakeMessageHelloVerifyRequest() {
  List<int> rawHelloVerifyRequest = [
    0xfe,
    0xff,
    0x14,
    0x25,
    0xfb,
    0xee,
    0xb3,
    0x7c,
    0x95,
    0xcf,
    0x00,
    0xeb,
    0xad,
    0xe2,
    0xef,
    0xc7,
    0xfd,
    0xbb,
    0xed,
    0xf7,
    0x1f,
    0x6c,
    0xcd,
  ];

  HandshakeMessageHelloVerifyRequest parsedHelloVerifyRequest =
      HandshakeMessageHelloVerifyRequest(
    version: ProtocolVersion(major: 0xFE, minor: 0xFF),
    cookie: [
      0x25,
      0xfb,
      0xee,
      0xb3,
      0x7c,
      0x95,
      0xcf,
      0x00,
      0xeb,
      0xad,
      0xe2,
      0xef,
      0xc7,
      0xfd,
      0xbb,
      0xed,
      0xf7,
      0x1f,
      0x6c,
      0xcd,
    ],
  );

  Uint8List raw = Uint8List.fromList(rawHelloVerifyRequest);
  HandshakeMessageHelloVerifyRequest c =
      HandshakeMessageHelloVerifyRequest.unmarshal(raw);
  assert(c.version.major == parsedHelloVerifyRequest.version.major);
  assert(c.version.minor == parsedHelloVerifyRequest.version.minor);
  assert(c.cookie.toString() == parsedHelloVerifyRequest.cookie.toString());

  Uint8List marshalled = c.marshal();
  assert(marshalled.toString() == rawHelloVerifyRequest.toString());
}

void main() {
  testHandshakeMessageHelloVerifyRequest();
}
