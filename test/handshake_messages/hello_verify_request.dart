import 'dart:typed_data';
import 'package:buffer/buffer.dart';

class ProtocolVersion {
  final int major;
  final int minor;

  ProtocolVersion(this.major, this.minor);
}

class HandshakeMessageHelloVerifyRequest {
  final ProtocolVersion version;
  final Uint8List cookie;

  HandshakeMessageHelloVerifyRequest({
    required this.version,
    required this.cookie,
  });

  HandshakeType get handshakeType => HandshakeType.helloVerifyRequest;

  int get size => 1 + 1 + 1 + cookie.length;

  void marshal(ByteDataWriter writer) {
    if (cookie.length > 255) {
      throw Exception('Cookie too long');
    }

    writer.writeUint8(version.major);
    writer.writeUint8(version.minor);
    writer.writeUint8(cookie.length);
    writer.write(cookie);
  }

  static HandshakeMessageHelloVerifyRequest unmarshal(ByteDataReader reader) {
    final major = reader.readUint8();
    final minor = reader.readUint8();
    final cookieLength = reader.readUint8();
    final cookie = reader.read(cookieLength);

    if (cookie.length < cookieLength) {
      throw Exception('Buffer too small');
    }

    return HandshakeMessageHelloVerifyRequest(
      version: ProtocolVersion(major, minor),
      cookie: cookie,
    );
  }
}

enum HandshakeType {
  helloVerifyRequest,
}
