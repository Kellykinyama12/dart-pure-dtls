import 'dart:typed_data';

import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

class HelloVerifyRequest {
  late Uint8List version;
  late Uint8List cookie;

  HelloVerifyRequest();

  @override
  String toString() {
    final cookieStr = cookie.isEmpty
        ? '<nil>'
        : '0x${cookie.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';
    return '[HelloVerifyRequest] Ver: ${version.toString()}, Cookie: $cookieStr';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.HelloVerifyRequest;
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    // version = DtlsVersion.values[
    //     ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big)];
    version = buf.sublist(offset, offset + 2);
    offset += 2;

    final cookieLength = buf[offset];
    offset++;
    cookie = Uint8List.fromList(buf.sublist(offset, offset + cookieLength));
    offset += cookieLength;

    return offset;
  }

  Uint8List encode() {
    final buffer = BytesBuilder();

    // Encode version
    buffer.add(version);

    // Encode cookie length
    buffer.addByte(cookie.length);

    // Encode cookie
    buffer.add(cookie);

    return buffer.toBytes();
  }
}
