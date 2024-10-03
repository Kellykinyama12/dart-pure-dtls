import 'dart:typed_data';

import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

class HelloVerifyRequest {
  DtlsVersion version;
  Uint8List cookie;

  HelloVerifyRequest({required this.version, required this.cookie});

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
    version = DtlsVersion.values[
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big)];
    offset += 2;

    final cookieLength = buf[offset];
    offset++;
    cookie = Uint8List.fromList(buf.sublist(offset, offset + cookieLength));
    offset += cookieLength;

    return offset;
  }

  Uint8List encode() {
    final result = Uint8List(3 + cookie.length);
    final byteData = ByteData.sublistView(result);
    byteData.setUint16(0, version.value, Endian.big);
    result[2] = cookie.length;
    result.setRange(3, result.length, cookie);
    return result;
  }
}
