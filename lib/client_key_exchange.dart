import 'dart:typed_data';

import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

class ClientKeyExchange {
  late Uint8List publicKey;

  ClientKeyExchange();

  @override
  String toString() {
    return '[ClientKeyExchange] PublicKey: 0x${publicKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ClientKeyExchange;
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    final publicKeyLength = buf[offset];
    offset++;
    publicKey =
        Uint8List.fromList(buf.sublist(offset, offset + publicKeyLength));
    offset += publicKeyLength;
    return offset;
  }

  Uint8List encode() {
    final result = Uint8List(1 + publicKey.length);
    result[0] = publicKey.length;
    result.setRange(1, result.length, publicKey);
    return result;
  }
}
