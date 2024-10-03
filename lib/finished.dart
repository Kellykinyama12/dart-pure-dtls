import 'dart:typed_data';

import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

class Finished {
  late Uint8List verifyData;

  Finished();

  @override
  String toString() {
    return '[Finished] VerifyData: 0x${verifyData.map((b) => b.toRadixString(16).padLeft(2, '0')).join()} (${verifyData.length} bytes)';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.Finished;
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    verifyData = Uint8List.fromList(buf.sublist(offset, offset + arrayLen));
    offset += verifyData.length;
    return offset;
  }

  Uint8List encode() {
    return Uint8List.fromList(verifyData);
  }
}
