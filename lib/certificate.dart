import 'dart:typed_data';

import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';
import 'package:dart_dtls_final/utils.dart';

class Certificate {
  late List<Uint8List> certificates;

  Certificate();

  @override
  String toString() {
    return '[Certificate] Certificates: ${certificates[0].length} bytes';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.Certificate;
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    certificates = [];
    final length = Uint24.fromBytes(buf.sublist(offset, offset + 3));
    final lengthInt = length.toUint32();
    offset += 3;
    final offsetBackup = offset;
    while (offset < offsetBackup + lengthInt) {
      final certificateLength =
          Uint24.fromBytes(buf.sublist(offset, offset + 3));
      final certificateLengthInt = certificateLength.toUint32();
      offset += 3;

      final certificateBytes = Uint8List.fromList(
          buf.sublist(offset, offset + certificateLengthInt));
      offset += certificateLengthInt;
      certificates.add(certificateBytes);
    }
    return offset;
  }

  Uint8List encode() {
    final encodedCertificates = <int>[];
    for (final certificate in certificates) {
      final certificateLength = Uint24.fromUInt32(certificate.length);
      encodedCertificates.addAll(certificateLength.toBytes());
      encodedCertificates.addAll(certificate);
    }
    final length = Uint24.fromUInt32(encodedCertificates.length);
    return Uint8List.fromList([...length.toBytes(), ...encodedCertificates]);
  }
}
