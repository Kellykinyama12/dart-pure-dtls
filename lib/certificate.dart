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
    final buffer = BytesBuilder();

    // Calculate the total length of all certificates
    int totalLength =
        certificates.fold(0, (sum, cert) => sum + 3 + cert.length);

    // Encode the total length as a 3-byte integer
    final totalLengthBytes = Uint24(totalLength).toBytes();
    buffer.add(totalLengthBytes);

    // Encode each certificate
    for (var cert in certificates) {
      // Encode the length of the certificate as a 3-byte integer
      final certLengthBytes = Uint24(cert.length).toBytes();
      buffer.add(certLengthBytes);

      // Encode the certificate itself
      buffer.add(cert);
    }

    return buffer.toBytes();
  }
}
