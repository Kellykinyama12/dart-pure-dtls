import 'dart:typed_data';

import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

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

class Uint24 {
  final int value;

  Uint24(this.value);

  factory Uint24.fromBytes(Uint8List bytes) {
    return Uint24((bytes[0] << 16) | (bytes[1] << 8) | bytes[2]);
  }

  factory Uint24.fromUInt32(int value) {
    return Uint24(value & 0xFFFFFF);
  }

  int toUint32() {
    return value;
  }

  Uint8List toBytes() {
    return Uint8List(3)
      ..[0] = (value >> 16) & 0xFF
      ..[1] = (value >> 8) & 0xFF
      ..[2] = value & 0xFF;
  }
}
