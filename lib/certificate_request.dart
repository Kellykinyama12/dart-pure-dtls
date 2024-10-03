import 'dart:typed_data';

import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

class CertificateRequest {
  late List<CertificateType> certificateTypes;
  late List<AlgoPair> algoPairs;

  CertificateRequest();

  @override
  String toString() {
    return '[CertificateRequest] CertificateTypes: ${certificateTypes.map((e) => e.name).join(', ')}, AlgoPair: ${algoPairs.map((e) => e.toString()).join(', ')}';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.CertificateRequest;
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    final certificateTypeCount = buf[offset];
    offset++;
    certificateTypes = List<CertificateType>.generate(
        certificateTypeCount, (i) => CertificateType.values[buf[offset + i]]);
    offset += certificateTypeCount;
    final algoPairLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    final algoPairCount = algoPairLength ~/ 2;
    algoPairs = List<AlgoPair>.generate(algoPairCount, (i) {
      final algoPair = AlgoPair();
      offset = algoPair.decode(buf, offset, arrayLen);
      return algoPair;
    });
    offset += 2; // Distinguished Names Length

    return offset;
  }

  Uint8List encode() {
    final encodedCertificateTypes =
        certificateTypes.map((e) => e.index).toList();
    final encodedAlgoPairs = algoPairs.expand((e) => e.encode()).toList();
    final algoPairLength = Uint8List(2)
      ..buffer.asByteData().setUint16(0, encodedAlgoPairs.length, Endian.big);

    return Uint8List.fromList([
      encodedCertificateTypes.length,
      ...encodedCertificateTypes,
      ...algoPairLength,
      ...encodedAlgoPairs,
      0x00, 0x00, // Distinguished Names Length
    ]);
  }
}

enum CertificateType {
  ECDSASign,
  // Add other certificate types as needed
}

extension CertificateTypeExtension on CertificateType {
  String get name {
    switch (this) {
      case CertificateType.ECDSASign:
        return 'ECDSASign';
      default:
        return 'Unknown Certificate Type';
    }
  }
}

class AlgoPair {
  HashAlgorithm hashAlgorithm;
  SignatureAlgorithm signatureAlgorithm;

  AlgoPair(
      [this.hashAlgorithm = HashAlgorithm.SHA256,
      this.signatureAlgorithm = SignatureAlgorithm.ECDSA]);

  @override
  String toString() {
    return '{HashAlg: ${hashAlgorithm.name} Signature Alg: ${signatureAlgorithm.name}}';
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    hashAlgorithm = HashAlgorithm.values[buf[offset]];
    offset += 1;
    signatureAlgorithm = SignatureAlgorithm.values[buf[offset]];
    offset += 1;
    return offset;
  }

  Uint8List encode() {
    return Uint8List.fromList([
      hashAlgorithm.index,
      signatureAlgorithm.index,
    ]);
  }
}

enum HashAlgorithm {
  SHA256,
  // Add other hash algorithms as needed
}

extension HashAlgorithmExtension on HashAlgorithm {
  String get name {
    switch (this) {
      case HashAlgorithm.SHA256:
        return 'SHA256';
      default:
        return 'Unknown Hash Algorithm';
    }
  }
}

enum SignatureAlgorithm {
  ECDSA,
  // Add other signature algorithms as needed
}

extension SignatureAlgorithmExtension on SignatureAlgorithm {
  String get name {
    switch (this) {
      case SignatureAlgorithm.ECDSA:
        return 'ECDSA';
      default:
        return 'Unknown Signature Algorithm';
    }
  }
}
