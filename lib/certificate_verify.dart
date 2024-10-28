import 'dart:typed_data';

import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

class CertificateVerify {
  late AlgoPair algoPair;
  late Uint8List signature;

  CertificateVerify();

  @override
  String toString() {
    return '[CertificateVerify] AlgoPair: ${algoPair.toString()}, Signature: 0x${signature.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.CertificateVerify;
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    algoPair = AlgoPair();
    offset = algoPair.decode(buf, offset, arrayLen);
    final signatureLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    signature =
        Uint8List.fromList(buf.sublist(offset, offset + signatureLength));
    offset += signatureLength;
    return offset;
  }

  Uint8List encode() {
    final buffer = BytesBuilder();

    // Encode algorithm pair
    buffer.add(algoPair.encode());

    // Encode signature
    final signatureLengthBytes = ByteData(2);
    signatureLengthBytes.setUint16(0, signature.length, Endian.big);
    buffer.add(signatureLengthBytes.buffer.asUint8List());
    buffer.add(signature);

    return buffer.toBytes();
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
    return '{HashAlg: ${hashAlgorithm.name}, Signature Alg: ${signatureAlgorithm.name}}';
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
