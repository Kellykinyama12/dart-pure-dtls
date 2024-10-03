import 'dart:typed_data';

import 'package:dart_dtls_final/cipher_suites.dart';
import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

class ServerKeyExchange {
  late CurveType ellipticCurveType;
  late Curve namedCurve;
  late Uint8List publicKey;
  late AlgoPair algoPair;
  late Uint8List signature;

  ServerKeyExchange();

  @override
  String toString() {
    return '[ServerKeyExchange] EllipticCurveType: ${ellipticCurveType.toString()}, NamedCurve: ${namedCurve.toString()}, AlgoPair: ${algoPair.toString()}, PublicKey: 0x${publicKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ServerKeyExchange;
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    ellipticCurveType = CurveType.values[buf[offset]];
    offset++;
    namedCurve = Curve.values[
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big)];
    offset += 2;
    final publicKeyLength = buf[offset];
    offset++;
    publicKey =
        Uint8List.fromList(buf.sublist(offset, offset + publicKeyLength));
    offset += publicKeyLength;
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
    final result = BytesBuilder();
    result.add(Uint8List.fromList([ellipticCurveType.index]));
    final byteData = ByteData(2);
    byteData.setUint16(0, namedCurve.index, Endian.big);
    result.add(byteData.buffer.asUint8List());
    result.add(Uint8List.fromList([publicKey.length]));
    result.add(publicKey);
    result.add(algoPair.encode());
    byteData.setUint16(0, signature.length, Endian.big);
    result.add(byteData.buffer.asUint8List());
    result.add(signature);
    return result.toBytes();
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
