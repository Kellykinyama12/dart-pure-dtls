// import 'dart:typed_data';

// import 'package:dart_dtls_final/cipher_suites.dart';
// import 'package:dart_dtls_final/handshake_header.dart';
// import 'package:dart_dtls_final/record_header.dart';

// class ServerKeyExchange {
//   late CurveType ellipticCurveType;
//   late Curve namedCurve;
//   late Uint8List publicKey;
//   late AlgoPair algoPair;
//   late Uint8List signature;

//   ServerKeyExchange();

//   @override
//   String toString() {
//     return '[ServerKeyExchange] EllipticCurveType: ${ellipticCurveType.toString()}, NamedCurve: ${namedCurve.toString()}, AlgoPair: ${algoPair.toString()}, PublicKey: 0x${publicKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';
//   }

//   ContentType getContentType() {
//     return ContentType.Handshake;
//   }

//   HandshakeType getHandshakeType() {
//     return HandshakeType.ServerKeyExchange;
//   }

//   int decode(Uint8List buf, int offset, int arrayLen) {
//     ellipticCurveType = CurveType.values[buf[offset]];
//     offset++;
//     namedCurve = Curve.values[
//         ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big)];
//     offset += 2;
//     final publicKeyLength = buf[offset];
//     offset++;
//     publicKey =
//         Uint8List.fromList(buf.sublist(offset, offset + publicKeyLength));
//     offset += publicKeyLength;
//     algoPair = AlgoPair();
//     offset = algoPair.decode(buf, offset, arrayLen);
//     final signatureLength =
//         ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
//     offset += 2;
//     signature =
//         Uint8List.fromList(buf.sublist(offset, offset + signatureLength));
//     offset += signatureLength;
//     return offset;
//   }

//   Uint8List encode() {
//     final result = BytesBuilder();
//     result.add(Uint8List.fromList([ellipticCurveType.index]));
//     final byteData = ByteData(2);
//     byteData.setUint16(0, namedCurve.index, Endian.big);
//     result.add(byteData.buffer.asUint8List());
//     result.add(Uint8List.fromList([publicKey.length]));
//     result.add(publicKey);
//     result.add(algoPair.encode());
//     byteData.setUint16(0, signature.length, Endian.big);
//     result.add(byteData.buffer.asUint8List());
//     result.add(signature);
//     return result.toBytes();
//   }
// }

// class AlgoPair {
//   HashAlgorithm hashAlgorithm;
//   SignatureAlgorithm signatureAlgorithm;

//   AlgoPair(
//       [this.hashAlgorithm = HashAlgorithm.SHA256,
//       this.signatureAlgorithm = SignatureAlgorithm.ECDSA]);

//   @override
//   String toString() {
//     return '{HashAlg: ${hashAlgorithm.name} Signature Alg: ${signatureAlgorithm.name}}';
//   }

//   int decode(Uint8List buf, int offset, int arrayLen) {
//     hashAlgorithm = HashAlgorithm.values[buf[offset]];
//     offset += 1;
//     signatureAlgorithm = SignatureAlgorithm.values[buf[offset]];
//     offset += 1;
//     return offset;
//   }

//   Uint8List encode() {
//     return Uint8List.fromList([
//       hashAlgorithm.index,
//       signatureAlgorithm.index,
//     ]);
//   }
// }

// enum HashAlgorithm {
//   SHA256,
//   // Add other hash algorithms as needed
// }

// extension HashAlgorithmExtension on HashAlgorithm {
//   String get name {
//     switch (this) {
//       case HashAlgorithm.SHA256:
//         return 'SHA256';
//       default:
//         return 'Unknown Hash Algorithm';
//     }
//   }
// }

// enum SignatureAlgorithm {
//   ECDSA,
//   // Add other signature algorithms as needed
// }

// extension SignatureAlgorithmExtension on SignatureAlgorithm {
//   String get name {
//     switch (this) {
//       case SignatureAlgorithm.ECDSA:
//         return 'ECDSA';
//       default:
//         return 'Unknown Signature Algorithm';
//     }
//   }
// }

import 'dart:typed_data';

import 'package:dart_dtls_final/algo_pair.dart';
import 'package:dart_dtls_final/utils.dart';

class ServerKeyExchange {
  int? ellipticCurveType;
  int? namedCurve;
  Uint8List? publicKey;
  AlgoPair? algoPair;
  Uint8List? signature;

  dynamic decode(Uint8List buf, int offset, int arrayLen)
  //(int, error)
  {
    ellipticCurveType = (buf[offset]);
    offset++;
    namedCurve = uint16(buf.sublist(offset, offset + 2));
    offset += 2;
    var publicKeyLength = buf[offset];
    offset++;

    print("Public key length: $publicKeyLength");
    //m.PublicKey = make([]byte, publicKeyLength)
    publicKey = buf.sublist(offset, offset + publicKeyLength);
    offset = offset + publicKeyLength;
    algoPair = AlgoPair();
    var err;
    (offset, err) = algoPair!.decode(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    var signatureLength = uint16(buf.sublist(offset, offset + 2));
    offset += 2;
    print("Signature length: $signatureLength");
    //m.ignature = make([]byte, signatureLength)
    signature = buf.sublist(offset, offset + signatureLength);
    offset += signatureLength;
    return (offset, null);
  }

  Uint8List encode() {
    final buffer = BytesBuilder();

    // Encode elliptic curve type
    buffer.addByte(ellipticCurveType ?? 0);

    // Encode named curve
    final namedCurveBytes = ByteData(2);
    namedCurveBytes.setUint16(0, namedCurve ?? 0, Endian.big);
    buffer.add(namedCurveBytes.buffer.asUint8List());

    // Encode public key length and public key
    buffer.addByte(publicKey?.length ?? 0);
    if (publicKey != null) {
      buffer.add(publicKey!);
    }

    // Encode algorithm pair
    buffer.add(algoPair?.encode() ?? Uint8List(0));

    // Encode signature length and signature
    final signatureLengthBytes = ByteData(2);
    signatureLengthBytes.setUint16(0, signature?.length ?? 0, Endian.big);
    buffer.add(signatureLengthBytes.buffer.asUint8List());
    if (signature != null) {
      buffer.add(signature!);
    }

    return buffer.toBytes();
  }

  @override
  String toString() {
    // TODO: implement toString
    return "{ curver type: $ellipticCurveType, name curve: $namedCurve, public key: ${publicKey?.length}, algo pair:$algoPair, signature lenth: ${signature?.length}}";
  }
}
