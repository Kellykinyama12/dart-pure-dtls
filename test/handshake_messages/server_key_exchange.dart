import 'dart:typed_data';
import 'package:buffer/buffer.dart';

class EllipticCurveType {
  final int value;

  EllipticCurveType(this.value);
}

class NamedCurve {
  final int value;

  NamedCurve(this.value);
}

class SignatureHashAlgorithm {
  final int hash;
  final int signature;

  SignatureHashAlgorithm(this.hash, this.signature);
}

class HandshakeMessageServerKeyExchange {
  final Uint8List identityHint;
  final EllipticCurveType ellipticCurveType;
  final NamedCurve namedCurve;
  final Uint8List publicKey;
  final SignatureHashAlgorithm algorithm;
  final Uint8List signature;

  HandshakeMessageServerKeyExchange({
    required this.identityHint,
    required this.ellipticCurveType,
    required this.namedCurve,
    required this.publicKey,
    required this.algorithm,
    required this.signature,
  });

  HandshakeType get handshakeType => HandshakeType.serverKeyExchange;

  int get size {
    if (identityHint.isNotEmpty) {
      return 2 + identityHint.length;
    } else {
      return 1 + 2 + 1 + publicKey.length + 2 + 2 + signature.length;
    }
  }

  void marshal(ByteDataWriter writer) {
    if (identityHint.isNotEmpty) {
      writer.writeUint16(identityHint.length);
      writer.write(identityHint);
      return;
    }

    writer.writeUint8(ellipticCurveType.value);
    writer.writeUint16(namedCurve.value);
    writer.writeUint8(publicKey.length);
    writer.write(publicKey);
    writer.writeUint8(algorithm.hash);
    writer.writeUint8(algorithm.signature);
    writer.writeUint16(signature.length);
    writer.write(signature);
  }

  static HandshakeMessageServerKeyExchange unmarshal(ByteDataReader reader) {
    final data = reader.toBytes();

    // If parsed as PSK return early and only populate PSK Identity Hint
    final pskLength = (data << 8) | data;
    if (data.length == pskLength + 2) {
      return HandshakeMessageServerKeyExchange(
        identityHint: Uint8List.fromList(data.sublist(2)),
        ellipticCurveType: EllipticCurveType(0),
        namedCurve: NamedCurve(0),
        publicKey: Uint8List(0),
        algorithm: SignatureHashAlgorithm(0, 0),
        signature: Uint8List(0),
      );
    }

    final ellipticCurveType = EllipticCurveType(data);
    final namedCurve = NamedCurve((data << 8) | data);
    final publicKeyLength = data;
    final publicKey = Uint8List.fromList(data.sublist(4, 4 + publicKeyLength));
    final offset = 4 + publicKeyLength;
    final hashAlgorithm = data[offset];
    final signatureAlgorithm = data[offset + 1];
    final signatureLength = (data[offset + 2] << 8) | data[offset + 3];
    final signature = Uint8List.fromList(
        data.sublist(offset + 4, offset + 4 + signatureLength));

    return HandshakeMessageServerKeyExchange(
      identityHint: Uint8List(0),
      ellipticCurveType: ellipticCurveType,
      namedCurve: namedCurve,
      publicKey: publicKey,
      algorithm: SignatureHashAlgorithm(hashAlgorithm, signatureAlgorithm),
      signature: signature,
    );
  }
}

enum HandshakeType {
  serverKeyExchange,
}
