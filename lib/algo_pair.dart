import 'dart:typed_data';

class AlgoPair {
  late int hashAlgorithm;
  late int signatureAlgorithm;

  AlgoPair();

  @override
  String toString() {
    return '{HashAlg: ${hashAlgorithm} Signature Alg: ${signatureAlgorithm}}';
  }

  (int, bool?) decode(Uint8List buf, int offset, int arrayLen) {
    hashAlgorithm = buf[offset];
    offset += 1;
    signatureAlgorithm = buf[offset];
    offset += 1;
    return (offset, null);
  }

  Uint8List encode() {
    return Uint8List.fromList([
      hashAlgorithm,
      signatureAlgorithm,
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
