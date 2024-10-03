import 'dart:typed_data';

class AlgoPair {
  HashAlgorithm hashAlgorithm;
  SignatureAlgorithm signatureAlgorithm;

  AlgoPair(this.hashAlgorithm, this.signatureAlgorithm);

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
