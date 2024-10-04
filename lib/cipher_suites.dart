import 'dart:typed_data';
import 'package:pointycastle/export.dart';

typedef intCipherSuiteID = int;

enum CipherSuiteID {
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
}

enum CurveType {
  NamedCurve,
}

enum Curve {
  X25519,
}

enum PointFormat {
  Uncompressed,
}

enum HashAlgorithm {
  SHA256,
}

enum SignatureAlgorithm {
  ECDSA,
}

enum CertificateType {
  ECDSASign,
}

enum KeyExchangeAlgorithm {
  None,
  ECDHE,
}

enum SRTPProtectionProfile {
  AEAD_AES_128_GCM,
}

class CipherSuite {
  final CipherSuiteID id;
  final KeyExchangeAlgorithm keyExchangeAlgorithm;
  final CertificateType certificateType;
  final HashAlgorithm hashAlgorithm;
  final SignatureAlgorithm signatureAlgorithm;

  CipherSuite({
    required this.id,
    required this.keyExchangeAlgorithm,
    required this.certificateType,
    required this.hashAlgorithm,
    required this.signatureAlgorithm,
  });

  @override
  String toString() {
    return 'ID: ${id.name}, KeyExchangeAlgorithm: ${keyExchangeAlgorithm.name}, CertificateType: ${certificateType.name}, HashAlgorithm: ${hashAlgorithm.name}, SignatureAlgorithm: ${signatureAlgorithm.name}';
  }
}

const supportedCurves = {
  Curve.X25519: true,
};

const supportedSRTPProtectionProfiles = {
  SRTPProtectionProfile.AEAD_AES_128_GCM: true,
};

final supportedCipherSuites = {
  CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: CipherSuite(
    id: CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    keyExchangeAlgorithm: KeyExchangeAlgorithm.ECDHE,
    certificateType: CertificateType.ECDSASign,
    hashAlgorithm: HashAlgorithm.SHA256,
    signatureAlgorithm: SignatureAlgorithm.ECDSA,
  ),
};

extension CipherSuiteIDExtension on CipherSuiteID {
  String get name {
    switch (this) {
      case CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        return 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256';
      default:
        return 'Unknown Cipher Suite';
    }
  }
}

extension CurveTypeExtension on CurveType {
  String get name {
    switch (this) {
      case CurveType.NamedCurve:
        return 'NamedCurve';
      default:
        return 'Unknown Curve Type';
    }
  }
}

extension CurveExtension on Curve {
  String get name {
    switch (this) {
      case Curve.X25519:
        return 'X25519';
      default:
        return 'Unknown Curve';
    }
  }
}

extension PointFormatExtension on PointFormat {
  String get name {
    switch (this) {
      case PointFormat.Uncompressed:
        return 'Uncompressed';
      default:
        return 'Unknown Point Format';
    }
  }
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

  Uint8List execute(Uint8List input) {
    switch (this) {
      case HashAlgorithm.SHA256:
        final digest = SHA256Digest().process(input);
        return digest;
      default:
        return Uint8List(0);
    }
  }

  Digest get cryptoHashType {
    switch (this) {
      case HashAlgorithm.SHA256:
        return SHA256Digest();
      default:
        throw UnsupportedError('Unsupported hash algorithm');
    }
  }

  Digest getFunction() {
    switch (this) {
      case HashAlgorithm.SHA256:
        return SHA256Digest();
      default:
        throw UnsupportedError('Unsupported hash algorithm');
    }
  }
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

extension KeyExchangeAlgorithmExtension on KeyExchangeAlgorithm {
  String get name {
    switch (this) {
      case KeyExchangeAlgorithm.None:
        return 'None';
      case KeyExchangeAlgorithm.ECDHE:
        return 'ECDHE';
      default:
        return 'Unknown Key Exchange Algorithm';
    }
  }
}

extension SRTPProtectionProfileExtension on SRTPProtectionProfile {
  String get name {
    switch (this) {
      case SRTPProtectionProfile.AEAD_AES_128_GCM:
        return 'SRTP_AEAD_AES_128_GCM';
      default:
        return 'Unknown SRTP Protection Profile';
    }
  }
}
