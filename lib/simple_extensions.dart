import 'dart:typed_data';

enum ExtensionType {
  ServerName,
  SupportedEllipticCurves,
  SupportedPointFormats,
  SupportedSignatureAlgorithms,
  UseSRTP,
  ALPN,
  UseExtendedMasterSecret,
  RenegotiationInfo,
  Unknown,
}

abstract class Extension {
  ExtensionType getExtensionType();
  Uint8List encode();
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen);
  @override
  String toString();
}

class ExtUseExtendedMasterSecret implements Extension {
  @override
  String toString() => '[UseExtendedMasterSecret]';

  @override
  ExtensionType getExtensionType() => ExtensionType.UseExtendedMasterSecret;

  @override
  Uint8List encode() {
    return Uint8List(0);
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    // No decoding needed for this extension
  }
}

class ExtRenegotiationInfo implements Extension {
  @override
  String toString() => '[RenegotiationInfo]';

  @override
  ExtensionType getExtensionType() => ExtensionType.RenegotiationInfo;

  @override
  Uint8List encode() {
    return Uint8List.fromList([0]);
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    // No decoding needed for this extension
  }
}

class ExtUseSRTP implements Extension {
  List<SRTPProtectionProfile> protectionProfiles;
  Uint8List mki;

  ExtUseSRTP(this.protectionProfiles, this.mki);

  @override
  String toString() {
    final protectionProfilesStr =
        protectionProfiles.map((p) => p.toString()).join('\n+ ');
    return '[UseSRTP]\n+ Protection Profiles:\n+ $protectionProfilesStr';
  }

  @override
  ExtensionType getExtensionType() => ExtensionType.UseSRTP;

  @override
  Uint8List encode() {
    final result =
        Uint8List(2 + (protectionProfiles.length * 2) + 1 + mki.length);
    var offset = 0;
    final byteData = ByteData.sublistView(result);
    byteData.setUint16(offset, protectionProfiles.length * 2, Endian.big);
    offset += 2;
    for (final profile in protectionProfiles) {
      byteData.setUint16(offset, profile.index, Endian.big);
      offset += 2;
    }
    result[offset] = mki.length;
    offset++;
    result.setRange(offset, offset + mki.length, mki);
    return result;
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    final protectionProfilesLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    final protectionProfilesCount = protectionProfilesLength ~/ 2;
    protectionProfiles =
        List<SRTPProtectionProfile>.generate(protectionProfilesCount, (i) {
      final profile = SRTPProtectionProfile.values[
          ByteData.sublistView(buf, offset, offset + 2)
              .getUint16(0, Endian.big)];
      offset += 2;
      return profile;
    });
    final mkiLength = buf[offset];
    offset++;
    mki = Uint8List.fromList(buf.sublist(offset, offset + mkiLength));
  }
}

class ExtSupportedPointFormats implements Extension {
  List<PointFormat> pointFormats;

  ExtSupportedPointFormats(this.pointFormats);

  @override
  String toString() {
    return '[SupportedPointFormats] Point Formats: ${pointFormats.join(', ')}';
  }

  @override
  ExtensionType getExtensionType() => ExtensionType.SupportedPointFormats;

  @override
  Uint8List encode() {
    final result = Uint8List(1 + pointFormats.length);
    result[0] = pointFormats.length;
    for (var i = 0; i < pointFormats.length; i++) {
      result[i + 1] = pointFormats[i].index;
    }
    return result;
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    final pointFormatsCount = buf[offset];
    offset++;
    pointFormats = List<PointFormat>.generate(
        pointFormatsCount, (i) => PointFormat.values[buf[offset + i]]);
  }
}

class ExtSupportedEllipticCurves implements Extension {
  List<Curve> curves;

  ExtSupportedEllipticCurves(this.curves);

  @override
  String toString() {
    final curvesStr = curves.map((c) => c.toString()).join('\n+ ');
    return '[SupportedEllipticCurves]\n+ Curves:\n+ $curvesStr';
  }

  @override
  ExtensionType getExtensionType() => ExtensionType.SupportedEllipticCurves;

  @override
  Uint8List encode() {
    final result = Uint8List(2 + (curves.length * 2));
    var offset = 0;
    final byteData = ByteData.sublistView(result);
    byteData.setUint16(offset, curves.length * 2, Endian.big);
    offset += 2;
    for (final curve in curves) {
      byteData.setUint16(offset, curve.index, Endian.big);
      offset += 2;
    }
    return result;
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    final curvesLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    final curvesCount = curvesLength ~/ 2;
    curves = List<Curve>.generate(
        curvesCount,
        (i) => Curve.values[ByteData.sublistView(buf, offset, offset + 2)
            .getUint16(0, Endian.big)]);
  }
}

class ExtUnknown implements Extension {
  ExtensionType type;
  int dataLength;

  ExtUnknown(this.type, this.dataLength);

  @override
  String toString() {
    return '[Unknown Extension Type] Ext Type: ${type.index}, Data: $dataLength bytes';
  }

  @override
  ExtensionType getExtensionType() => ExtensionType.Unknown;

  @override
  Uint8List encode() {
    throw UnsupportedError('ExtUnknown cannot be encoded, it\'s readonly');
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    // No decoding needed for this extension
  }
}

enum SRTPProtectionProfile {
  SRTP_AES128_CM_HMAC_SHA1_80,
  SRTP_AES128_CM_HMAC_SHA1_32,
  // Add other profiles as needed
}

extension SRTPProtectionProfileExtension on SRTPProtectionProfile {
  String get name {
    switch (this) {
      case SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80:
        return 'SRTP_AES128_CM_HMAC_SHA1_80';
      case SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32:
        return 'SRTP_AES128_CM_HMAC_SHA1_32';
      default:
        return 'Unknown SRTP Protection Profile';
    }
  }

  String SRTPProtectionProfileToString() => name;
}

enum PointFormat {
  Uncompressed,
  // Add other point formats as needed
}

enum Curve {
  X25519,
  // Add other curves as needed
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

  String curveToString() => name;
}
