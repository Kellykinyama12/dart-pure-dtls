import 'dart:typed_data';

import 'package:dart_dtls_final/utils.dart';

enum ExtensionType {
  ServerName(0),
  SupportedEllipticCurves(10),
  SupportedPointFormats(11),
  SupportedSignatureAlgorithms(13),
  UseSRTP(14),
  ALPN(16),
  UseExtendedMasterSecret(23),
  RenegotiationInfo(65281),

  Unknown(65535); //Not a valid value

  final int value;

  const ExtensionType(this.value);

  factory ExtensionType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

// abstract class Extension {
//   ExtensionType getExtensionType();
//   Uint8List encode();
//   void decode(int extensionLength, Uint8List buf, int offset, int arrayLen);
//   @override
//   String toString();
// }

// class ExtUseExtendedMasterSecret implements Extension {
//   @override
//   String toString() => '[UseExtendedMasterSecret]';

//   @override
//   ExtensionType getExtensionType() => ExtensionType.UseExtendedMasterSecret;

//   @override
//   Uint8List encode() {
//     return Uint8List(0);
//   }

//   @override
//   void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
//     // No decoding needed for this extension
//   }
// }

// class ExtRenegotiationInfo implements Extension {
//   @override
//   String toString() => '[RenegotiationInfo]';

//   @override
//   ExtensionType getExtensionType() => ExtensionType.RenegotiationInfo;

//   @override
//   Uint8List encode() {
//     return Uint8List.fromList([0]);
//   }

//   @override
//   void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
//     // No decoding needed for this extension
//   }
// }

// class ExtUseSRTP implements Extension {
//   List<SRTPProtectionProfile> protectionProfiles;
//   Uint8List mki;

//   ExtUseSRTP(this.protectionProfiles, this.mki);

//   @override
//   String toString() {
//     final protectionProfilesStr =
//         protectionProfiles.map((p) => p.toString()).join('\n+ ');
//     return '[UseSRTP]\n+ Protection Profiles:\n+ $protectionProfilesStr';
//   }

//   @override
//   ExtensionType getExtensionType() => ExtensionType.UseSRTP;

//   @override
//   Uint8List encode() {
//     final result =
//         Uint8List(2 + (protectionProfiles.length * 2) + 1 + mki.length);
//     var offset = 0;
//     final byteData = ByteData.sublistView(result);
//     byteData.setUint16(offset, protectionProfiles.length * 2, Endian.big);
//     offset += 2;
//     for (final profile in protectionProfiles) {
//       byteData.setUint16(offset, profile.index, Endian.big);
//       offset += 2;
//     }
//     result[offset] = mki.length;
//     offset++;
//     result.setRange(offset, offset + mki.length, mki);
//     return result;
//   }

//   @override
//   void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
//     final protectionProfilesLength =
//         ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
//     offset += 2;
//     final protectionProfilesCount = protectionProfilesLength ~/ 2;
//     protectionProfiles =
//         List<SRTPProtectionProfile>.generate(protectionProfilesCount, (i) {
//       final profile = SRTPProtectionProfile.values[
//           ByteData.sublistView(buf, offset, offset + 2)
//               .getUint16(0, Endian.big)];
//       offset += 2;
//       return profile;
//     });
//     final mkiLength = buf[offset];
//     offset++;
//     mki = Uint8List.fromList(buf.sublist(offset, offset + mkiLength));
//   }
// }

// class ExtSupportedPointFormats implements Extension {
//   List<PointFormat> pointFormats;

//   ExtSupportedPointFormats(this.pointFormats);

//   @override
//   String toString() {
//     return '[SupportedPointFormats] Point Formats: ${pointFormats.join(', ')}';
//   }

//   @override
//   ExtensionType getExtensionType() => ExtensionType.SupportedPointFormats;

//   @override
//   Uint8List encode() {
//     final result = Uint8List(1 + pointFormats.length);
//     result[0] = pointFormats.length;
//     for (var i = 0; i < pointFormats.length; i++) {
//       result[i + 1] = pointFormats[i].index;
//     }
//     return result;
//   }

//   @override
//   void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
//     final pointFormatsCount = buf[offset];
//     offset++;
//     pointFormats = List<PointFormat>.generate(
//         pointFormatsCount, (i) => PointFormat.values[buf[offset + i]]);
//   }
// }

// class ExtSupportedEllipticCurves implements Extension {
//   List<Curve> curves;

//   ExtSupportedEllipticCurves(this.curves);

//   @override
//   String toString() {
//     final curvesStr = curves.map((c) => c.toString()).join('\n+ ');
//     return '[SupportedEllipticCurves]\n+ Curves:\n+ $curvesStr';
//   }

//   @override
//   ExtensionType getExtensionType() => ExtensionType.SupportedEllipticCurves;

//   @override
//   Uint8List encode() {
//     final result = Uint8List(2 + (curves.length * 2));
//     var offset = 0;
//     final byteData = ByteData.sublistView(result);
//     byteData.setUint16(offset, curves.length * 2, Endian.big);
//     offset += 2;
//     for (final curve in curves) {
//       byteData.setUint16(offset, curve.index, Endian.big);
//       offset += 2;
//     }
//     return result;
//   }

//   @override
//   void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
//     final curvesLength =
//         ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
//     offset += 2;
//     final curvesCount = curvesLength ~/ 2;
//     curves = List<Curve>.generate(
//         curvesCount,
//         (i) => Curve.values[ByteData.sublistView(buf, offset, offset + 2)
//             .getUint16(0, Endian.big)]);
//   }
// }

// class ExtUnknown implements Extension {
//   ExtensionType type;
//   int dataLength;

//   ExtUnknown(this.type, this.dataLength);

//   @override
//   String toString() {
//     return '[Unknown Extension Type] Ext Type: ${type.index}, Data: $dataLength bytes';
//   }

//   @override
//   ExtensionType getExtensionType() => ExtensionType.Unknown;

//   @override
//   Uint8List encode() {
//     throw UnsupportedError('ExtUnknown cannot be encoded, it\'s readonly');
//   }

//   @override
//   void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
//     // No decoding needed for this extension
//   }
// }

// enum SRTPProtectionProfile {
//   SRTP_AES128_CM_HMAC_SHA1_80,
//   SRTP_AES128_CM_HMAC_SHA1_32,
//   // Add other profiles as needed
// }

// enum PointFormat {
//   Uncompressed,
//   // Add other point formats as needed
// }

// enum Curve {
//   X25519,
//   // Add other curves as needed
// }

// extension CurveExtension on Curve {
//   String get name {
//     switch (this) {
//       case Curve.X25519:
//         return 'X25519';
//       default:
//         return 'Unknown Curve';
//     }
//   }

//   @override
//   String CurveToString() => name;
// }

class ExtUseExtendedMasterSecret {
  dynamic Decode(int extensionLength, Uint8List buf, int offset, int arrayLen)
  //error
  {
    return null;
  }

  Uint8List encode() {
    return Uint8List(0); // No data to encode for this extension
  }
}

class ExtRenegotiationInfo {
  Uint8List encode() {
    return Uint8List.fromList([0]); // Single byte with value 0
  }
}

class ExtUseSRTP {
  List<SRTPProtectionProfile> protectionProfiles = [];
  Uint8List? mki; //                []byte

  //  Uint8List encode() {
  //   final buffer = BytesBuilder();
  //   final protectionProfilesLength = protectionProfiles.length * 2;
  //   final byteData = ByteData(2);
  //   byteData.setUint16(0, protectionProfilesLength, Endian.big);
  //   buffer.add(byteData.buffer.asUint8List());

  //   for (final profile in protectionProfiles) {
  //     final profileData = ByteData(2);
  //     profileData.setUint16(0, profile.index, Endian.big);
  //     buffer.add(profileData.buffer.asUint8List());
  //   }

  //   buffer.addByte(mki?.length ?? 0);
  //   if (mki != null) {
  //     buffer.add(mki!);
  //   }

  //   return buffer.toBytes();
  // }
}

// Only Uncompressed was implemented.
// See for further Elliptic Curve Point Format classs: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2
class ExtSupportedPointFormats {
  List<PointFormat> pointFormats = [];

  dynamic Decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    var pointFormatsCount = buf[offset];
    offset++;
    //e.PointFormats = make([]PointFormat, pointFormatsCount)
    for (int i = 0; i < pointFormatsCount; i++) {
      pointFormats.add((buf[offset]));
      offset++;
    }

    return null;
  }

  // Uint8List encode() {
  //   final buffer = BytesBuilder();
  //   buffer.addByte(pointFormats.length);
  //   for (var format in pointFormats) {
  //     buffer.addByte(format.index);
  //   }
  //   return buffer.toBytes();
  // }
}

// Only X25519 was implemented.
// See for further NamedCurve classs: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.1
class ExtSupportedEllipticCurves {
  List<Curve> Curves = [];
  dynamic Decode(int extensionLength, Uint8List buf, int offset, int arrayLen)
  //error
  {
    var curvesLength = uint16(buf.sublist(offset, offset + 2));
    offset += 2;
    var curvesCount = curvesLength / 2;
    // e.Curves = make([]Curve, curvesCount)
    for (int i = 0; i < curvesCount; i++) {
      Curves.add(uint16(buf.sublist(offset, offset + 2)));
      offset += 2;
    }

    return null;
  }

  // Uint8List encode() {
  //   final buffer = BytesBuilder();
  //   final byteData = ByteData(2);
  //   byteData.setUint16(0, curves.length * 2, Endian.big);
  //   buffer.add(byteData.buffer.asUint8List());

  //   for (var curve in curves) {
  //     final curveData = ByteData(2);
  //     curveData.setUint16(0, curve.index, Endian.big);
  //     buffer.add(curveData.buffer.asUint8List());
  //   }

  //   return buffer.toBytes();
  // }

  @override
  String toString() {
    return Curves.toString();
  }
}

// ExtUnknown is not for processing. It is only for debugging purposes.
class ExtUnknown {
  ExtensionType? Type;
  int? DataLength;

  ExtUnknown(this.Type, this.DataLength);
  dynamic Decode(int extensionLength, Uint8List buf, int offset, int arrayLen)
  //error
  {
    print("Unknown extension: $Type cannot be decoded");
    return null;
  }

  Uint8List encode() {
    throw UnsupportedError('ExtUnknown cannot be encoded, it\'s readonly');
  }
}
