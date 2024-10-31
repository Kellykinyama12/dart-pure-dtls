// import 'dart:typed_data';

// import 'package:dart_dtls_final/record_header.dart';

// enum AlertLevel {
//   Warning,
//   Fatal,
// }

// extension AlertLevelExtension on AlertLevel {
//   String get name {
//     switch (this) {
//       case AlertLevel.Warning:
//         return 'Warning';
//       case AlertLevel.Fatal:
//         return 'Fatal';
//       default:
//         return 'Unknown Alert Type';
//     }
//   }

//   String toCustomString() {
//     return '$name (${this.index + 1})';
//   }
// }

// enum AlertDescription {
//   CloseNotify,
//   UnexpectedMessage,
//   BadRecordMac,
//   DecryptionFailed,
//   RecordOverflow,
//   DecompressionFailure,
//   HandshakeFailure,
//   NoCertificate,
//   BadCertificate,
//   UnsupportedCertificate,
//   CertificateRevoked,
//   CertificateExpired,
//   CertificateUnknown,
//   IllegalParameter,
//   UnknownCA,
//   AccessDenied,
//   DecodeError,
//   DecryptError,
//   ExportRestriction,
//   ProtocolVersion,
//   InsufficientSecurity,
//   InternalError,
//   UserCanceled,
//   NoRenegotiation,
//   UnsupportedExtension,
// }

// extension AlertDescriptionExtension on AlertDescription {
//   String get name {
//     switch (this) {
//       case AlertDescription.CloseNotify:
//         return 'CloseNotify';
//       case AlertDescription.UnexpectedMessage:
//         return 'UnexpectedMessage';
//       case AlertDescription.BadRecordMac:
//         return 'BadRecordMac';
//       case AlertDescription.DecryptionFailed:
//         return 'DecryptionFailed';
//       case AlertDescription.RecordOverflow:
//         return 'RecordOverflow';
//       case AlertDescription.DecompressionFailure:
//         return 'DecompressionFailure';
//       case AlertDescription.HandshakeFailure:
//         return 'HandshakeFailure';
//       case AlertDescription.NoCertificate:
//         return 'NoCertificate';
//       case AlertDescription.BadCertificate:
//         return 'BadCertificate';
//       case AlertDescription.UnsupportedCertificate:
//         return 'UnsupportedCertificate';
//       case AlertDescription.CertificateRevoked:
//         return 'CertificateRevoked';
//       case AlertDescription.CertificateExpired:
//         return 'CertificateExpired';
//       case AlertDescription.CertificateUnknown:
//         return 'CertificateUnknown';
//       case AlertDescription.IllegalParameter:
//         return 'IllegalParameter';
//       case AlertDescription.UnknownCA:
//         return 'UnknownCA';
//       case AlertDescription.AccessDenied:
//         return 'AccessDenied';
//       case AlertDescription.DecodeError:
//         return 'DecodeError';
//       case AlertDescription.DecryptError:
//         return 'DecryptError';
//       case AlertDescription.ExportRestriction:
//         return 'ExportRestriction';
//       case AlertDescription.ProtocolVersion:
//         return 'ProtocolVersion';
//       case AlertDescription.InsufficientSecurity:
//         return 'InsufficientSecurity';
//       case AlertDescription.InternalError:
//         return 'InternalError';
//       case AlertDescription.UserCanceled:
//         return 'UserCanceled';
//       case AlertDescription.NoRenegotiation:
//         return 'NoRenegotiation';
//       case AlertDescription.UnsupportedExtension:
//         return 'UnsupportedExtension';
//       default:
//         return 'Unknown Alert Description';
//     }
//   }

//   String toCustomString() {
//     return '$name (${this.index})';
//   }
// }

// class Alert {
//   late AlertLevel level;
//   late AlertDescription description;

//   Alert();

//   ContentType getContentType() {
//     return ContentType.Alert;
//   }

//   @override
//   String toString() {
//     return 'Alert ${level.toCustomString()} ${description.toCustomString()}';
//   }

//   int decode(Uint8List buf, int offset, int arrayLen) {
//     level = AlertLevel.values[buf[offset] - 1];
//     offset++;
//     description = AlertDescription.values[buf[offset]];
//     offset++;
//     return offset;
//   }

//   Uint8List encode() {
//     final buffer = BytesBuilder();

//     // Encode alert level
//     buffer.addByte(level.index + 1);

//     // Encode alert description
//     buffer.addByte(description.index);

//     return buffer.toBytes();
//   }
// }

import 'dart:typed_data';

enum AlertLevel {
  AlertLevelWarning(1),
  AlertLevelFatal(2);

  const AlertLevel(this.value);

  final int value;

  factory AlertLevel.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

enum AlertDescription {
  AlertDescriptionCloseNotify(0),
  AlertDescriptionUnexpectedMessage(10),
  AlertDescriptionBadRecordMac(20),
  AlertDescriptionDecryptionFailed(21),
  AlertDescriptionRecordOverflow(22),
  AlertDescriptionDecompressionFailure(30),
  AlertDescriptionHandshakeFailure(40),
  AlertDescriptionNoCertificate(41),
  AlertDescriptionBadCertificate(42),
  AlertDescriptionUnsupportedCertificate(43),
  AlertDescriptionCertificateRevoked(44),
  AlertDescriptionCertificateExpired(45),
  AlertDescriptionCertificateUnknown(46),
  AlertDescriptionIllegalParameter(47),
  AlertDescriptionUnknownCA(48),
  AlertDescriptionAccessDenied(49),
  AlertDescriptionDecodeError(50),
  AlertDescriptionDecryptError(51),
  AlertDescriptionExportRestriction(60),
  AlertDescriptionProtocolVersion(70),
  AlertDescriptionInsufficientSecurity(71),
  AlertDescriptionInternalError(80),
  AlertDescriptionUserCanceled(90),
  AlertDescriptionNoRenegotiation(100),
  AlertDescriptionUnsupportedExtension(110);

  const AlertDescription(this.value);

  final int value;

  factory AlertDescription.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

class Alert {
  AlertLevel? Level;
  AlertDescription? Description;

  (int, bool?) decode(Uint8List buf, int offset, int arrayLen)
  //(int, error)
  {
    Level = AlertLevel.fromInt(buf[offset]);
    offset++;
    Description = AlertDescription.fromInt(buf[offset]);
    offset++;

    print("alert: $this");

    return (offset, null);
  }

  @override
  String toString() {
    return "alert level: $Level, alert description: $Description";
  }
}
