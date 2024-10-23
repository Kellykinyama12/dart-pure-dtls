// import 'dart:typed_data';

// import 'package:dart_dtls_final/cipher_suites.dart';
// import 'package:dart_dtls_final/extensions.dart';
// import 'package:dart_dtls_final/handshake_header.dart';

// import 'dart:math' as dmath;

// import 'package:dart_dtls_final/record_header.dart';
// import 'package:dart_dtls_final/simple_extensions.dart'; // Import the dart:math library

// class ServerHello {
//   late DtlsVersion version;
//   late Random random;
//   late Uint8List sessionId;
//   late CipherSuiteID cipherSuiteID;
//   late int compressionMethodID;
//   late Map<ExtensionType, Extension> extensions;

//   ServerHello();

//   @override
//   String toString() {
//     final extensionsStr =
//         extensions.values.map((ext) => ext.toString()).toList();
//     return [
//       '[ServerHello] Ver: ${version.toString()}, SessionID: ${sessionId.length}',
//       'Cipher Suite ID: 0x${cipherSuiteID.index.toRadixString(16)}',
//       'Extensions: ${extensionsStr.join(', ')}',
//     ].join('\n');
//   }

//   ContentType getContentType() {
//     return ContentType.Handshake;
//   }

//   HandshakeType getHandshakeType() {
//     return HandshakeType.ServerHello;
//   }

//   int decode(Uint8List buf, int offset, int arrayLen) {
//     version = DtlsVersion.values[
//         ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big)];
//     offset += 2;

//     random = Random.decode(buf, offset, arrayLen);
//     offset += Random.randomBytesLength + 4;

//     final sessionIdLength = buf[offset];
//     offset++;
//     sessionId =
//         Uint8List.fromList(buf.sublist(offset, offset + sessionIdLength));
//     offset += sessionIdLength;

//     cipherSuiteID = CipherSuiteID.values[
//         ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big)];
//     offset += 2;

//     compressionMethodID = buf[offset];
//     offset++;

//     extensions = decodeExtensionMap(buf, offset, arrayLen);
//     offset += 2 +
//         extensions.values.fold(0, (sum, ext) => sum + ext.encode().length + 4);

//     return offset;
//   }

//   Uint8List encode() {
//     final result = BytesBuilder();
//     final byteData = ByteData(2);
//     byteData.setUint16(0, version.value, Endian.big);
//     result.add(byteData.buffer.asUint8List());
//     result.add(random.encode());

//     result.add(Uint8List.fromList([sessionId.length]));
//     result.add(sessionId);

//     byteData.setUint16(0, cipherSuiteID.index, Endian.big);
//     result.add(byteData.buffer.asUint8List());

//     result.add(Uint8List.fromList([compressionMethodID]));

//     final encodedExtensions = encodeExtensionMap(extensions);
//     result.add(encodedExtensions);

//     return result.toBytes();
//   }
// }

// class Random {
//   static const int randomBytesLength = 28;

//   DateTime gmtUnixTime;
//   Uint8List randomBytes;

//   Random(this.gmtUnixTime, this.randomBytes);

//   Uint8List encode() {
//     final result = Uint8List(4 + randomBytesLength);
//     final byteData = ByteData.sublistView(result);
//     byteData.setUint32(
//         0, gmtUnixTime.millisecondsSinceEpoch ~/ 1000, Endian.big);
//     result.setRange(4, 4 + randomBytesLength, randomBytes);
//     return result;
//   }

//   void generate() {
//     gmtUnixTime = DateTime.now().toUtc();
//     randomBytes = Uint8List(randomBytesLength);
//     final random = dmath.Random.secure();
//     for (int i = 0; i < randomBytesLength; i++) {
//       randomBytes[i] = random.nextInt(256);
//     }
//   }

//   static Random decode(Uint8List buf, int offset, int arrayLen) {
//     final gmtUnixTime = DateTime.fromMillisecondsSinceEpoch(
//       ByteData.sublistView(buf, offset, offset + 4).getUint32(0, Endian.big) *
//           1000,
//       isUtc: true,
//     );
//     offset += 4;
//     final randomBytes =
//         Uint8List.fromList(buf.sublist(offset, offset + randomBytesLength));
//     offset += randomBytesLength;
//     return Random(gmtUnixTime, randomBytes);
//   }
// }

// // abstract class Extension {
// //   ExtensionType getExtensionType();
// //   Uint8List encode();
// //   void decode(int extensionLength, Uint8List buf, int offset, int arrayLen);
// //   @override
// //   String toString();
// // }

// Map<ExtensionType, Extension> decodeExtensionMap(
//     Uint8List buf, int offset, int arrayLen) {
//   final result = <ExtensionType, Extension>{};
//   final length =
//       ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
//   offset += 2;
//   final offsetBackup = offset;
//   while (offset < offsetBackup + length) {
//     final extensionType = ExtensionType.values[
//         ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big)];
//     offset += 2;
//     final extensionLength =
//         ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
//     offset += 2;
//     Extension extension;
//     switch (extensionType) {
//       // Add your extension decoding logic here
//       default:
//         extension = ExtUnknown(extensionType, extensionLength);
//     }
//     extension.decode(extensionLength, buf, offset, arrayLen);
//     result[extensionType] = extension;
//     offset += extensionLength;
//   }
//   return result;
// }

// Uint8List encodeExtensionMap(Map<ExtensionType, Extension> extensionMap) {
//   final encodedBody = BytesBuilder();
//   for (final extension in extensionMap.values) {
//     final encodedExtension = extension.encode();
//     final byteData = ByteData(2);
//     byteData.setUint16(0, extension.getExtensionType().index, Endian.big);
//     encodedBody.add(byteData.buffer.asUint8List());
//     byteData.setUint16(0, encodedExtension.length, Endian.big);
//     encodedBody.add(byteData.buffer.asUint8List());
//     encodedBody.add(encodedExtension);
//   }
//   final result = BytesBuilder();
//   final byteData = ByteData(2);
//   byteData.setUint16(0, encodedBody.length, Endian.big);
//   result.add(byteData.buffer.asUint8List());
//   result.add(encodedBody.toBytes());
//   return result.toBytes();
// }

// class ExtUnknown implements Extension {
//   ExtensionType type;
//   int dataLength;

//   ExtUnknown(this.type, this.dataLength);

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

//   @override
//   String toString() {
//     return '[Unknown Extension Type] Ext Type: ${type.index}, Data: $dataLength bytes';
//   }
// }

import 'dart:typed_data';

import 'package:dart_dtls_final/client_hello.dart';
import 'package:dart_dtls_final/dtls_rand.dart';
import 'package:dart_dtls_final/extensions.dart';
import 'package:dart_dtls_final/random.dart';
import 'package:dart_dtls_final/utils.dart';

// import 'package:dtls2/src/extensions.dart';
// import 'package:dtls2/src/random.dart';
// import 'package:dtls2/src/utils.dart';

class ServerHello {
  int? version;
  DtlsRandom? random;
  Uint8List? SessionID;
  int? cipherSuiteID;
  int? compressionMethodID;
  Map<ExtensionType, dynamic> extensions = {};

  dynamic decode(Uint8List buf, int offset, int arrayLen)
  //(int, error)
  {
    // https://github.com/pion/dtls/blob/680c851ed9efc926757f7df6858c82ac63f03a5d/pkg/protocol/handshake/message_client_hello.go#L66
    version = uint16(buf.sublist(offset, offset + 2));
    offset += 2;

    var decodedRandom;
    var err;
    (decodedRandom, offset, err) = DecodeRandom(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    random = decodedRandom;

    var sessionIDLength = buf[offset];
    offset++;
    //m.SessionID = make([]byte, sessionIDLength)
    SessionID = buf.sublist(offset, offset + sessionIDLength);
    offset += sessionIDLength;

    cipherSuiteID = uint16(buf.sublist(offset, offset + 2));
    offset += 2;

    compressionMethodID = buf[offset];
    offset++;
    var extensionsMap;
    (extensionsMap, offset, err) = DecodeExtensionMap(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    extensions = extensionsMap;
    return (offset, null);
  }

  // Uint8List encode() {
  //   final result = Uint8List((4 + randomBytesLength).toInt());
  //   final byteData = ByteData.sublistView(result);
  //   byteData.setUint32(
  //       0, random!.GMTUnixTime!, Endian.big);
  //   result.setRange(4, 4 + randomBytesLength, random!.RandomBytes);
  //   return result;
  // }

  Uint8List encode() {
    final result = BytesBuilder();
    final byteData = ByteData(2);
    byteData.setUint16(0, version!, Endian.big);
    result.add(byteData.buffer.asUint8List());
    result.add(random!.Encode());

    result.add(Uint8List.fromList([SessionID!.length]));
    result.add(SessionID!);

    byteData.setUint16(0, cipherSuiteID!, Endian.big);
    result.add(byteData.buffer.asUint8List());

    result.add(Uint8List.fromList([compressionMethodID!]));

    final encodedExtensions = encodeExtensionMap(extensions);
    result.add(encodedExtensions);

    return result.toBytes();
  }

  Uint8List encodeExtensionMap(Map<ExtensionType, dynamic> extensionMap) {
    final encodedBody = BytesBuilder();
    for (final extension in extensionMap.values) {
      final encodedExtension = extension.encode();
      final byteData = ByteData(2);
      byteData.setUint16(0, extension.getExtensionType().index, Endian.big);
      encodedBody.add(byteData.buffer.asUint8List());
      byteData.setUint16(0, encodedExtension.length, Endian.big);
      encodedBody.add(byteData.buffer.asUint8List());
      encodedBody.add(encodedExtension);
    }
    final result = BytesBuilder();
    final byteData = ByteData(2);
    byteData.setUint16(0, encodedBody.length, Endian.big);
    result.add(byteData.buffer.asUint8List());
    result.add(encodedBody.toBytes());
    return result.toBytes();
  }

  @override
  String toString() {
    // TODO: implement ==
    return "{ version: $version, random: $random, session: $SessionID, cipher suit id: $cipherSuiteID, extensions: $extensions}";
  }
}
