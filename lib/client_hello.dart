import 'dart:typed_data';
import 'dart:math' as dmath; // Import the dart:math library

import 'package:dart_dtls_final/cipher_suites.dart';
import 'package:dart_dtls_final/extensions.dart';
import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';
import 'package:dart_dtls_final/simple_extensions.dart';
import 'package:dart_dtls_final/utils.dart';

class ClientHello {
  late Uint8List version;
  late Random random;
  late Uint8List cookie;
  late Uint8List sessionId;
  late List<intCipherSuiteID> cipherSuiteIDs;
  late Uint8List compressionMethodIDs;
  late Map<ExtensionType, dynamic> extensions;

  ClientHello();

  @override
  String toString() {
    // final extensionsStr =
    //     extensions.values.map((ext) => ext.toString()).toList();
    // final cipherSuiteIDsStr =
    //     cipherSuiteIDs.map((cs) => cs.toString()).toList();
    // final cookieStr = cookie.isEmpty
    //     ? '<nil>'
    //     : '0x${cookie.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';

    return [
      '[ClientHello] Ver: ${version.toString()}, Cookie: $cookie, SessionID: ${sessionId.length}',
      'Cipher Suite IDs: ${cipherSuiteIDs}',
      'Extensions: ${extensions}',
    ].join('\n');
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ClientHello;
  }

  Uint8List encode() {
    final buffer = BytesBuilder();

    // Encode version
    buffer.add(version);

    // Encode random
    buffer.add(random.encode());

    // Encode session ID
    buffer.addByte(sessionId.length);
    buffer.add(sessionId);

    // Encode cookie
    buffer.addByte(cookie.length);
    buffer.add(cookie);

    // Encode cipher suite IDs
    final cipherSuiteLength = cipherSuiteIDs.length * 2;
    final cipherSuiteLengthBytes = ByteData(2);
    cipherSuiteLengthBytes.setUint16(0, cipherSuiteLength, Endian.big);
    buffer.add(cipherSuiteLengthBytes.buffer.asUint8List());
    for (var id in cipherSuiteIDs) {
      final idBytes = ByteData(2);
      idBytes.setUint16(0, id, Endian.big);
      buffer.add(idBytes.buffer.asUint8List());
    }

    // Encode compression method IDs
    buffer.addByte(compressionMethodIDs.length);
    buffer.add(compressionMethodIDs);

    // Encode extensions
    final extensionsBuffer = BytesBuilder();
    for (var entry in extensions.entries) {
      final extensionTypeBytes = ByteData(2);
      extensionTypeBytes.setUint16(0, entry.key.value, Endian.big);
      extensionsBuffer.add(extensionTypeBytes.buffer.asUint8List());

      final extensionData = entry.value.encode();
      final extensionLengthBytes = ByteData(2);
      extensionLengthBytes.setUint16(0, extensionData.length, Endian.big);
      extensionsBuffer.add(extensionLengthBytes.buffer.asUint8List());
      extensionsBuffer.add(extensionData);
    }
    final extensionsLengthBytes = ByteData(2);
    extensionsLengthBytes.setUint16(0, extensionsBuffer.length, Endian.big);
    buffer.add(extensionsLengthBytes.buffer.asUint8List());
    buffer.add(extensionsBuffer.toBytes());

    return buffer.toBytes();
  }

  (int, bool?) decode(Uint8List buf, int offset, int arrayLen) {
    // version = DtlsVersion.values[
    //     ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big)];
    version = buf.sublist(offset, offset + 2);
    offset += 2;

    var (decodedRandom, decodeOffset, err) =
        Random.decode(buf, offset, arrayLen);
    //offset = decodeOffset;
    random = decodedRandom;
    offset += Random.randomBytesLength + 4;

    final sessionIdLength = buf[offset];
    offset++;
    sessionId =
        Uint8List.fromList(buf.sublist(offset, offset + sessionIdLength));
    offset += sessionIdLength;

    final cookieLength = buf[offset];
    print("cookie length: $cookieLength");
    offset++;
    print("buffer length: ${buf.length - offset}");
    cookie = buf.sublist(offset, offset + cookieLength);
    offset += cookieLength;

    //print("cookie: $cookie, length: $cookieLength");

    var (decodedCipherSuiteIDs, decodedOffset, errCipher) =
        decodeCipherSuiteIDs(buf, offset, arrayLen);
    cipherSuiteIDs = decodedCipherSuiteIDs;
    offset += 2 + cipherSuiteIDs.length * 2;

    if (errCipher != null) {
      return (offset, errCipher);
    }

    compressionMethodIDs = decodeCompressionMethodIDs(buf, offset, arrayLen);
    offset += 1 + compressionMethodIDs.length;

    var exts;
    (exts, offset, err) = DecodeExtensionMap(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    extensions = exts;

    return (offset, null);

    // extensions = DecodeExtensionMap(buf, offset, arrayLen);
    // offset += 2 +
    //     extensions.values.fold(0, (sum, ext) => sum + ext.encode().length + 4);

    // return (offset, null);
  }

  int uint16(Uint8List b) {
    // https://stackoverflow.com/questions/45000982/convert-3-bytes-to-int-in-go
    //return (b[2]) | (b[1]) << 8 | (b[0]) << 16;

    if (b.length != 2) {
      throw ArgumentError("Incorrect length");
    }
    var data = b.sublist(0);
    var buffer = data.buffer;
    var bytes = ByteData.view(buffer);
    return bytes.getUint16(0);
  }

  (List<intCipherSuiteID>, int, bool?) decodeCipherSuiteIDs(
      Uint8List buf, int offset, int arrayLen) {
    // final length =
    //     ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    // final count = length ~/ 2;
    // offset += 2;
    // return (
    //   List<intCipherSuiteID>.generate(count, (i) {
    //     final id = ByteData.sublistView(buf, offset, offset + 2)
    //         .getUint16(0, Endian.big);
    //     offset += 2;
    //     return id;
    //   }),
    //   offset,
    //   null
    // );

    var length = uint16(buf.sublist(offset, offset + 2));

    var count = length ~/ 2;
    offset += 2;

    // print("cipher suites length: $count");
    List<intCipherSuiteID> result = [];
    for (int i = 0; i < count; i++) {
      try {
        result.add(uint16(buf.sublist(offset, offset + 2)));
        // print("Cipher suit id: ${result[i]}");
        offset += 2;
      } catch (e) {
        return (result, offset, true);
      }
    }
    return (result, offset, null);
  }

  Uint8List decodeCompressionMethodIDs(
      Uint8List buf, int offset, int arrayLen) {
    final count = buf[offset];
    offset++;
    return Uint8List.fromList(buf.sublist(offset, offset + count));
  }
}

class Random {
  static const int randomBytesLength = 28;

  DateTime gmtUnixTime;
  Uint8List randomBytes;

  Random(this.gmtUnixTime, this.randomBytes);

  Uint8List encode() {
    final result = Uint8List(4 + randomBytesLength);
    final byteData = ByteData.sublistView(result);
    byteData.setUint32(
        0, gmtUnixTime.millisecondsSinceEpoch ~/ 1000, Endian.big);
    result.setRange(4, 4 + randomBytesLength, randomBytes);
    return result;
  }

  void generate() {
    gmtUnixTime = DateTime.now().toUtc();
    randomBytes = Uint8List(randomBytesLength);
    final random = dmath.Random
        .secure(); // Use Random.secure() to generate secure random numbers
    for (int i = 0; i < randomBytesLength; i++) {
      randomBytes[i] = random.nextInt(256);
    }
  }

  static (Random, int, bool?) decode(Uint8List buf, int offset, int arrayLen) {
    final gmtUnixTime = DateTime.fromMillisecondsSinceEpoch(
      ByteData.sublistView(buf, offset, offset + 4).getUint32(0, Endian.big) *
          1000,
      isUtc: true,
    );
    offset += 4;
    final randomBytes =
        Uint8List.fromList(buf.sublist(offset, offset + randomBytesLength));
    offset += randomBytesLength;
    return (Random(gmtUnixTime, randomBytes), offset, null);
  }
}

// abstract class Extension {
//   ExtensionType getExtensionType();
//   Uint8List encode();
//   void decode(int extensionLength, Uint8List buf, int offset, int arrayLen);
//   @override
//   String toString();
// }

// Map<ExtensionType, Extension> decodeExtensionMap(
//     Uint8List buf, int offset, int arrayLen) {
//   final result = <ExtensionType, Extension>{};
//   final length =
//       ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
//   offset += 2;
//   final offsetBackup = offset;
//   while (offset < offsetBackup + length && offset < arrayLen) {
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

dynamic DecodeExtensionMap(Uint8List buf, int offset, int arrayLen)
//(map[ExtensionType]Extension, int, error)
{
  Map<ExtensionType, dynamic> result = {};
  var length = uint16(buf.sublist(offset, offset + 2));
  offset += 2;
  var offsetBackup = offset;
  while (offset < offsetBackup + length) {
    var extensionType =
        ExtensionType.fromInt(uint16(buf.sublist(offset, offset + 2)));
    offset += 2;
    var extensionLength = uint16(buf.sublist(offset, offset + 2));
    offset += 2;
    var extension;
    switch (extensionType) {
      case ExtensionType.UseExtendedMasterSecret:
        extension = ExtUseExtendedMasterSecret();
      case ExtensionType.UseSRTP:
        extension = ExtUseSRTP();
      case ExtensionType.SupportedPointFormats:
        extension = ExtSupportedPointFormats();
      case ExtensionType.SupportedEllipticCurves:
        extension = ExtSupportedEllipticCurves();
      default:
        extension = ExtUnknown(extensionType, extensionLength);
    }
    if (extension != null) {
      var err = extension.Decode(extensionLength, buf, offset, arrayLen);

      if (err != null) {
        return (null, offset, err);
      }
      result[extensionType] = extension;
    }
    offset += extensionLength;
  }
  return (result, offset, null);
}

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
