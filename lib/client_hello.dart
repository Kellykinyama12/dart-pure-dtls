import 'dart:typed_data';
import 'dart:math' as dmath; // Import the dart:math library

import 'package:dart_dtls_final/cipher_suites.dart';
import 'package:dart_dtls_final/extensions.dart';
import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

class ClientHello {
  late DtlsVersion version;
  late Random random;
  late Uint8List cookie;
  late Uint8List sessionId;
  late List<CipherSuiteID> cipherSuiteIDs;
  late Uint8List compressionMethodIDs;
  late Map<ExtensionType, Extension> extensions;

  ClientHello();

  @override
  String toString() {
    final extensionsStr =
        extensions.values.map((ext) => ext.toString()).toList();
    final cipherSuiteIDsStr =
        cipherSuiteIDs.map((cs) => cs.toString()).toList();
    final cookieStr = cookie.isEmpty
        ? '<nil>'
        : '0x${cookie.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';

    return [
      '[ClientHello] Ver: ${version.toString()}, Cookie: $cookieStr, SessionID: ${sessionId.length}',
      'Cipher Suite IDs: ${cipherSuiteIDsStr.join(', ')}',
      'Extensions: ${extensionsStr.join(', ')}',
    ].join('\n');
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ClientHello;
  }

  Uint8List encode() {
    // Implement encoding logic
    return Uint8List(0);
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    version = DtlsVersion.values[
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big)];
    offset += 2;

    random = Random.decode(buf, offset, arrayLen);
    offset += Random.randomBytesLength + 4;

    final sessionIdLength = buf[offset];
    offset++;
    sessionId =
        Uint8List.fromList(buf.sublist(offset, offset + sessionIdLength));
    offset += sessionIdLength;

    final cookieLength = buf[offset];
    offset++;
    cookie = Uint8List.fromList(buf.sublist(offset, offset + cookieLength));
    offset += cookieLength;

    cipherSuiteIDs = decodeCipherSuiteIDs(buf, offset, arrayLen);
    offset += 2 + cipherSuiteIDs.length * 2;

    compressionMethodIDs = decodeCompressionMethodIDs(buf, offset, arrayLen);
    offset += 1 + compressionMethodIDs.length;

    extensions = decodeExtensionMap(buf, offset, arrayLen);
    offset += 2 +
        extensions.values.fold(0, (sum, ext) => sum + ext.encode().length + 4);

    return offset;
  }

  List<CipherSuiteID> decodeCipherSuiteIDs(
      Uint8List buf, int offset, int arrayLen) {
    final length =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    final count = length ~/ 2;
    offset += 2;
    return List<CipherSuiteID>.generate(count, (i) {
      final id = CipherSuiteID.values[
          ByteData.sublistView(buf, offset, offset + 2)
              .getUint16(0, Endian.big)];
      offset += 2;
      return id;
    });
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

  static Random decode(Uint8List buf, int offset, int arrayLen) {
    final gmtUnixTime = DateTime.fromMillisecondsSinceEpoch(
      ByteData.sublistView(buf, offset, offset + 4).getUint32(0, Endian.big) *
          1000,
      isUtc: true,
    );
    offset += 4;
    final randomBytes =
        Uint8List.fromList(buf.sublist(offset, offset + randomBytesLength));
    offset += randomBytesLength;
    return Random(gmtUnixTime, randomBytes);
  }
}

// abstract class Extension {
//   ExtensionType getExtensionType();
//   Uint8List encode();
//   void decode(int extensionLength, Uint8List buf, int offset, int arrayLen);
//   @override
//   String toString();
// }

Map<ExtensionType, Extension> decodeExtensionMap(
    Uint8List buf, int offset, int arrayLen) {
  final result = <ExtensionType, Extension>{};
  final length =
      ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
  offset += 2;
  final offsetBackup = offset;
  while (offset < offsetBackup + length) {
    final extensionType = ExtensionType.values[
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big)];
    offset += 2;
    final extensionLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    Extension extension;
    switch (extensionType) {
      // Add your extension decoding logic here
      default:
        extension = ExtUnknown(extensionType, extensionLength);
    }
    extension.decode(extensionLength, buf, offset, arrayLen);
    result[extensionType] = extension;
    offset += extensionLength;
  }
  return result;
}

class ExtUnknown implements Extension {
  ExtensionType type;
  int dataLength;

  ExtUnknown(this.type, this.dataLength);

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

  @override
  String toString() {
    return '[Unknown Extension Type] Ext Type: ${type.index}, Data: $dataLength bytes';
  }
}
