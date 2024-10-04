import 'dart:typed_data';

import 'package:dart_dtls_final/alert.dart';
import 'package:dart_dtls_final/certificate.dart';
import 'package:dart_dtls_final/certificate_request.dart';
import 'package:dart_dtls_final/certificate_verify.dart';
import 'package:dart_dtls_final/change_cipher_spec.dart';
import 'package:dart_dtls_final/client_hello.dart';
import 'package:dart_dtls_final/client_key_exchange.dart';
import 'package:dart_dtls_final/finished.dart';
import 'package:dart_dtls_final/handshake_context.dart';
import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';
import 'package:dart_dtls_final/server_hello.dart';
import 'package:dart_dtls_final/server_hello_done.dart';
import 'package:dart_dtls_final/server_key_exchange.dart';

abstract class BaseDtlsMessage {
  ContentType getContentType();
  Uint8List encode();
  int decode(Uint8List buf, int offset, int arrayLen);
  @override
  String toString();
}

abstract class BaseDtlsHandshakeMessage extends BaseDtlsMessage {
  HandshakeType getHandshakeType();
}

class DtlsErrors {
  static const errIncompleteDtlsMessage =
      'data contains incomplete DTLS message';
  static const errUnknownDtlsContentType =
      'data contains unknown DTLS content type';
  static const errUnknownDtlsHandshakeType =
      'data contains unknown DTLS handshake type';
}

bool isDtlsPacket(Uint8List buf, int offset, int arrayLen) {
  return arrayLen > 0 && buf[offset] >= 20 && buf[offset] <= 63;
}

Future<DecodeDtlsMessageResult> decodeDtlsMessage(
    HandshakeContext context, Uint8List buf, int offset, int arrayLen) async {
  if (arrayLen < 1) {
    throw ArgumentError(DtlsErrors.errIncompleteDtlsMessage);
  }
  final (header, decodedOffset, err) =
      RecordHeader.decode(buf, offset, arrayLen);
  offset = decodedOffset;

  if (header.epoch < context.clientEpoch) {
    // Ignore incoming message
    offset += header.length;
    return DecodeDtlsMessageResult(null, null, null, offset);
  }

  context.clientEpoch = header.epoch;

  Uint8List? decryptedBytes;
  Uint8List? encryptedBytes;
  if (header.epoch > 0) {
    // Data arrives encrypted, we should decrypt it before.
    if (context.isCipherSuiteInitialized) {
      encryptedBytes = buf.sublist(offset, offset + header.length);
      offset += header.length;
      decryptedBytes = await context.gcm?.decrypt(header, encryptedBytes);
    }
  }

  switch (header.contentType) {
    case ContentType.Handshake:
      if (decryptedBytes == null) {
        final offsetBackup = offset;
        final (handshakeHeader, decodedOffset, err) =
            HandshakeHeader.decode(buf, offset, arrayLen);

        offset += decodedOffset;

        if (handshakeHeader.length.value !=
            handshakeHeader.fragmentLength.value) {
          // Ignore fragmented packets
          print('Ignore fragmented packets: ${header.contentType}');
          return DecodeDtlsMessageResult(null, null, null, offset);
        }

        final result = await decodeHandshake(
            header, handshakeHeader, buf, offset, arrayLen);
        final copyArray = Uint8List.fromList(buf.sublist(offsetBackup, offset));
        context.handshakeMessagesReceived[handshakeHeader.handshakeType] =
            copyArray;

        return DecodeDtlsMessageResult(header, handshakeHeader, result, offset);
      } else {
        final (handshakeHeader, decodedOffset, err) =
            HandshakeHeader.decode(decryptedBytes, 0, decryptedBytes.length);
        final result = await decodeHandshake(
            header, handshakeHeader, decryptedBytes, 0, decryptedBytes.length);

        final copyArray = Uint8List.fromList(decryptedBytes);
        context.handshakeMessagesReceived[handshakeHeader.handshakeType] =
            copyArray;

        return DecodeDtlsMessageResult(header, handshakeHeader, result, offset);
      }
    case ContentType.ChangeCipherSpec:
      final changeCipherSpec = ChangeCipherSpec();
      offset = changeCipherSpec.decode(buf, offset, arrayLen);
      return DecodeDtlsMessageResult(header, null, changeCipherSpec, offset);
    case ContentType.Alert:
      final alert = Alert();
      if (decryptedBytes == null) {
        offset = alert.decode(buf, offset, arrayLen);
      } else {
        alert.decode(decryptedBytes, 0, decryptedBytes.length);
      }
      return DecodeDtlsMessageResult(header, null, alert, offset);
    default:
      throw ArgumentError(DtlsErrors.errUnknownDtlsContentType);
  }
}

Future<dynamic> decodeHandshake(
    RecordHeader header,
    HandshakeHeader handshakeHeader,
    Uint8List buf,
    int offset,
    int arrayLen) async {
  // late BaseDtlsMessage result;
  dynamic result;
  switch (handshakeHeader.handshakeType) {
    case HandshakeType.ClientHello:
      result = ClientHello();
      break;
    case HandshakeType.ServerHello:
      result = ServerHello();
      break;
    case HandshakeType.Certificate:
      result = Certificate();
      break;
    case HandshakeType.ServerKeyExchange:
      result = ServerKeyExchange();
      break;
    case HandshakeType.CertificateRequest:
      result = CertificateRequest();
      break;
    case HandshakeType.ServerHelloDone:
      result = ServerHelloDone();
      break;
    case HandshakeType.ClientKeyExchange:
      result = ClientKeyExchange();
      break;
    case HandshakeType.CertificateVerify:
      result = CertificateVerify();
      break;
    case HandshakeType.Finished:
      result = Finished();
      break;
    default:
      throw ArgumentError(DtlsErrors.errUnknownDtlsHandshakeType);
  }
  var (decodeOffset, err) = result.decode(buf, offset, arrayLen);
  return result;
}

class DecodeDtlsMessageResult {
  final RecordHeader? recordHeader;
  final HandshakeHeader? handshakeHeader;
  final dynamic message;
  final int offset;

  DecodeDtlsMessageResult(
      this.recordHeader, this.handshakeHeader, this.message, this.offset);
}

// class HandshakeHeader {
//   final HandshakeType handshakeType;
//   final Uint24 length;
//   final int messageSequence;
//   final Uint24 fragmentOffset;
//   final Uint24 fragmentLength;

//   HandshakeHeader({
//     required this.handshakeType,
//     required this.length,
//     required this.messageSequence,
//     required this.fragmentOffset,
//     required this.fragmentLength,
//   });

//   static HandshakeHeader decode(Uint8List buf, int offset, int arrayLen) {
//     final handshakeType = HandshakeType.values[buf[offset]];
//     offset++;
//     final length = Uint24.fromBytes(buf.sublist(offset, offset + 3));
//     offset += 3;
//     final messageSequence =
//         ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
//     offset += 2;
//     final fragmentOffset = Uint24.fromBytes(buf.sublist(offset, offset + 3));
//     offset += 3;
//     final fragmentLength = Uint24.fromBytes(buf.sublist(offset, offset + 3));
//     offset += 3;
//     return HandshakeHeader(
//       handshakeType: handshakeType,
//       length: length,
//       messageSequence: messageSequence,
//       fragmentOffset: fragmentOffset,
//       fragmentLength: fragmentLength,
//     );
//   }
// }
