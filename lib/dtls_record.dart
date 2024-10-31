import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

class HelloVerifyRequest {
  final int messageType = 3; // Message type for HelloVerifyRequest
  final int version = 0xFEFF; // DTLS version
  final Uint8List cookie;

  HelloVerifyRequest(this.cookie);

  Uint8List toBytes() {
    final cookieLength = cookie.length;
    final buffer = BytesBuilder();

    buffer.addByte(messageType);
    buffer.addByte(version >> 8);
    buffer.addByte(version & 0xFF);
    buffer.addByte(cookieLength);
    buffer.add(cookie);

    return buffer.toBytes();
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.HelloVerifyRequest;
  }
}

class DTLSRecord {
  final int contentType = 22; // Handshake
  final int version = 0xFEFF; // DTLS version
  final int epoch = 0; // Initial epoch
  final int sequenceNumber; // Initial sequence number
  final Uint8List handshakeMessage;

  DTLSRecord(this.handshakeMessage, this.sequenceNumber);

  Uint8List toBytes() {
    final buffer = BytesBuilder();

    buffer.addByte(contentType);
    buffer.addByte(version >> 8);
    buffer.addByte(version & 0xFF);
    buffer.addByte(epoch >> 8);
    buffer.addByte(epoch & 0xFF);
    buffer.add(Uint8List(6)); // 6 bytes for sequence number
    buffer.addByte(handshakeMessage.length >> 8);
    buffer.addByte(handshakeMessage.length & 0xFF);
    buffer.add(handshakeMessage);

    return buffer.toBytes();
  }
}
