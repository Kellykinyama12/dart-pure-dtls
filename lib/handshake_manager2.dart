import 'dart:typed_data';
import 'dart:math' as dmath;
import 'dart:io';
import 'package:dart_dtls_final/certificate.dart';
import 'package:dart_dtls_final/certificate_verify.dart';
import 'package:dart_dtls_final/client_hello.dart';
import 'package:dart_dtls_final/client_key_exchange.dart';
import 'package:dart_dtls_final/dtls_message.dart';
import 'package:dart_dtls_final/extensions.dart';
import 'package:dart_dtls_final/finished.dart';
import 'package:dart_dtls_final/handshake_context.dart';
import 'package:collection/collection.dart';
import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/hello_verify_request.dart';
import 'package:dart_dtls_final/record_header.dart';
import 'package:dart_dtls_final/server_hello.dart';
import 'package:dart_dtls_final/crypto.dart';

import 'dtls_state.dart';

class HandshakeManager {
  HandshakeContext newContext(InternetAddress addr, RawDatagramSocket conn,
      String clientUfrag, String expectedFingerprintHash) {
    return HandshakeContext();
  }

  Future<void> processIncomingMessage(
      HandshakeContext context, dynamic incomingMessage) async {
    print("Incoming message: ${incomingMessage.runtimeType}");

    decodeDtlsMessage(context, incomingMessage, 0, incomingMessage.length);
    switch (incomingMessage.runtimeType) {
      case ClientHello:
        final message = incomingMessage as ClientHello;
        switch (context.flight) {
          case Flight.Flight0:
            context.setDTLSState(DTLSState.Connecting);
            context.protocolVersion = message.version;
            context.cookie = generateDtlsCookie();
            context.flight = Flight.Flight2;
            final helloVerifyRequestResponse =
                createDtlsHelloVerifyRequest(context);
            //sendMessage(context, helloVerifyRequestResponse);
            return;
          default:
        }
    }
  }

  Uint8List generateDtlsCookie() {
    final cookie = Uint8List(20);
    final random = dmath.Random.secure();
    for (int i = 0; i < cookie.length; i++) {
      cookie[i] = random.nextInt(256);
    }
    return cookie;
  }

  HelloVerifyRequest createDtlsHelloVerifyRequest(HandshakeContext context) {
    return HelloVerifyRequest(
      version: context.protocolVersion,
      cookie: context.cookie,
    );
  }

  // void sendMessage(HandshakeContext context, dynamic message) {
  //   final encodedMessageBody = message.encode();
  //   final encodedMessage = BytesBuilder();
  //   HandshakeHeader? handshakeHeader;
  //   switch (message.getContentType()) {
  //     case ContentType.Handshake:
  //       final handshakeMessage = message as BaseDtlsHandshakeMessage;
  //       handshakeHeader = HandshakeHeader(
  //         handshakeType: handshakeMessage.getHandshakeType(),
  //         length: Uint24.fromUint32(encodedMessageBody.length),
  //         messageSequence: context.serverHandshakeSequenceNumber,
  //         fragmentOffset: Uint24.fromUint32(0),
  //         fragmentLength: Uint24.fromUint32(encodedMessageBody.length),
  //       );
  //       context.increaseServerHandshakeSequence();
  //       encodedMessage.add(handshakeHeader.encode());
  //       encodedMessage.add(encodedMessageBody);
  //       context.handshakeMessagesSent[handshakeMessage.getHandshakeType()] =
  //           encodedMessage.toBytes();
  //       break;
  //     case ContentType.ChangeCipherSpec:
  //       encodedMessage.add(encodedMessageBody);
  //       break;
  //   }

  //   final sequenceNumber = Uint8List(6);
  //   sequenceNumber[sequenceNumber.length - 1] += context.serverSequenceNumber;
  //   final header = RecordHeader(
  //     contentType: message.getContentType(),
  //     version: DtlsVersion.v1_2,
  //     epoch: context.serverEpoch,
  //     sequenceNumber: sequenceNumber,
  //     length: encodedMessage.length,
  //   );

  //   if (context.serverEpoch > 0) {
  //     // Epoch is greater than zero, we should encrypt it.
  //     if (context.isCipherSuiteInitialized) {
  //       final encryptedMessage =
  //           context.gcm!.encrypt(header, encodedMessage.toBytes());
  //       encodedMessage.clear();
  //       encodedMessage.add(encryptedMessage);
  //       header.length = encodedMessage.length;
  //     }
  //   }

  //   final encodedHeader = header.encode();
  //   encodedMessage.add(encodedHeader);

  //   context.conn.send(encodedMessage.toBytes(), context.addr);
  //   context.increaseServerSequence();
  // }
}
