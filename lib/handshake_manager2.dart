import 'dart:convert';
import 'dart:typed_data';
import 'dart:math' as dmath;
import 'dart:io';
import 'package:dart_dtls_final/certificate.dart';
import 'package:dart_dtls_final/certificate_verify.dart';
import 'package:dart_dtls_final/client_hello.dart';
import 'package:dart_dtls_final/client_key_exchange.dart';
import 'package:dart_dtls_final/dtls_message.dart';
import 'package:dart_dtls_final/dtls_record.dart';
import 'package:dart_dtls_final/extensions.dart';
import 'package:dart_dtls_final/finished.dart';
import 'package:dart_dtls_final/handshake_context.dart';
import 'package:collection/collection.dart';
import 'package:dart_dtls_final/handshake_header.dart';
//import 'package:dart_dtls_final/hello_verify_request.dart';
import 'package:dart_dtls_final/record_header.dart';
import 'package:dart_dtls_final/server_hello.dart';
import 'package:dart_dtls_final/crypto.dart';
import 'package:dart_dtls_final/utils.dart';

import 'dtls_state.dart';

class HandshakeManager {
  // HandshakeContext newContext(InternetAddress addr, RawDatagramSocket conn,
  //     String clientUfrag, String expectedFingerprintHash) {
  //   return HandshakeContext();
  // }

  Future<void> processIncomingMessage(
      HandshakeContext context, dynamic incomingMessage) async {
    // print("Incoming message: ${incomingMessage.runtimeType}");

    final decodedMessage = await decodeDtlsMessage(
        context, incomingMessage, 0, incomingMessage.length);
    //print("Incoming message type: ${decodedMessage.message.runtimeType}");
    switch (decodedMessage.message.runtimeType) {
      case ClientHello:
        final message = decodedMessage.message as ClientHello;
        switch (context.flight) {
          case Flight.Flight0:
            context.setDTLSState(DTLSState.Connecting);
            context.protocolVersion = message.version;
            //print("context protocol version: ${context.protocolVersion}");
            context.cookie = generateDtlsCookie();
            //print("context protocol version: ${context.cookie}");
            context.flight = Flight.Flight2;
            final helloVerifyRequestResponse =
                createDtlsHelloVerifyRequest(context);
            //print("Hello verify request response: $helloVerifyRequestResponse");
            sendMessage(context, helloVerifyRequestResponse);
            return;
          case Flight.Flight2:
            {
              if (message.cookie.isEmpty) {
                context.flight = Flight.Flight0;
                print("Empty cookie: ${message.cookie}");
                context.setDTLSState(DTLSState.Connecting);
                context.protocolVersion = message.version;
                //print("context protocol version: ${context.protocolVersion}");
                context.cookie = generateDtlsCookie();
                //print("context protocol version: ${context.cookie}");
                context.flight = Flight.Flight2;
                final helloVerifyRequestResponse =
                    createDtlsHelloVerifyRequest(context);
                //print("Hello verify request response: $helloVerifyRequestResponse");
                sendMessage(context, helloVerifyRequestResponse);
              }
              print("Received cookie: ${message.cookie}");
            }
          default:
            print("Unhandle flight: ${context.flight}");
        }
      default:
        {
          print("Unhandle Runtime type: ${decodedMessage.message.runtimeType}");
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
    HelloVerifyRequest hvr = HelloVerifyRequest(generateDtlsCookie());
    // hvr.version = context.protocolVersion;
    // hvr.cookie = context.cookie;
    return hvr;
  }

//   func (m *HandshakeManager) SendMessage(context *HandshakeContext, message BaseDtlsMessage) {
// 	encodedMessageBody := message.Encode()
// 	encodedMessage := make([]byte, 0)
// 	var handshakeHeader *HandshakeHeader
// 	switch message.GetContentType() {
// 	case ContentTypeHandshake:
// 		handshakeMessage := message.(BaseDtlsHandshakeMessage)
// 		handshakeHeader = &HandshakeHeader{
// 			HandshakeType:   handshakeMessage.GetHandshakeType(),
// 			Length:          NewUint24FromUInt32((uint32(len(encodedMessageBody)))),
// 			MessageSequence: context.ServerHandshakeSequenceNumber,
// 			FragmentOffset:  NewUint24FromUInt32(0),
// 			FragmentLength:  NewUint24FromUInt32((uint32(len(encodedMessageBody)))),
// 		}
// 		context.IncreaseServerHandshakeSequence()
// 		encodedHandshakeHeader := handshakeHeader.Encode()
// 		encodedMessage = append(encodedMessage, encodedHandshakeHeader...)
// 		encodedMessage = append(encodedMessage, encodedMessageBody...)
// 		context.HandshakeMessagesSent[handshakeMessage.GetHandshakeType()] = encodedMessage
// 	case ContentTypeChangeCipherSpec:
// 		encodedMessage = append(encodedMessage, encodedMessageBody...)
// 	}

// 	sequenceNumber := [6]byte{}
// 	sequenceNumber[len(sequenceNumber)-1] += byte(context.ServerSequenceNumber)
// 	header := &RecordHeader{
// 		ContentType:    message.GetContentType(),
// 		Version:        DtlsVersion1_2,
// 		Epoch:          context.ServerEpoch,
// 		SequenceNumber: sequenceNumber,
// 		Length:         uint16(len(encodedMessage)),
// 	}

// 	if context.ServerEpoch > 0 {
// 		// Epoch is greater than zero, we should encrypt it.
// 		if context.IsCipherSuiteInitialized {
// 			encryptedMessage, err := context.GCM.Encrypt(header, encodedMessage)
// 			if err != nil {
// 				panic(err)
// 			}
// 			encodedMessage = encryptedMessage
// 			header.Length = uint16(len(encodedMessage))
// 		}
// 	}

// 	encodedHeader := header.Encode()
// 	encodedMessage = append(encodedHeader, encodedMessage...)

// 	logging.Infof(logging.ProtoDTLS, "Sending message (<u>Flight %d</u>)\n%s\n%s\n%s", context.Flight, header, handshakeHeader, message)
// 	logging.LineSpacer(2)

// 	context.Conn.WriteToUDP(encodedMessage, context.Addr)
// 	context.IncreaseServerSequence()
// }

  Future<void> sendMessage(HandshakeContext context, dynamic message) async {
    print("sending message...");
    final Uint8List encodedMessageBody = message.toBytes();
    final encodedMessage = BytesBuilder();
    HandshakeHeader? handshakeHeader;

    //print("Content type: ${message.getContentType()}");
    print("");
    switch (message.getContentType()) {
      case ContentType.Handshake:
        // final handshakeMessage = message;
        // handshakeHeader = HandshakeHeader(
        //   handshakeType: handshakeMessage.getHandshakeType(),
        //   length: Uint24.fromUInt32(encodedMessageBody.length),
        //   messageSequence: context.serverHandshakeSequenceNumber,
        //   fragmentOffset: Uint24.fromUInt32(0),
        //   fragmentLength: Uint24.fromUInt32(encodedMessageBody.length),
        // );

        // print("Handshake header: ${handshakeHeader}");
        // print("encoded Message Body: ${encodedMessageBody.length}");
        // context.increaseServerHandshakeSequence();

        // final encodedHandshakeHeader = BytesBuilder();
        // encodedHandshakeHeader.add(handshakeHeader.encode());
        // encodedHandshakeHeader.add(encodedMessageBody);
        // encodedMessage.add(encodedHandshakeHeader.toBytes());

        // //     encodedHandshakeHeader := handshakeHeader.Encode()
        // // encodedMessage = append(encodedMessage, encodedHandshakeHeader...)
        // // encodedMessage = append(encodedMessage, encodedMessageBody...)

        // var (hh, dOffset, err) = HandshakeHeader.decode(
        //     encodedMessage.toBytes(), 0, encodedMessage.toBytes().length);

        final sequenceNumber = Uint8List(6);
        print("server sequence number: ${context.serverSequenceNumber}");
        sequenceNumber[sequenceNumber.length - 1] +=
            context.serverSequenceNumber;

        // final recordHeader = RecordHeader(
        //   contentType: message.getContentType(),
        //   version: DtlsVersion.v1_2,
        //   versionBytes: context.protocolVersion,
        //   epoch: context.serverEpoch,
        //   sequenceNumber: sequenceNumber,
        //   intSequenceNumber: 0,
        //   length: encodedMessage.toBytes().length,
        // );

        // final encodedRecordHeader = BytesBuilder();
        // encodedRecordHeader.add(recordHeader.encode());
        // encodedRecordHeader.add(encodedMessage.toBytes());

        // //print("Decoded message: $header");

        // final decodedMessage = await decodeDtlsMessage(
        //     context,
        //     encodedRecordHeader.toBytes(),
        //     0,
        //     encodedRecordHeader.toBytes().length);
        // print("Decoded message: $decodedMessage");

        //print("Handshake header: $hh");

        // final decodedMessage = await decodeDtlsMessage(context,
        //     encodedMessage.toBytes(), 0, encodedMessage.toBytes().length);
        // print("Decoded message: $decodedMessage");

        // context.handshakeMessagesSent[handshakeMessage.getHandshakeType()] =
        //     encodedMessage.toBytes();

        // Uint8List toBytes() {
        final buffer = BytesBuilder();

        //return buffer.toBytes();
        //}

        // Example cookie
        final cookie = generateDtlsCookie();

        // Create HelloVerifyRequest message
        final helloVerifyRequest =
            HelloVerifyRequest(Uint8List.fromList(cookie));

        // Convert HelloVerifyRequest to bytes
        final handshakeMessage = helloVerifyRequest.toBytes();

        // Create DTLS record with HelloVerifyRequest
        final dtlsRecord =
            DTLSRecord(handshakeMessage, context.serverSequenceNumber);

        buffer.addByte(dtlsRecord.contentType);
        buffer.addByte(dtlsRecord.version >> 8);
        buffer.addByte(dtlsRecord.version & 0xFF);

        //buffer.add(context.protocolVersion);
        buffer.addByte(dtlsRecord.epoch >> 8);
        buffer.addByte(dtlsRecord.epoch & 0xFF);
        buffer.add(sequenceNumber); // 6 bytes for sequence number
        buffer.addByte(handshakeMessage.length >> 8);
        buffer.addByte(handshakeMessage.length & 0xFF);
        buffer.add(handshakeMessage);

        // Convert DTLS record to bytes
        final dtlsMessage = buffer.toBytes();

        // Print the DTLS message bytes
        // print('DTLS message: ${dtlsMessage}');

        var (msg) = await decodeDtlsMessage(
            context, dtlsMessage, 0, dtlsMessage.length);
        print("dtls message: $msg");

        context.conn.send(dtlsMessage, context.addr, context.port);

        context.increaseServerSequence();
        break;
      case ContentType.ChangeCipherSpec:
        encodedMessage.add(encodedMessageBody);
        break;

      default:
        {
          print("Unhandle content type:${message.getContentType()}");
        }
    }

    final sequenceNumber = Uint8List(6);
    sequenceNumber[sequenceNumber.length - 1] += context.serverSequenceNumber;
    final recordHeader = RecordHeader(
      contentType: message.getContentType(),
      version: DtlsVersion.v1_2,
      versionBytes: Uint8List.fromList([0xfe, 0xff]),
      epoch: context.serverEpoch,
      sequenceNumber: sequenceNumber,
      intSequenceNumber: 0,
      length: encodedMessage.toBytes().length,
    );

    if (context.serverEpoch > 0) {
      // Epoch is greater than zero, we should encrypt it.
      if (context.isCipherSuiteInitialized) {
        final encryptedMessage =
            await context.gcm!.encrypt(recordHeader, encodedMessage.toBytes());
        encodedMessage.clear();
        encodedMessage.add(encryptedMessage);
        recordHeader.length = encodedMessage.length;
      }
    }

    // final encodedHeader = recordHeader.encode();
    // //encodedMessage.add(encodedHeader);
    // var (rh, dOffset, err) =
    //     RecordHeader.decode(encodedHeader, 0, encodedHeader.length);

    // print("Record header: $rh");

    // final encodedRecordHeader = BytesBuilder();
    // encodedRecordHeader.add(encodedHeader);
    // encodedRecordHeader.add(encodedMessage.toBytes());

    // //print("Decoded message: $header");

    // final decodedMessage = await decodeDtlsMessage(context,
    //     encodedRecordHeader.toBytes(), 0, encodedRecordHeader.toBytes().length);
    // print("Decoded message: $decodedMessage");

    //processIncomingMessage(context, encodedMessage.toBytes());
    // context.conn.send(encodedMessage.toBytes(), context.addr, context.port);
    // context.increaseServerSequence();
  }
}
