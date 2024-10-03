import 'dart:typed_data';
import 'dart:math' as dmath;
import 'dart:io';
import 'package:dart_dtls_final/certificate.dart';
import 'package:dart_dtls_final/certificate_verify.dart';
import 'package:dart_dtls_final/client_hello.dart';
import 'package:dart_dtls_final/client_key_exchange.dart';
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
  HandshakeManager();

  HandshakeContext newContext(InternetAddress addr, RawDatagramSocket conn,
      String clientUfrag, String expectedFingerprintHash) {
    return HandshakeContext();
  }

  Future<void> processIncomingMessage(
      HandshakeContext context, dynamic incomingMessage) async {
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
            sendMessage(context, helloVerifyRequestResponse);
            return;
          case Flight.Flight2:
            if (message.cookie.isEmpty) {
              context.flight = Flight.Flight0;
              return;
            }

            // Create a ListEquality object
            final listEquality = ListEquality();
            if (!listEquality.equals(context.cookie, message.cookie)) {
              return setStateFailed(context, 'client hello cookie is invalid');
            }
            final negotiatedCipherSuite =
                negotiateOnCipherSuiteIDs(message.cipherSuiteIDs);
            context.cipherSuite = negotiatedCipherSuite;
            for (final extensionItem in message.extensions.values) {
              switch (extensionItem.runtimeType) {
                case ExtSupportedEllipticCurves:
                  final msgExtension =
                      extensionItem as ExtSupportedEllipticCurves;
                  final negotiatedCurve =
                      negotiateOnCurves(msgExtension.curves);
                  context.curve = negotiatedCurve;
                  break;
                case ExtUseSRTP:
                  final msgExtension = extensionItem as ExtUseSRTP;
                  final negotiatedProtectionProfile =
                      negotiateOnSRTPProtectionProfiles(
                          msgExtension.protectionProfiles);
                  context.srtpProtectionProfile = negotiatedProtectionProfile;
                  break;
                case ExtUseExtendedMasterSecret:
                  context.useExtendedMasterSecret = true;
                  break;
              }
            }

            context.clientRandom = message.random;
            context.serverRandom = Random();
            context.serverRandom.generate();

            final serverKeyPair = generateCurveKeypair(context.curve);
            context.serverPublicKey = serverKeyPair.publicKey;
            context.serverPrivateKey = serverKeyPair.privateKey;

            final clientRandomBytes = context.clientRandom.encode();
            final serverRandomBytes = context.serverRandom.encode();

            context.serverKeySignature = generateKeySignature(
              clientRandomBytes,
              serverRandomBytes,
              context.serverPublicKey,
              context.curve,
              serverCertificate.privateKey,
              context.cipherSuite.hashAlgorithm,
            );

            context.flight = Flight.Flight4;
            final serverHelloResponse = createDtlsServerHello(context);
            sendMessage(context, serverHelloResponse);
            final certificateResponse = createDtlsCertificate();
            sendMessage(context, certificateResponse);
            final serverKeyExchangeResponse =
                createDtlsServerKeyExchange(context);
            sendMessage(context, serverKeyExchangeResponse);
            final certificateRequestResponse =
                createDtlsCertificateRequest(context);
            sendMessage(context, certificateRequestResponse);
            final serverHelloDoneResponse = createDtlsServerHelloDone(context);
            sendMessage(context, serverHelloDoneResponse);
        }
        break;
      case Certificate:
        final message = incomingMessage as Certificate;
        context.clientCertificates = message.certificates;
        final certificateFingerprintHash =
            getCertificateFingerprintFromBytes(context.clientCertificates[0]);
        if (context.expectedFingerprintHash != certificateFingerprintHash) {
          return setStateFailed(context,
              'incompatible fingerprint hashes from SDP and DTLS data');
        }
        break;
      case CertificateVerify:
        final message = incomingMessage as CertificateVerify;
        if (!(context.cipherSuite!.hashAlgorithm ==
                message.algoPair.hashAlgorithm &&
            context.cipherSuite!.signatureAlgorithm ==
                message.algoPair.signatureAlgorithm)) {
          return setStateFailed(context, 'incompatible signature scheme');
        }
        final handshakeMessages =
            concatHandshakeMessages(context, false, false);
        if (handshakeMessages == null) {
          return setStateFailed(
              context, 'error while concatenating handshake messages');
        }
        final err = verifyCertificate(
            handshakeMessages,
            context.cipherSuite.hashAlgorithm,
            message.signature,
            context.clientCertificates);
        if (err != null) {
          return setStateFailed(context, err);
        }
        break;
      case ClientKeyExchange:
        final message = incomingMessage as ClientKeyExchange;
        context.clientKeyExchangePublic = message.publicKey;
        if (!context.isCipherSuiteInitialized) {
          final err = initCipherSuite(context);
          if (err != null) {
            return setStateFailed(context, err);
          }
        }
        break;
      case Finished:
        final message = incomingMessage as Finished;
        final handshakeMessages = concatHandshakeMessages(context, true, true);
        if (handshakeMessages == null) {
          return setStateFailed(
              context, 'error while concatenating handshake messages');
        }
        final calculatedVerifyData = verifyFinishedData(handshakeMessages,
            context.serverMasterSecret, context.cipherSuite.hashAlgorithm);
        if (calculatedVerifyData == null) {
          return setStateFailed(context, 'error while verifying finished data');
        }
        context.flight = Flight.Flight6;
        final changeCipherSpecResponse = createDtlsChangeCipherSpec(context);
        sendMessage(context, changeCipherSpecResponse);
        context.increaseServerEpoch();
        final finishedResponse =
            createDtlsFinished(context, calculatedVerifyData);
        sendMessage(context, finishedResponse);
        context.setDTLSState(DTLSState.Connected);
        break;
      default:
        break;
    }
  }

  void sendMessage(HandshakeContext context, BaseDtlsMessage message) {
    final encodedMessageBody = message.encode();
    final encodedMessage = BytesBuilder();
    HandshakeHeader? handshakeHeader;
    switch (message.getContentType()) {
      case ContentType.Handshake:
        final handshakeMessage = message as BaseDtlsHandshakeMessage;
        handshakeHeader = HandshakeHeader(
          handshakeType: handshakeMessage.getHandshakeType(),
          length: Uint24.fromUint32(encodedMessageBody.length),
          messageSequence: context.serverHandshakeSequenceNumber,
          fragmentOffset: Uint24.fromUint32(0),
          fragmentLength: Uint24.fromUint32(encodedMessageBody.length),
        );
        context.increaseServerHandshakeSequence();
        encodedMessage.add(handshakeHeader.encode());
        encodedMessage.add(encodedMessageBody);
        context.handshakeMessagesSent[handshakeMessage.getHandshakeType()] =
            encodedMessage.toBytes();
        break;
      case ContentType.ChangeCipherSpec:
        encodedMessage.add(encodedMessageBody);
        break;
    }

    final sequenceNumber = Uint8List(6);
    sequenceNumber[sequenceNumber.length - 1] += context.serverSequenceNumber;
    final header = RecordHeader(
      contentType: message.getContentType(),
      version: DtlsVersion.v1_2,
      epoch: context.serverEpoch,
      sequenceNumber: sequenceNumber,
      length: encodedMessage.length,
    );

    if (context.serverEpoch > 0) {
      // Epoch is greater than zero, we should encrypt it.
      if (context.isCipherSuiteInitialized) {
        final encryptedMessage =
            context.gcm!.encrypt(header, encodedMessage.toBytes());
        encodedMessage.clear();
        encodedMessage.add(encryptedMessage);
        header.length = encodedMessage.length;
      }
    }

    final encodedHeader = header.encode();
    encodedMessage.add(encodedHeader);

    context.conn.send(encodedMessage.toBytes(), context.addr);
    context.increaseServerSequence();
  }

  bool setStateFailed(HandshakeContext context, String error) {
    context.setDTLSState(DTLSState.Failed);
    print('DTLS handshake failed: $error');
    return false;
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

  ServerHello createDtlsServerHello(HandshakeContext context) {
    final extensions = <ExtensionType, Extension>{};
    if (context.useExtendedMasterSecret) {
      extensions[ExtensionType.UseExtendedMasterSecret] =
          ExtUseExtendedMasterSecret();
    }
    extensions[ExtensionType.RenegotiationInfo] = ExtRenegotiationInfo();

    if (context.srtpProtectionProfile != SRTPProtectionProfile.Unknown) {
      final useSRTP = ExtUseSRTP(
        protectionProfiles: [context.srtpProtectionProfile],
      );
      extensions[ExtensionType.UseSRTP] = useSRTP;
    }

    final supportedPointFormats = ExtSupportedPointFormats(
      pointFormats: [PointFormat.Uncompressed],
    );
    extensions[ExtensionType.SupportedPointFormats] = supportedPointFormats;

    return ServerHello(
      version: context.protocolVersion,
      random: context.serverRandom,
      cipherSuiteID: context.cipherSuite.id,
      extensions: extensions,
    );
  }

  Certificate createDtlsCertificate() {
    return Certificate(
      certificates: serverCertificate.certificate,
    );
  }

  // ServerKeyExchange createDtlsServer
}
