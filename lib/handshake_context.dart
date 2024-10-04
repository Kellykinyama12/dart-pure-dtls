import 'dart:io';
import 'dart:typed_data';
import 'dart:math' as dmath;

import 'package:dart_dtls_final/cipher_suites.dart';
import 'package:dart_dtls_final/crypto_gcm.dart';
import 'package:dart_dtls_final/dtls_state.dart';
import 'package:dart_dtls_final/handshake_header.dart';
import 'package:dart_dtls_final/record_header.dart';

class HandshakeContext {
  // Client IP and Port
  InternetAddress addr;
  int port;
  // Server UDP listener connection
  RawDatagramSocket conn;
  late String clientUfrag;
  late String expectedFingerprintHash;
  DTLSState dtlsState = DTLSState.New;
  void Function(DTLSState)? onDTLSStateChangeHandler;

  late Uint8List protocolVersion;
  CipherSuite? cipherSuite;
  late CurveType curveType;
  late Curve curve;
  late SRTPProtectionProfile srtpProtectionProfile;
  late Random clientRandom;
  late Uint8List clientKeyExchangePublic;

  late Random serverRandom;
  late Uint8List serverMasterSecret;
  late Uint8List serverPublicKey;
  late Uint8List serverPrivateKey;
  late Uint8List serverKeySignature;
  late List<Uint8List> clientCertificates;

  late bool isCipherSuiteInitialized;
  GCM? gcm;

  late bool useExtendedMasterSecret;

  Map<HandshakeType, Uint8List> handshakeMessagesReceived = {};
  late Map<HandshakeType, Uint8List> handshakeMessagesSent = {};

  int clientEpoch = 0;
  late int clientSequenceNumber;
  int serverEpoch = 0;
  int serverSequenceNumber = 0;
  int serverHandshakeSequenceNumber = 0;

  late Uint8List cookie;
  Flight flight = Flight.Flight0;

  Uint8List? keyingMaterialCache;

  HandshakeContext(
      {this.onDTLSStateChangeHandler,
      this.cipherSuite,
      this.gcm,
      this.keyingMaterialCache,
      required this.conn,
      required this.addr,
      required this.port});

  void increaseServerEpoch() {
    serverEpoch++;
    serverSequenceNumber = 0;
  }

  void increaseServerSequence() {
    serverSequenceNumber++;
  }

  void increaseServerHandshakeSequence() {
    serverHandshakeSequenceNumber++;
  }

  Future<Uint8List> exportKeyingMaterial(int length) async {
    if (keyingMaterialCache != null) {
      return keyingMaterialCache!;
    }
    final encodedClientRandom = clientRandom.encode();
    final encodedServerRandom = serverRandom.encode();
    print(
        'Exporting keying material from DTLS context (expected length: $length)...');
    keyingMaterialCache = await generateKeyingMaterial(
        serverMasterSecret,
        encodedClientRandom,
        encodedServerRandom,
        cipherSuite!.hashAlgorithm,
        length);
    return keyingMaterialCache!;
  }

  void setDTLSState(DTLSState dtlsState) {
    if (this.dtlsState == dtlsState) {
      return;
    }
    this.dtlsState = dtlsState;
    if (onDTLSStateChangeHandler != null) {
      onDTLSStateChangeHandler!(dtlsState);
    }
  }
}

enum Flight {
  Flight0,
  Flight2,
  Flight4,
  Flight6,
}

Future<Uint8List> generateKeyingMaterial(
    Uint8List serverMasterSecret,
    Uint8List encodedClientRandom,
    Uint8List encodedServerRandom,
    HashAlgorithm hashAlgorithm,
    int length) async {
  // Implement keying material generation logic
  return Uint8List(length);
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
    final random = dmath.Random.secure();
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
