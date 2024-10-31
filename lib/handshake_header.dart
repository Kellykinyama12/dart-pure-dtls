import 'dart:typed_data';

import 'utils.dart';

// enum HandshakeType {
//   HelloRequest,
//   ClientHello,
//   ServerHello,
//   HelloVerifyRequest,
//   Certificate,
//   ServerKeyExchange,
//   CertificateRequest,
//   ServerHelloDone,
//   CertificateVerify,
//   ClientKeyExchange,
//   Finished,
// }

enum HandshakeType {
  // https://github.com/eclipse/tinydtls/blob/706888256c3e03d9fcf1ec37bb1dd6499213be3c/dtls.h#L344
  HelloRequest(0),
  ClientHello(1),
  ServerHello(2),
  HelloVerifyRequest(3),
  Certificate(11),
  ServerKeyExchange(12),
  CertificateRequest(13),
  ServerHelloDone(14),
  CertificateVerify(15),
  ClientKeyExchange(16),
  Finished(20);

  const HandshakeType(this.value);

  final int value;

  factory HandshakeType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

extension HandshakeTypeExtension on HandshakeType {
  String get name {
    switch (this) {
      case HandshakeType.HelloRequest:
        return 'HelloRequest';
      case HandshakeType.ClientHello:
        return 'ClientHello';
      case HandshakeType.ServerHello:
        return 'ServerHello';
      case HandshakeType.HelloVerifyRequest:
        return 'VerifyRequest';
      case HandshakeType.Certificate:
        return 'Certificate';
      case HandshakeType.ServerKeyExchange:
        return 'ServerKeyExchange';
      case HandshakeType.CertificateRequest:
        return 'CertificateRequest';
      case HandshakeType.ServerHelloDone:
        return 'ServerHelloDone';
      case HandshakeType.CertificateVerify:
        return 'CertificateVerify';
      case HandshakeType.ClientKeyExchange:
        return 'ClientKeyExchange';
      case HandshakeType.Finished:
        return 'Finished';
      default:
        return 'Unknown type';
    }
  }

  @override
  String handshakeTypeToString() {
    return '$name (${this.index})';
  }
}

class HandshakeHeader {
  HandshakeType handshakeType;
  Uint24 length;
  int messageSequence;
  Uint24 fragmentOffset;
  Uint24 fragmentLength;
  int? intFragmented;

  HandshakeHeader(
      {required this.handshakeType,
      required this.length,
      required this.messageSequence,
      required this.fragmentOffset,
      required this.fragmentLength,
      this.intFragmented});

  @override
  String toString() {
    return '[Handshake Header] Handshake Type: ${handshakeType.toString()}, Message Seq: $messageSequence';
  }

  Uint8List encode() {
    final buffer = BytesBuilder();

    // Encode handshake type
    buffer.addByte(handshakeType.index);

    // Encode length
    buffer.add(length.toBytes());

    // Encode message sequence
    final messageSequenceBytes = ByteData(2);
    messageSequenceBytes.setUint16(0, messageSequence, Endian.big);
    buffer.add(messageSequenceBytes.buffer.asUint8List());

    // Encode fragment offset
    buffer.add(fragmentOffset.toBytes());

    // Encode fragment length
    buffer.add(fragmentLength.toBytes());

    return buffer.toBytes();
  }

  static (HandshakeHeader, int, bool?) decode(
      Uint8List buf, int offset, int arrayLen) {
    final handshakeType = HandshakeType.values[buf[offset]];
    offset++;
    final length = Uint24.fromBytes(buf.sublist(offset, offset + 3));
    offset += 3;
    final messageSequence =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    final fragmentOffset = Uint24.fromBytes(buf.sublist(offset, offset + 3));
    offset += 3;
    final fragmentLength = Uint24.fromBytes(buf.sublist(offset, offset + 3));
    offset += 3;

    // print("""{handshakeType: $handshakeType,
    //     length: ${length.value},
    //     messageSequence: $messageSequence,
    //     fragmentOffset: ${fragmentOffset.value},
    //     fragmentLength: ${fragmentLength.value},}""");
    return (
      HandshakeHeader(
          handshakeType: handshakeType,
          length: length,
          messageSequence: messageSequence,
          fragmentOffset: fragmentOffset,
          fragmentLength: fragmentLength,
          intFragmented: fragmentLength.toUint32()),
      offset,
      null
    );
  }
}
