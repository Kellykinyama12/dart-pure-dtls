import 'dart:typed_data';

enum HandshakeType {
  HelloRequest,
  ClientHello,
  ServerHello,
  HelloVerifyRequest,
  Certificate,
  ServerKeyExchange,
  CertificateRequest,
  ServerHelloDone,
  CertificateVerify,
  ClientKeyExchange,
  Finished,
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

class Uint24 {
  final int value;

  Uint24(this.value);

  factory Uint24.fromBytes(Uint8List bytes) {
    return Uint24((bytes[0] << 16) | (bytes[1] << 8) | bytes[2]);
  }

  Uint8List toBytes() {
    return Uint8List(3)
      ..[0] = (value >> 16) & 0xFF
      ..[1] = (value >> 8) & 0xFF
      ..[2] = value & 0xFF;
  }

  int intVal() {
    return value;
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
    final result = Uint8List(12);
    result[0] = handshakeType.index;
    result.setRange(1, 4, length.toBytes());
    ByteData.sublistView(result).setUint16(4, messageSequence, Endian.big);
    result.setRange(6, 9, fragmentOffset.toBytes());
    result.setRange(9, 12, fragmentLength.toBytes());
    return result;
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

    print("""{handshakeType: $handshakeType,
        length: ${length.value},
        messageSequence: $messageSequence,
        fragmentOffset: ${fragmentOffset.value},
        fragmentLength: ${fragmentLength.value},}""");
    return (
      HandshakeHeader(
          handshakeType: handshakeType,
          length: length,
          messageSequence: messageSequence,
          fragmentOffset: fragmentOffset,
          fragmentLength: fragmentLength,
          intFragmented: fragmentLength.intVal()),
      offset,
      null
    );
  }
}
