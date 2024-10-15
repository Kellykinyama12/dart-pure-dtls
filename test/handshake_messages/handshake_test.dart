import 'dart:typed_data';
import 'dart:io';
import 'package:buffer/buffer.dart';

class ProtocolVersion {
  final int major;
  final int minor;

  ProtocolVersion(this.major, this.minor);
}

class HandshakeRandom {
  DateTime gmtUnixTime;
  Uint8List randomBytes;

  HandshakeRandom({
    required this.gmtUnixTime,
    required this.randomBytes,
  });

  factory HandshakeRandom.defaultInstance() {
    return HandshakeRandom(
      gmtUnixTime: DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      randomBytes: Uint8List(28),
    );
  }

  int get size => 4 + randomBytes.length;

  void marshal(ByteDataWriter writer) {
    final secs = gmtUnixTime.millisecondsSinceEpoch ~/ 1000;
    writer.writeUint32(secs);
    writer.write(randomBytes);
  }

  static HandshakeRandom unmarshal(ByteDataReader reader) {
    final secs = reader.readUint32();
    final gmtUnixTime = DateTime.fromMillisecondsSinceEpoch(secs * 1000, isUtc: true);
    final randomBytes = reader.read(28);

    return HandshakeRandom(
      gmtUnixTime: gmtUnixTime,
      randomBytes: randomBytes,
    );
  }

  void populate() {
    gmtUnixTime = DateTime.now().toUtc();
    final rng = Random.secure();
    for (int i = 0; i < randomBytes.length; i++) {
      randomBytes[i] = rng.nextInt(256);
    }
  }
}

class CompressionMethods {
  final List<int> ids;

  CompressionMethods({required this.ids});
}

class HandshakeMessageClientHello {
  final ProtocolVersion version;
  final HandshakeRandom random;
  final List<int> cookie;
  final List<int> cipherSuites;
  final CompressionMethods compressionMethods;
  final List<int> extensions;

  HandshakeMessageClientHello({
    required this.version,
    required this.random,
    required this.cookie,
    required this.cipherSuites,
    required this.compressionMethods,
    required this.extensions,
  });
}

class HandshakeHeader {
  final HandshakeType handshakeType;
  final int length;
  final int messageSequence;
  final int fragmentOffset;
  final int fragmentLength;

  HandshakeHeader({
    required this.handshakeType,
    required this.length,
    required this.messageSequence,
    required this.fragmentOffset,
    required this.fragmentLength,
  });
}

enum HandshakeType {
  clientHello,
}

class Handshake {
  final HandshakeHeader handshakeHeader;
  final HandshakeMessageClientHello handshakeMessage;

  Handshake({
    required this.handshakeHeader,
    required this.handshakeMessage,
  });

  void marshal(ByteDataWriter writer) {
    writer.writeUint8(handshakeHeader.handshakeType.index);
    writer.writeUint24(handshakeHeader.length);
    writer.writeUint16(handshakeHeader.messageSequence);
    writer.writeUint24(handshakeHeader.fragmentOffset);
    writer.writeUint24(handshakeHeader.fragmentLength);

    handshakeMessage.version.marshal(writer);
    handshakeMessage.random.marshal(writer);
    writer.writeUint8(handshakeMessage.cookie.length);
    writer.write(handshakeMessage.cookie);
    writer.writeUint16(handshakeMessage.cipherSuites.length);
    writer.write(handshakeMessage.cipherSuites);
    writer.writeUint8(handshakeMessage.compressionMethods.ids.length);
    writer.write(handshakeMessage.compressionMethods.ids);
    writer.writeUint16(handshakeMessage.extensions.length);
    writer.write(handshakeMessage.extensions);
  }

  static Handshake unmarshal(ByteDataReader reader) {
    final handshakeType = HandshakeType.values[reader.readUint8()];
    final length = reader.readUint24();
    final messageSequence = reader.readUint16();
    final fragmentOffset = reader.readUint24();
    final fragmentLength = reader.readUint24();

    final version = ProtocolVersion(reader.readUint8(), reader.readUint8());
    final random = HandshakeRandom.unmarshal(reader);
    final cookieLength = reader.readUint8();
    final cookie = reader.read(cookieLength);
    final cipherSuitesLength = reader.readUint16();
    final cipherSuites = reader.read(cipherSuitesLength);
    final compressionMethodsLength = reader.readUint8();
    final compressionMethods = CompressionMethods(ids: reader.read(compressionMethodsLength));
    final extensionsLength = reader.readUint16();
    final extensions = reader.read(extensionsLength);

    return Handshake(
      handshakeHeader: HandshakeHeader(
        handshakeType: handshakeType,
        length: length,
        messageSequence: messageSequence,
        fragmentOffset: fragmentOffset,
        fragmentLength: fragmentLength,
      ),
      handshakeMessage: HandshakeMessageClientHello(
        version: version,
        random: random,
        cookie: cookie,
        cipherSuites: cipherSuites,
        compressionMethods: compressionMethods,
        extensions: extensions,
      ),
    );
  }
}

extension ByteDataWriterExtension on ByteDataWriter {
  void writeUint24(int value) {
    writeUint8((value >> 16) & 0xFF);
    writeUint8((value >> 8) & 0xFF);
    writeUint8(value & 0xFF);
  }
}

extension ByteDataReaderExtension on ByteDataReader {
  int readUint24() {
    final byte1 = readUint8();
    final byte2 = readUint8();
    final byte3 = readUint8();
    return (byte1 << 16) | (byte2 << 8) | byte3;
  }
}
