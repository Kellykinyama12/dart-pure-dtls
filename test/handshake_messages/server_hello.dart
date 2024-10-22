import 'dart:convert';
import 'dart:typed_data';
import 'package:buffer/buffer.dart';

class ProtocolVersion {
  final int major;
  final int minor;

  ProtocolVersion(this.major, this.minor);
}

class HandshakeRandom {
  final Uint8List randomBytes;

  HandshakeRandom(this.randomBytes);

  void marshal(ByteDataWriter writer) {
    writer.write(randomBytes);
  }

  static HandshakeRandom unmarshal(ByteDataReader reader) {
    final randomBytes = reader.read(32);
    return HandshakeRandom(randomBytes);
  }

class CipherSuiteId {
  final int id;

  CipherSuiteId(this.id);
}

class CompressionMethodId {
  final int id;

  CompressionMethodId(this.id);
}

class Extension {
  final int type;
  final Uint8List data;

  Extension(this.type, this.data);

  void marshal(ByteDataWriter writer) {
    writer.writeUint16(type);
    writer.writeUint16(data.length);
    writer.write(data);
  }

  static Extension unmarshal(ByteDataReader reader) {
    final type = reader.readUint16();
    final length = reader.readUint16();
    final data = reader.read(length);
    return Extension(type, data);
  }
}

class HandshakeMessageServerHello {
  final ProtocolVersion version;
  final HandshakeRandom random;
  final CipherSuiteId cipherSuite;
  final CompressionMethodId compressionMethod;
  final List<Extension> extensions;

  HandshakeMessageServerHello({
    required this.version,
    required this.random,
    required this.cipherSuite,
    required this.compressionMethod,
    required this.extensions,
  });

  HandshakeType get handshakeType => HandshakeType.serverHello;

  int get size {
    int len = 2 + random.randomBytes.length;
    len += 1; // SessionID
    len += 2; // CipherSuite
    len += 1; // CompressionMethod
    len += 2; // Extensions length
    for (var extension in extensions) {
      len += 4 + extension.data.length;
    }
    return len;
  }

  void marshal(ByteDataWriter writer) {
    writer.writeUint8(version.major);
    writer.writeUint8(version.minor);
    random.marshal(writer);
    writer.writeUint8(0x00); // SessionID
    writer.writeUint16(cipherSuite.id);
    writer.writeUint8(compressionMethod.id);

    final extensionBuffer = ByteDataWriter();
    for (var extension in extensions) {
      extension.marshal(extensionBuffer);
    }

    writer.writeUint16(extensionBuffer.toBytes().length);
    writer.write(extensionBuffer.toBytes());
  }

  static HandshakeMessageServerHello unmarshal(ByteDataReader reader) {
    final major = reader.readUint8();
    final minor = reader.readUint8();
    final random = HandshakeRandom.unmarshal(reader);

    final sessionIdLen = reader.readUint8();
    reader.read(sessionIdLen); // SessionID

    final cipherSuite = CipherSuiteId(reader.readUint16());
    final compressionMethod = CompressionMethodId(reader.readUint8());

    final extensionBufferLen = reader.readUint16();
    final extensionBuffer = reader.read(extensionBufferLen);

    final extensions = <Extension>[];
    final extensionReader = ByteDataReader()..add(extensionBuffer);
    while (extensionReader.remainingLength > 0) {
      extensions.add(Extension.unmarshal(extensionReader));
    }

    return HandshakeMessageServerHello(
      version: ProtocolVersion(major, minor),
      random: random,
      cipherSuite: cipherSuite,
      compressionMethod: compressionMethod,
      extensions: extensions,
    );
  }
}

enum HandshakeType {
  serverHello,
}
