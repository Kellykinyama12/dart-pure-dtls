import 'dart:typed_data';
import 'package:buffer/buffer.dart';

const int RECORD_LAYER_HEADER_SIZE = 13;
const int MAX_SEQUENCE_NUMBER = 0x0000FFFFFFFFFFFF;

const int DTLS1_2MAJOR = 0xfe;
const int DTLS1_2MINOR = 0xfd;

const int DTLS1_0MAJOR = 0xfe;
const int DTLS1_0MINOR = 0xff;

const int VERSION_DTLS12 = 0xfefd;

const ProtocolVersion PROTOCOL_VERSION1_0 =
    ProtocolVersion(major: DTLS1_0MAJOR, minor: DTLS1_0MINOR);
const ProtocolVersion PROTOCOL_VERSION1_2 =
    ProtocolVersion(major: DTLS1_2MAJOR, minor: DTLS1_2MINOR);

class ProtocolVersion {
  final int major;
  final int minor;

  const ProtocolVersion({required this.major, required this.minor});
}

class RecordLayerHeader {
  final int contentType;
  final ProtocolVersion protocolVersion;
  final int epoch;
  final int sequenceNumber; // uint48 in spec
  final int contentLen;

  RecordLayerHeader({
    required this.contentType,
    required this.protocolVersion,
    required this.epoch,
    required this.sequenceNumber,
    required this.contentLen,
  });

  void marshal(ByteDataWriter writer) {
    if (sequenceNumber > MAX_SEQUENCE_NUMBER) {
      throw Exception('Sequence number overflow');
    }

    writer.writeUint8(contentType);
    writer.writeUint8(protocolVersion.major);
    writer.writeUint8(protocolVersion.minor);
    writer.writeUint16(epoch, Endian.big);

    var be = Uint8List(8);
    ByteData.view(be.buffer).setUint64(0, sequenceNumber, Endian.big);
    writer.write(be.sublist(2)); // uint48 in spec

    writer.writeUint16(contentLen, Endian.big);
  }

  static RecordLayerHeader unmarshal(ByteDataReader reader) {
    final contentType = reader.readUint8();
    final major = reader.readUint8();
    final minor = reader.readUint8();
    final epoch = reader.readUint16(Endian.big);

    var be = Uint8List(8);
    reader.read(be, 2, 6);
    final sequenceNumber = ByteData.view(be.buffer).getUint64(0, Endian.big);

    final protocolVersion = ProtocolVersion(major: major, minor: minor);
    if (protocolVersion != PROTOCOL_VERSION1_0 &&
        protocolVersion != PROTOCOL_VERSION1_2) {
      throw Exception('Unsupported protocol version');
    }
    final contentLen = reader.readUint16(Endian.big);

    return RecordLayerHeader(
      contentType: contentType,
      protocolVersion: protocolVersion,
      epoch: epoch,
      sequenceNumber: sequenceNumber,
      contentLen: contentLen,
    );
  }
}
