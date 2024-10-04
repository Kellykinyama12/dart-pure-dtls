import 'dart:typed_data';

enum ContentType {
  ChangeCipherSpec,
  Alert,
  Handshake,
  ApplicationData,
}

extension ContentTypeExtension on ContentType {
  String get name {
    switch (this) {
      case ContentType.ChangeCipherSpec:
        return 'ChangeCipherSpec';
      case ContentType.Alert:
        return 'Alert';
      case ContentType.Handshake:
        return 'Handshake';
      case ContentType.ApplicationData:
        return 'ApplicationData';
      default:
        return 'Unknown Content Type';
    }
  }

  String contentTypeToString() {
    return '$name (${this.index + 20})';
  }
}

enum DtlsVersion {
  v1_0,
  v1_2,
}

extension DtlsVersionExtension on DtlsVersion {
  String get name {
    switch (this) {
      case DtlsVersion.v1_0:
        return '1.0';
      case DtlsVersion.v1_2:
        return '1.2';
      default:
        return 'Unknown Version';
    }
  }

  int get value {
    switch (this) {
      case DtlsVersion.v1_0:
        return 0xfeff;
      case DtlsVersion.v1_2:
        return 0xfefd;
      default:
        return 0;
    }
  }

  String dtlsVersionToString() {
    return '$name (0x${value.toRadixString(16)})';
  }
}

class RecordHeader {
  static const int sequenceNumberSize = 6;

  ContentType contentType;
  DtlsVersion version;
  int epoch;
  Uint8List sequenceNumber;
  int length;

  RecordHeader({
    required this.contentType,
    required this.version,
    required this.epoch,
    required this.sequenceNumber,
    required this.length,
  });

  @override
  String toString() {
    final seqNum =
        ByteData.sublistView(Uint8List(8)..setRange(2, 8, sequenceNumber))
            .getUint64(0, Endian.big);
    return '[Record Header] Content Type: ${contentType.toString()}, Ver: ${version.toString()}, Epoch: $epoch, SeqNum: $seqNum';
  }

  Uint8List encode() {
    final result = Uint8List(7 + sequenceNumberSize);
    final byteData = ByteData.sublistView(result);
    result[0] = contentType.index + 20;
    byteData.setUint16(1, version.value, Endian.big);
    byteData.setUint16(3, epoch, Endian.big);
    result.setRange(5, 5 + sequenceNumberSize, sequenceNumber);
    byteData.setUint16(5 + sequenceNumberSize, length, Endian.big);
    return result;
  }

  static (RecordHeader, int, bool?) decode(
      Uint8List buf, int offset, int arrayLen) {
    final contentType = ContentType.values[buf[offset] - 20];
    offset++;
    final version = DtlsVersion.values.firstWhere((v) =>
        v.value ==
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big));
    offset += 2;
    final epoch =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    final sequenceNumber =
        Uint8List.fromList(buf.sublist(offset, offset + sequenceNumberSize));
    offset += sequenceNumberSize;
    final length =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    print("""{contentType: $contentType,
      version: $version,
      epoch: $epoch,
      sequenceNumber: $sequenceNumber,
      length: $length}""");
    return (
      RecordHeader(
        contentType: contentType,
        version: version,
        epoch: epoch,
        sequenceNumber: sequenceNumber,
        length: length,
      ),
      offset,
      null
    );
  }
}
