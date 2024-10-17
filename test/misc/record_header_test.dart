import 'dart:typed_data';

import 'package:dart_dtls_final/record_header.dart';
import 'package:dart_dtls_final/utils.dart';

//dart .\test\misc\record_header_test.dart

void main() {
  Uint8List ChangeCipherSpecSinglePacket = Uint8List.fromList([
    0x14,
    0xfe,
    0xff,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x12,
    0x00,
    0x01,
    0x01,
  ]);

  var (recordHeader, offset, arrayLen) = RecordHeader.decode(
      ChangeCipherSpecSinglePacket, 0, ChangeCipherSpecSinglePacket.length);

  // RecordHeader {
  //       record_layer_header: RecordLayerHeader {
  //           content_type: ContentType::ChangeCipherSpec,
  //           protocol_version: ProtocolVersion {
  //               major: 0xfe,
  //               minor: 0xff,
  //           },
  //           epoch: 0,
  //           sequence_number: 18,
  //           content_len: 1,
  //       },
  //       content: Content::ChangeCipherSpec(ChangeCipherSpec {}),
  //   },

  final version = DtlsVersion.values.firstWhere((v) =>
      v.value ==
      ByteData.sublistView(Uint8ClampedList.fromList([0xfe, 0xff]), 0, 2)
          .getUint16(0, Endian.big));

  final seqNum = intToUint8List(18);

  final testRecordHeader = RecordHeader(
    contentType: ContentType.ChangeCipherSpec,
    version: version,
    epoch: 0,
    sequenceNumber: seqNum,
    intSequenceNumber: 18,
    length: 1,
  );
  print("Deocode recorder header: $recordHeader");

  print("Wanted recorder header: $testRecordHeader");
}
