import 'dart:typed_data';

import 'package:dart_dtls_final/client_hello.dart';
import 'package:dart_dtls_final/record_header.dart';

void main() {
  Uint8List raw_client_hello = Uint8List.fromList([
    0xfe,
    0xfd,
    0xb6,
    0x2f,
    0xce,
    0x5c,
    0x42,
    0x54,
    0xff,
    0x86,
    0xe1,
    0x24,
    0x41,
    0x91,
    0x42,
    0x62,
    0x15,
    0xad,
    0x16,
    0xc9,
    0x15,
    0x8d,
    0x95,
    0x71,
    0x8a,
    0xbb,
    0x22,
    0xd7,
    0x47,
    0xec,
    0xd8,
    0x3d,
    0xdc,
    0x4b,
    0x00,
    0x14,
    0xe6,
    0x14,
    0x3a,
    0x1b,
    0x04,
    0xea,
    0x9e,
    0x7a,
    0x14,
    0xd6,
    0x6c,
    0x57,
    0xd0,
    0x0e,
    0x32,
    0x85,
    0x76,
    0x18,
    0xde,
    0xd8,
    0x00,
    0x04,
    0xc0,
    0x2b,
    0xc0,
    0x0a,
    0x01,
    0x00,
    0x00,
    0x08,
    0x00,
    0x0a,
    0x00,
    0x04,
    0x00,
    0x02,
    0x00,
    0x1d,
  ]);

  ClientHello clientHello = ClientHello();

  // var (recordHeader, offset, arrayLen) =
  //     RecordHeader.decode(raw_client_hello, 0, raw_client_hello.length);

  clientHello.decode(raw_client_hello, 0, raw_client_hello.length);

  print("Decoded client hello: $clientHello");
}
