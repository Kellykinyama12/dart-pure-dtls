import 'dart:typed_data';

import 'package:dart_dtls_final/hello_verify_request.dart';

//test\handshake\hello_verify_request_test.dart

void test_handshake_message_hello_verify_request() {
  final raw_hello_verify_request = Uint8List.fromList([
    0xfe,
    0xff,
    0x14,
    0x25,
    0xfb,
    0xee,
    0xb3,
    0x7c,
    0x95,
    0xcf,
    0x00,
    0xeb,
    0xad,
    0xe2,
    0xef,
    0xc7,
    0xfd,
    0xbb,
    0xed,
    0xf7,
    0x1f,
    0x6c,
    0xcd,
  ]);

  HelloVerifyRequest hvr = HelloVerifyRequest();
  hvr.decode(raw_hello_verify_request, 0, raw_hello_verify_request.length);
  print("Hello verify request: ${hvr}");
}

void main() {
  test_handshake_message_hello_verify_request();
}
