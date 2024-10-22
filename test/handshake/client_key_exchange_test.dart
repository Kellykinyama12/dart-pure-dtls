import 'dart:ffi';
import 'dart:typed_data';

import 'package:dart_dtls_final/client_key_exchange.dart';

//dart .\test\handshake\client_key_exchange_test.dart

void main() {
  final raw_client_key_exchange = Uint8List.fromList([
    0x20,
    0x26,
    0x78,
    0x4a,
    0x78,
    0x70,
    0xc1,
    0xf9,
    0x71,
    0xea,
    0x50,
    0x4a,
    0xb5,
    0xbb,
    0x00,
    0x76,
    0x02,
    0x05,
    0xda,
    0xf7,
    0xd0,
    0x3f,
    0xe3,
    0xf7,
    0x4e,
    0x8a,
    0x14,
    0x6f,
    0xb7,
    0xe0,
    0xc0,
    0xff,
    0x54,
  ]);

  ClientKeyExchange clientKeyExchange = ClientKeyExchange();
  clientKeyExchange.decode(
      raw_client_key_exchange, 0, raw_client_key_exchange.length);

  print("Client key exchange public key: ${clientKeyExchange.publicKey}");
  print("Expected public key: ${raw_client_key_exchange.sublist(1)}");
}
