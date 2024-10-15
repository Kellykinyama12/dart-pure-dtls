import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

class HandshakeMessageFinished {
  final List<int> verifyData;

  HandshakeMessageFinished({required this.verifyData});

  static HandshakeMessageFinished unmarshal(Uint8List data) {
    // Implement the unmarshalling logic here
    // This is a placeholder implementation
    return HandshakeMessageFinished(verifyData: data.toList());
  }

  Uint8List marshal() {
    // Implement the marshalling logic here
    // This is a placeholder implementation
    return Uint8List.fromList(verifyData);
  }
}

void testHandshakeMessageFinished() {
  List<int> rawFinished = [
    0x01,
    0x01,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
  ];

  HandshakeMessageFinished parsedFinished = HandshakeMessageFinished(
    verifyData: rawFinished,
  );

  Uint8List raw = Uint8List.fromList(rawFinished);
  HandshakeMessageFinished c = HandshakeMessageFinished.unmarshal(raw);
  assert(c.verifyData.toString() == parsedFinished.verifyData.toString());

  Uint8List marshalled = c.marshal();
  assert(marshalled.toString() == rawFinished.toString());
}

void main() {
  testHandshakeMessageFinished();
}
