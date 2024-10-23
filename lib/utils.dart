import 'dart:typed_data';

typedef SRTPProtectionProfile = int;

typedef PointFormat = int;

typedef Curve = int;

class Uint24 {
  final int value;

  Uint24(this.value);

  factory Uint24.fromBytes(Uint8List bytes) {
    return Uint24((bytes[0] << 16) | (bytes[1] << 8) | bytes[2]);
  }

  factory Uint24.fromUInt32(int value) {
    return Uint24(value & 0xFFFFFF);
  }

  int toUint32() {
    return value;
  }

  Uint8List toBytes() {
    return Uint8List(3)
      ..[0] = (value >> 16) & 0xFF
      ..[1] = (value >> 8) & 0xFF
      ..[2] = value & 0xFF;
  }
}

Uint8List intToUint8List(int value) {
  var byteData = ByteData(8);
  byteData.setUint64(0, value, Endian.big);
  return byteData.buffer.asUint8List();
}

Uint8List uint16ToUint8List(int value) {
  var byteData = ByteData(2);
  byteData.setUint16(0, value, Endian.big);
  return byteData.buffer.asUint8List();
}

int uint16(Uint8List b) {
  // https://stackoverflow.com/questions/45000982/convert-3-bytes-to-int-in-go
  //return (b[2]) | (b[1]) << 8 | (b[0]) << 16;

  if (b.length != 2) {
    throw ArgumentError("Incorrect length");
  }
  var data = b.sublist(0);
  var buffer = data.buffer;
  var bytes = ByteData.view(buffer);
  return bytes.getUint16(0);
}

Uint8List uint32toUint8List(int b) {
  // Create a ByteData buffer with 2 bytes (16 bits)
  ByteData byteData = ByteData(4);

  // Set the uint16 value at offset 0
  byteData.setUint32(0, b, Endian.big);

  // Convert ByteData to Uint8List
  Uint8List uint8List = byteData.buffer.asUint8List();

  return uint8List; // Output: [52, 18]
}

int uint32(Uint8List b) {
  // https://stackoverflow.com/questions/45000982/convert-3-bytes-to-int-in-go
  //return (b[2]) | (b[1]) << 8 | (b[0]) << 16;

  if (b.length != 4) {
    throw ArgumentError("Incorrect length");
  }
  var data = b.sublist(0);
  var buffer = data.buffer;
  var bytes = ByteData.view(buffer);
  return bytes.getUint32(0);
}
