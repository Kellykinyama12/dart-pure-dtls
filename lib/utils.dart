import 'dart:typed_data';

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
