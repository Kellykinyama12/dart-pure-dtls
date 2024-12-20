import 'dart:math';
import 'dart:typed_data';

import 'package:dart_dtls_final/utils.dart';

const RandomBytesLength = 28;

Uint8List generateRandomBytes(int length) {
  final random = Random.secure();
  final bytes = Uint8List(length);
  for (int i = 0; i < length; i++) {
    bytes[i] = random.nextInt(256);
  }
  return bytes;
}

class DtlsRandom {
  int? GMTUnixTime;
  Uint8List RandomBytes = generateRandomBytes(RandomBytesLength);

  Uint8List Encode() {
    final buffer = BytesBuilder();

    // Encode GMT Unix time
    final gmtUnixTimeBytes = ByteData(4);
    gmtUnixTimeBytes.setUint32(
        0,
        GMTUnixTime ?? DateTime.now().millisecondsSinceEpoch ~/ 1000,
        Endian.big);
    buffer.add(gmtUnixTimeBytes.buffer.asUint8List());

    // Encode random bytes
    buffer.add(RandomBytes);

    return buffer.toBytes();
  }

//   func (r *Random) Encode() []byte {
// 	result := make([]byte, 4+RandomBytesLength)

// 	binary.BigEndian.PutUint32(result[0:4], uint32(r.GMTUnixTime.Unix()))
// 	copy(result[4:], r.RandomBytes[:])
// 	return result
// }

  @override
  String toString() {
    return "{ time: $GMTUnixTime, random bytes: $RandomBytes}";
  }
}

dynamic DecodeRandom(Uint8List buf, int offset, int arrayLen)
//(*Random, int, error)
{
  var result = DtlsRandom();
  result.GMTUnixTime = uint32(buf.sublist(offset, offset + 4));
  offset += 4;
  result.RandomBytes = buf.sublist(offset, offset + RandomBytesLength);
  offset += RandomBytesLength;

  return (result, offset, null);
}
