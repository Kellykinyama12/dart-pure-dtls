import 'dart:typed_data';
import 'dart:math' as dmath;
import 'package:pointycastle/export.dart';

const int randomBytesLength = 28;

class Random {
  DateTime gmtUnixTime;
  Uint8List randomBytes;

  Random(this.gmtUnixTime, this.randomBytes);

  Uint8List encode() {
    final result = Uint8List(4 + randomBytesLength);
    final byteData = ByteData.sublistView(result);
    byteData.setUint32(
        0, gmtUnixTime.millisecondsSinceEpoch ~/ 1000, Endian.big);
    result.setRange(4, 4 + randomBytesLength, randomBytes);
    return result;
  }

  void generate() {
    gmtUnixTime = DateTime.now().toUtc();
    randomBytes = Uint8List(randomBytesLength);
    final random = dmath.Random.secure();
    for (int i = 0; i < randomBytesLength; i++) {
      randomBytes[i] = random.nextInt(256);
    }
  }

  static Random decode(Uint8List buf, int offset, int arrayLen) {
    final gmtUnixTime = DateTime.fromMillisecondsSinceEpoch(
      ByteData.sublistView(buf, offset, offset + 4).getUint32(0, Endian.big) *
          1000,
      isUtc: true,
    );
    offset += 4;
    final randomBytes =
        Uint8List.fromList(buf.sublist(offset, offset + randomBytesLength));
    offset += randomBytesLength;
    return Random(gmtUnixTime, randomBytes);
  }
}
