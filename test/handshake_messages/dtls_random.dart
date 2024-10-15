import 'dart:typed_data';
import 'dart:math';
import 'package:buffer/buffer.dart';

const int RANDOM_BYTES_LENGTH = 28;
const int HANDSHAKE_RANDOM_LENGTH = RANDOM_BYTES_LENGTH + 4;

class HandshakeRandom {
  DateTime gmtUnixTime;
  Uint8List randomBytes;

  HandshakeRandom({
    required this.gmtUnixTime,
    required this.randomBytes,
  });

  factory HandshakeRandom.defaultInstance() {
    return HandshakeRandom(
      gmtUnixTime: DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      randomBytes: Uint8List(RANDOM_BYTES_LENGTH),
    );
  }

  int get size => 4 + RANDOM_BYTES_LENGTH;

  void marshal(ByteDataWriter writer) {
    final secs = gmtUnixTime.millisecondsSinceEpoch ~/ 1000;
    writer.writeUint32(secs);
    writer.write(randomBytes);
  }

  static HandshakeRandom unmarshal(ByteDataReader reader) {
    final secs = reader.readUint32();
    final gmtUnixTime =
        DateTime.fromMillisecondsSinceEpoch(secs * 1000, isUtc: true);

    final randomBytes = reader.read(RANDOM_BYTES_LENGTH);

    return HandshakeRandom(
      gmtUnixTime: gmtUnixTime,
      randomBytes: randomBytes,
    );
  }

  void populate() {
    gmtUnixTime = DateTime.now().toUtc();
    final rng = Random.secure();
    for (int i = 0; i < RANDOM_BYTES_LENGTH; i++) {
      randomBytes[i] = rng.nextInt(256);
    }
  }
}
