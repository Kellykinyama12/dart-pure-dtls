import 'dart:io';
import 'dart:typed_data';

import 'package:dart_dtls_final/dtls_message.dart';
import 'package:dart_dtls_final/handshake_context.dart';
import 'package:dart_dtls_final/handshake_manager2.dart';

void main() async {
  // Bind the socket to any available address and port
  final socket =
      await RawDatagramSocket.bind(InternetAddress("127.0.0.1"), 4444);

  HandshakeManager handshakeManager = HandshakeManager();
  HandshakeContext? context;
  print(
      'Datagram socket ready to send and receive data on ${socket.address.address}:${socket.port}');

  // Listen for events
  socket.listen((RawSocketEvent event) {
    switch (event) {
      case RawSocketEvent.read:
        Datagram? datagram = socket.receive();
        if (datagram != null) {
          print(
              'Received ${datagram.data.length} bytes from ${datagram.address.address}:${datagram.port}');
          if (context == null) {
            context = HandshakeContext(
                conn: socket, addr: datagram.address, port: datagram.port);

            handshakeManager.processIncomingMessage(context!, datagram.data);
          } else {
            handshakeManager.processIncomingMessage(context!, datagram.data);
          }
        }
        break;
      case RawSocketEvent.write:
        // Handle write events
        break;
      case RawSocketEvent.closed:
        print('Socket closed');
        break;
      default:
        print('Unexpected event: $event');
    }
  });

  // Send a datagram
  //var data = Uint8List.fromList('Hello, world!'.codeUnits);
  //socket.send(data, InternetAddress.loopbackIPv4, 12345);
}
