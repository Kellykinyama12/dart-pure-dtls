import 'package:crypto/crypto.dart';
import 'package:dart_dtls_final/crypto.dart';
import 'package:logging/logging.dart';

class Config {
  static final serverDomainName = 'your.server.domain.name';
}

class Dtls {
  static var serverCertificate;
  static String? serverCertificateFingerprint;

  static void init() {
    final log = Logger('DTLS');
    log.info('Initializing self signed certificate for server...');
    try {
      //serverCertificate = generateServerCertificate(Config.serverDomainName);
      serverCertificate = generateSelfSignedCertificate();
      print("Server certificate: $serverCertificate");
      serverCertificateFingerprint =
          getCertificateFingerprint(serverCertificate);
      //print("Server certificate: $serverCertificateFingerprint");
      log.info(
          'Self signed certificate created with fingerprint <u>$serverCertificateFingerprint</u>');
      log.info(
          'This certificate is stored in Dtls.serverCertificate variable globally, it will be used while DTLS handshake, sending SDP, SRTP, SRTCP packets, etc...');
    } catch (e) {
      log.severe('Error generating server certificate: $e');
    }
  }
}
