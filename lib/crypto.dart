import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:pointycastle/export.dart';
import 'package:basic_utils/basic_utils.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart'
    as cryptography; // Add this import

import 'package:basic_utils/basic_utils.dart' as cryptoUtils;

import 'package:asn1lib/asn1lib.dart';

class EcdsaSignature {
  BigInt r, s;
  EcdsaSignature(this.r, this.s);
}

String generateSelfSignedCertificate() {
  cryptoUtils.AsymmetricKeyPair<cryptoUtils.PublicKey, cryptoUtils.PrivateKey>
      pair = cryptoUtils.CryptoUtils.generateEcKeyPair();
  var privKey = pair.privateKey as cryptoUtils.ECPrivateKey;
  var pubKey = pair.publicKey as cryptoUtils.ECPublicKey;
  var dn = {
    'CN': 'Self-Signed',
  };
  var csr = cryptoUtils.X509Utils.generateEccCsrPem(dn, privKey, pubKey);

  var x509PEM = cryptoUtils.X509Utils.generateSelfSignedCertificate(
    privKey,
    csr,
    365,
  );
  return x509PEM;
  //return Uint16List.fromList(utf8.encode(x509PEM));
}

// Future<AsymmetricKeyPair<PublicKey, PrivateKey>>
//     generateServerCertificatePrivateKey() async {
//   print("Generating ecc private key");
//   final keyParams = ECKeyGeneratorParameters(ECCurve_secp256r1());
//   final random = FortunaRandom();
//   final keyGen = ECKeyGenerator();
//   keyGen.init(ParametersWithRandom(keyParams, random));
//   return keyGen.generateKeyPair();
// }

Future<AsymmetricKeyPair<PublicKey, PrivateKey>>
    generateServerCertificatePrivateKey() async {
  print("Generating ECC private key");
  final keyParams = ECKeyGeneratorParameters(ECCurve_secp256r1());
  final random = FortunaRandom();

  // Seed the random number generator
  final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => Random.secure().nextInt(256)));
  random.seed(KeyParameter(seed));

  final keyGen = ECKeyGenerator();
  keyGen.init(ParametersWithRandom(keyParams, random));
  return keyGen.generateKeyPair();
}

// Future<Uint8List> generateSelfSignedCertificate(cryptography.KeyPair keyPair, PublicKey publicKey) async {
//   final asn1Sequence = ASN1Sequence();

//   // Add version
//   final version = ASN1Integer(BigInt.from(2));
//   asn1Sequence.add(version);

//   // Add serial number
//   final serialNumber = ASN1Integer(BigInt.from(1));
//   asn1Sequence.add(serialNumber);

//   // Add signature algorithm
//   final signatureAlgorithm = ASN1Sequence();
//   signatureAlgorithm.add(ASN1ObjectIdentifier.fromName('ecdsa-with-SHA256'));
//   asn1Sequence.add(signatureAlgorithm);

//   // Add issuer
//   final issuer = ASN1Sequence();
//   issuer.add(ASN1Set()..add(ASN1Sequence()..add(ASN1ObjectIdentifier.fromName('commonName'))..add(ASN1UTF8String('Self-Signed'))));
//   asn1Sequence.add(issuer);

//   // Add validity
//   final validity = ASN1Sequence();
//   validity.add(ASN1UtcTime(DateTime.now()));
//   validity.add(ASN1UtcTime(DateTime.now().add(Duration(days: 365))));
//   asn1Sequence.add(validity);

//   // Add subject
//   final subject = ASN1Sequence();
//   subject.add(ASN1Set()..add(ASN1Sequence()..add(ASN1ObjectIdentifier.fromName('commonName'))..add(ASN1UTF8String('Self-Signed'))));
//   asn1Sequence.add(subject);

//   // Add public key
//   final publicKeyBytes = (publicKey as cryptography.EcPublicKey).toBytes;
//   final publicKeyInfo = ASN1Sequence();
//   publicKeyInfo.add(ASN1Sequence()..add(ASN1ObjectIdentifier.fromName('ecPublicKey'))..add(ASN1ObjectIdentifier.fromName('secp256r1')));
//   publicKeyInfo.add(ASN1BitString(Uint8List.fromList(publicKeyBytes)));
//   asn1Sequence.add(publicKeyInfo);

//   // Sign the certificate
//   final signature = ASN1BitString(Uint8List.fromList([])); // Placeholder for signature
//   asn1Sequence.add(signature);

//   return asn1Sequence.encodedBytes;
// }

Future<Uint8List> generateServerCertificate(String cn) async {
  final keyPair = await generateServerCertificatePrivateKey();
  final privateKey = keyPair.privateKey as ECPrivateKey;
  final publicKey = keyPair.publicKey as ECPublicKey;

  // Generate a serial number within the valid range
  final serialNumber = BigInt.from(Random.secure().nextInt(1 << 32));

  final subject = 'CN=$cn';
  final issuer = subject;

  var dn = {
    'CN': cn,
  };
  print("Generating ECC CSR PEM");
  var csr = X509Utils.generateEccCsrPem(dn, privateKey, publicKey);

  var x509PEM = X509Utils.generateSelfSignedCertificate(privateKey, csr, 365,
      serialNumber: serialNumber.toString(), issuer: dn);

  return Uint8List.fromList(utf8.encode(x509PEM));
}

String generateSelfSignedCertificateKelly() {
  AsymmetricKeyPair<PublicKey, PrivateKey> pair =
      CryptoUtils.generateEcKeyPair();
  var privKey = pair.privateKey as ECPrivateKey;
  var pubKey = pair.publicKey as ECPublicKey;
  var dn = {
    'CN': 'Self-Signed',
  };
  var csr = X509Utils.generateEccCsrPem(dn, privKey, pubKey);

  var x509PEM = X509Utils.generateSelfSignedCertificate(
    privKey,
    csr,
    365,
  );
  return x509PEM;
}

Uint8List generateValueKeyMessage(Uint8List clientRandom,
    Uint8List serverRandom, Uint8List publicKey, int curve) {
  final serverECDHParams = Uint8List(4);
  serverECDHParams[0] = 3; // CurveTypeNamedCurve
  serverECDHParams.buffer.asByteData().setUint16(1, curve);
  serverECDHParams[3] = publicKey.length;

  final plaintext = Uint8List.fromList([
    ...clientRandom,
    ...serverRandom,
    ...serverECDHParams,
    ...publicKey,
  ]);

  return plaintext;
}

Future<Uint8List> generateKeySignature(
    Uint8List clientRandom,
    Uint8List serverRandom,
    Uint8List publicKey,
    int curve,
    ECPrivateKey privateKey) async {
  final msg =
      generateValueKeyMessage(clientRandom, serverRandom, publicKey, curve);
  final digest = SHA256Digest().process(msg);
  final signer = Signer('SHA-256/ECDSA');
  signer.init(true, PrivateKeyParameter<ECPrivateKey>(privateKey));
  final sig = signer.generateSignature(digest) as ECSignature;
  return Uint8List.fromList(
      [...bigIntToUint8List(sig.r), ...bigIntToUint8List(sig.s)]);
}

Uint8List bigIntToUint8List(BigInt number) {
  var hexString = number.toRadixString(16);
  if (hexString.length % 2 != 0) {
    hexString = '0' + hexString; // Ensure even length
  }
  return Uint8List.fromList(hex.decode(hexString));
}

String getCertificateFingerprint(Uint8List certificate) {
  print(utf8.decode(certificate));
  final digest = SHA256Digest().process(certificate);
  return digest
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join(':')
      .toUpperCase();
}

Future<Uint8List> generatePreMasterSecret(
    Uint8List publicKey, Uint8List privateKey) async {
  // final algorithm = cryptography.X25519();
  //final keyPair = cryptography.SimpleKeyPairData(privateKey, type: cryptography.KeyPairType.x25519);
  // final sharedSecret = await algorithm.sharedSecret(
  //   keyPair: keyPair,
  //   remotePublicKey: SimplePublicKey(publicKey, type: KeyPairType.x25519),
  // );

  final algorithm = cryptography.X25519();

  // Example private key bytes (32 bytes)

  // Example public key bytes (32 bytes)

  // Create the private key object
  final keyPair = cryptography.SimpleKeyPairData(
    privateKey,
    publicKey: cryptography.SimplePublicKey(publicKey,
        type: cryptography.KeyPairType.x25519),
    type: cryptography.KeyPairType.x25519,
  );

  // // Create the public key object
  final publicKeyBytes = cryptography.SimplePublicKey(publicKey,
      type: cryptography.KeyPairType.x25519);

  // Calculate the shared secret (pre-master secret)
  final sharedSecret = await algorithm.sharedSecretKey(
    keyPair: keyPair,
    remotePublicKey: publicKeyBytes,
  );

  // Extract the shared secret bytes
  final sharedSecretBytes = await sharedSecret.extractBytes();
  return Uint8List.fromList(sharedSecretBytes);
}

Future<Uint8List> generateMasterSecret(Uint8List preMasterSecret,
    Uint8List clientRandom, Uint8List serverRandom) async {
  final seed = Uint8List.fromList(
      [...utf8.encode('master secret'), ...clientRandom, ...serverRandom]);
  final result = await PHash(preMasterSecret, seed, 48);
  return result;
}

Future<Uint8List> generateExtendedMasterSecret(
    Uint8List preMasterSecret, Uint8List handshakeHash) async {
  final seed = Uint8List.fromList(
      [...utf8.encode('extended master secret'), ...handshakeHash]);
  final result = await PHash(preMasterSecret, seed, 48);
  return result;
}

Future<Uint8List> generateKeyingMaterial(Uint8List masterSecret,
    Uint8List clientRandom, Uint8List serverRandom, int length) async {
  final seed = Uint8List.fromList([
    ...utf8.encode('EXTRACTOR-dtls_srtp'),
    ...clientRandom,
    ...serverRandom
  ]);
  final result = await PHash(masterSecret, seed, length);
  return result;
}

Future<Uint8List> PHash(
    Uint8List secret, Uint8List seed, int requestedLength) async {
  final hmac = HMac(SHA256Digest(), 64);
  hmac.init(KeyParameter(secret));

  var result = Uint8List(requestedLength);
  var a = seed;
  var offset = 0;

  while (offset < requestedLength) {
    a = hmac.process(a);
    final output = hmac.process(Uint8List.fromList([...a, ...seed]));
    final remaining = requestedLength - offset;
    final toCopy = remaining < output.length ? remaining : output.length;
    result.setRange(offset, offset + toCopy, output);
    offset += toCopy;
  }

  return result;
}
