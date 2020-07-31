package rsa.bouncy.castel.cert;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class RSACertificateGenerator {
	private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

	public static void main(String[] args) {
		try {
			generateRSACert();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void generateRSACert() throws Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

		SecureRandom random = new SecureRandom();
		generator.initialize(2048, random);
		KeyPair pair = generator.generateKeyPair(); // public/private key pair that we are creating certificate for

		Date validityBeginDate = new Date(System.currentTimeMillis());
		System.out.println("Start Date :" + validityBeginDate);

		Date validityEndDate = new Date(System.currentTimeMillis() + 86400000L * 365 * 2);
		System.out.println("End Date :" + validityEndDate);

		// signers name
		X500Name issuerName = new X500Name("CN=Amdocs");

		// subjects name - the same as we are self signed.
		X500Name subjectName = issuerName;

		// serial
		BigInteger serial = BigInteger.valueOf(new Random().nextInt());

		// create the certificate - version 3
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				issuerName, serial, validityBeginDate, validityEndDate,
				subjectName, pair.getPublic()); // bckix jar for both class
		builder.addExtension(Extension.subjectKeyIdentifier, false,
				new SubjectKeyIdentifier(pair.getPublic().getEncoded()));
		builder.addExtension(Extension.basicConstraints, true,
				new BasicConstraints(true));

		X509Certificate cert = signCertificate(builder, pair.getPrivate());
		cert.checkValidity(new Date());
		cert.verify(pair.getPublic());

		encodeCertToPEM(cert, "RSAPublicKeyCertificate.pem");
		encodePrivateToPEM(pair.getPrivate(), "RSAPrivateKey.pem");
		encodePublicToPEM(cert.getPublicKey(), "RSAPublicKey.pem");
	}

	private static X509Certificate signCertificate(
			X509v3CertificateBuilder certificateBuilder,
			PrivateKey signedWithPrivateKey) throws OperatorCreationException,
			CertificateException {
		ContentSigner signer = new JcaContentSignerBuilder(
				"SHA256WithRSAEncryption").setProvider(PROVIDER_NAME).build(
				signedWithPrivateKey); // bcmail jar for jcajceHelper class
		return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME)
				.getCertificate(certificateBuilder.build(signer));
	}

	public static void encodeCertToPEM(X509Certificate cert, String fileName)
			throws CertificateEncodingException, IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		try (PemWriter writer = new PemWriter(new OutputStreamWriter(stream))) {
			writer.writeObject(new PemObject("PUBLIC KEY X509 CERTIFICATE",
					cert.getEncoded()));
		}
		FileOutputStream fos = new FileOutputStream(new File(fileName));
		stream.writeTo(fos);
	}

	public static void encodePrivateToPEM(Key privateKey, String fileName)
			throws CertificateEncodingException, IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		try (PemWriter writer = new PemWriter(new OutputStreamWriter(stream))) {
			writer.writeObject(new PemObject("PRIVATE KEY", privateKey
					.getEncoded()));
		}
		FileOutputStream fos = new FileOutputStream(new File(fileName));
		stream.writeTo(fos);
	}

	public static void encodePublicToPEM(Key publicKey, String fileName)
			throws CertificateEncodingException, IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		try (PemWriter writer = new PemWriter(new OutputStreamWriter(stream))) {
			writer.writeObject(new PemObject("PUBLIC KEY", publicKey
					.getEncoded()));
		}
		FileOutputStream fos = new FileOutputStream(new File(fileName));
		stream.writeTo(fos);
	}
}