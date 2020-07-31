package rsa.bouncy.castel.encryptdecrypt;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import Decoder.BASE64Encoder;

public class DataEncryptor {
	public static void main(String[] args) {
		try {
			//String hexEncodedCipher = encrypt("RSAPublicKeyCertificate.pem", "abcd! 08$");
			String hexEncodedCipher = encrypt("RSAPublicKeyCertificate.pem", "342276123181110");
			System.out.println("Encrypted Data : " + hexEncodedCipher);
		} catch(Exception exception) {
			exception.printStackTrace();
		}
	}

	private static String encrypt(String publicKeyFilename, String inputData) throws IOException, CertificateException, InvalidCipherTextException {
		System.out.println("-->Enter method encrypt on DataEncryptor");

		String encryptedData = "";
		String certificateString = readFileAsString(publicKeyFilename);
		X509Certificate certificate = null;
		CertificateFactory cf = null;
		try {
			if (certificateString != null && !certificateString.trim().isEmpty()) {
				certificateString = certificateString.replace("-----BEGIN PUBLIC KEY CERTIFICATE-----", "").replace("-----END PUBLIC KEY CERTIFICATE-----", "");
				cf = CertificateFactory.getInstance("X.509");
				certificate = (X509Certificate) cf.generateCertificate(new FileInputStream("RSAPublicKeyCertificate.pem"));
			}
		} catch (CertificateException e) {
			throw new CertificateException(e);
		}

		PublicKey key = certificate.getPublicKey();
		BASE64Encoder b64 = new BASE64Encoder();
		
		AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter) PublicKeyFactory.createKey(key.getEncoded());
		AsymmetricBlockCipher e = new RSAEngine();
		e = new org.bouncycastle.crypto.encodings.OAEPEncoding(e);
		e.init(true, publicKey);

		byte[] messageBytes = inputData.getBytes();
		byte[] hexEncodedCipher = e.processBlock(messageBytes, 0,messageBytes.length);
		encryptedData = b64.encode(hexEncodedCipher);

		System.out.println("<--Exit method encrypt on DataEncryptor");
		return encryptedData;
	}

	private static String readFileAsString(String filePath) throws java.io.IOException {
		System.out.println("-->Enter method readFileAsString on DataEncryptor");
		StringBuffer fileData = new StringBuffer(1000);
		BufferedReader reader = new BufferedReader(new FileReader(filePath));
		char[] buf = new char[1024];
		int numRead = 0;
		while ((numRead = reader.read(buf)) != -1) {
			String readData = String.valueOf(buf, 0, numRead);
			fileData.append(readData);
			buf = new char[1024];
		}
		reader.close();
		System.out.println(fileData.toString());
		System.out.println("<--Exit method readFileAsString on DataEncryptor");
		return fileData.toString();
	}

	public static String bytesToHex(byte[] in) {
		final StringBuilder builder = new StringBuilder();
		for (byte b : in) {
			builder.append(String.format("%02x", b));
		}
		return builder.toString();
	}
}