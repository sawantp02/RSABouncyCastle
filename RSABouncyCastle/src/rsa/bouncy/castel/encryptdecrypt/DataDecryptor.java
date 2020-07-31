package rsa.bouncy.castel.encryptdecrypt;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.Security;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import Decoder.BASE64Decoder;

public class DataDecryptor {
	public static void main(String[] args) {
		String encryptedData = "xS4Mjb/sMiyXAwdnhydC3W0V2Mp3T6AWcX5fx1yFurNxLrncDK125sVUuNCEIhL33HlDx9RDq1GmuDYcfU5NDhcpQdN92yzD0Zekr8/lTYtbRN4P9mvpNFSZWL7Jit5uWO1l6FpNKTZt4NJ0eZ2Khl/XK9uk+iV+dFOCa8h+fTcpdzolTAGVRhdYJpbf0+WtSaAEmG21Yt0O4S6G8fLQarviz2oNAAR7lxsfF/NydbzxXU9aBWbaLStZUxxqDBGz+LVKiA8sxYPqya1MbCC2Ev+cXh0vIYu8hWWHkviymtouy89sU61BN0TtfkTyzqdX250ntLakEG+mK+FRYEvOwQ==";
		System.out.println("Decrypted Data: " + decrypt("RSAPrivateKey.pem", encryptedData));
	}
	
	private static String decrypt(String privateKeyFilename, String encryptedData) {
		System.out.println("-->Enter method decrypt on DataDecryptor");
		String outputData = null;
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			String filecontent = readFileAsString(privateKeyFilename);
			if (filecontent != null && !filecontent.trim().isEmpty()) {
				filecontent = filecontent.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
			}

			System.out.println(filecontent);
			BASE64Decoder b64 = new BASE64Decoder();
			AsymmetricKeyParameter privateKey = (AsymmetricKeyParameter) PrivateKeyFactory.createKey(b64.decodeBuffer(filecontent));
			AsymmetricBlockCipher e = new RSAEngine();
			e = new org.bouncycastle.crypto.encodings.OAEPEncoding(e);
			e.init(false, privateKey);

			byte[] messageBytes = b64.decodeBuffer(encryptedData);
			byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
			outputData = new String(hexEncodedCipher);
		} catch (Exception e) {
			System.out.println(e);
		}
		System.out.println("<--Exit method decrypt on DataDecryptor");
		return outputData;
	}

	private static String readFileAsString(String filePath) throws java.io.IOException {
		System.out.println("-->Enter method readFileAsString on DataDecryptor");
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
		System.out.println("<--Exit method readFileAsString on DataDecryptor");
		return fileData.toString();
	}
}
