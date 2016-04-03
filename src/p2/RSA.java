package p2;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Scanner;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.encoders.Hex;

public class RSA {
	private static final boolean ENCRYPT = true;
	private static final boolean DECRYPT = false;
	private static final int KEY_LENGTH = 1;// 1024 1528 2048
	private static final String FILE_EXTENSION_PLAINTEXT = "txt";
	private static final String ALGORITHM = "RSA";
	private static final String FILE_EXTENSION_PRIVATE_KEY = "priv";
	private static final String FILE_EXTENSION_PUBLIC_KEY = "pub";
	private static final String FILE_EXTENSION_CIPHERTEXT = "encrsa";
	private static final String SEED = "UCTresM.";

	static Scanner scanner;

	public void doGenerateKeys() {
		scanner = new Scanner(System.in);

		System.out.print(
				"Introduzca el nombre de los archivos de clave a grabar \n(se almacenarán con las extensiones .priv y .pub):");
		String fileName = scanner.nextLine();
		try {
			if (fileName.trim().length() > 0) {
				String keyfilePath = Utils.instance().filesPath + fileName;
				KeyPairGenerator gen = KeyPairGeneratorSpi.getInstance(ALGORITHM);
				gen.initialize(KEY_LENGTH, generateSecureRamdom());

				Base64Encoder b64 = new Base64Encoder();

				KeyPair pair = gen.generateKeyPair();
				Key pubKey = pair.getPublic();
				Key privKey = pair.getPrivate();

				BufferedOutputStream pubOut = new BufferedOutputStream(
						new FileOutputStream(keyfilePath + "." + FILE_EXTENSION_PUBLIC_KEY));
				BufferedOutputStream privOut = new BufferedOutputStream(
						new FileOutputStream(keyfilePath + "." + FILE_EXTENSION_PRIVATE_KEY));
				b64.encode(pubKey.getEncoded(), 0, pubKey.getEncoded().length, pubOut);
				b64.encode(privKey.getEncoded(), 0, privKey.getEncoded().length, privOut);
				privOut.flush();
				privOut.close();
				pubOut.flush();
				pubOut.close();
			}
			System.out.println("Archivos de claves RSA almacenados");
		} catch (Exception e) {
			System.err.println("Ha ocurrido un error generando las claves RSA:" + e);
		}

	}

	public SecureRandom generateSecureRamdom() {
		SecureRandom sr = null;
		try {
			sr = new SecureRandom();
		    sr.setSeed(SEED.getBytes());
		} catch (Exception e) {
			System.err.println("Ha ocurrido un error generando el número aleatorio");
			return null;
		}
		return sr;

	}

	public void doEncrypt() {
		try {
			byte[] text = Utils.instance().doSelectFile("Seleccione un archivo para cifrar", FILE_EXTENSION_PLAINTEXT);
			if (text != null) {
				byte[] key = Utils.instance().doSelectFile("Seleccione una clave pública", FILE_EXTENSION_PUBLIC_KEY);
				if (key != null) {
					Base64Encoder b64 = new Base64Encoder();
					ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
					BufferedOutputStream bKey = new BufferedOutputStream(keyBytes);
					b64.decode(key, 0, key.length, bKey);
					bKey.flush();
					bKey.close();

					byte[] res = rsa(text, keyBytes.toByteArray(),RSA.ENCRYPT);
					System.out.println("Texto cifrado (en hexadecimal):" + new String(Hex.encode(res)));
					Utils.instance().saveFile(FILE_EXTENSION_CIPHERTEXT, Hex.encode(res));
				}
			} else {
				// No se desea continuar con la ejecución
			}
		} catch (Exception e) {
			System.err.println("Ha ocurrido un error cifrando el archivo:" + e);
		}

	}

	public void doDecrypt() {
		try {
			byte[] fileContent = Utils.instance().doSelectFile("Seleccione un archivo cifrado",
					FILE_EXTENSION_CIPHERTEXT);
			if (fileContent == null) {
				return;
			}
			byte[] key = Utils.instance().doSelectFile("Seleccione una clave privada", FILE_EXTENSION_PRIVATE_KEY);
			if (key != null) {
				Base64Encoder b64 = new Base64Encoder();
				ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
				BufferedOutputStream bKey = new BufferedOutputStream(keyBytes);
				b64.decode(key, 0, key.length, bKey);
				bKey.flush();
				bKey.close();

				byte[] res = rsa(Hex.decode(fileContent), keyBytes.toByteArray(),RSA.DECRYPT);
				if (res != null) {
					System.out.println("Texto en claro:\n" + new String(res));
				}
			}
		} catch (Exception e) {
			System.out.println("Ha ocurrido un error descifrando el archivo:" + e);
		}

	}

	private byte[] rsa(byte[] inputData, byte[] keyBytes, boolean decrypt) {
//..
		try {
			
			AsymmetricKeyParameter Key = (decrypt?
					(AsymmetricKeyParameter) PublicKeyFactory.createKey(keyBytes):
					(AsymmetricKeyParameter) PrivateKeyFactory.createKey(keyBytes));

			AsymmetricBlockCipher e = new RSAEngine();
			// http://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf
			e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
			e.init(decrypt, Key);

			byte[] hexEncodedCipher = e.processBlock(inputData, 0, inputData.length);
			return hexEncodedCipher;
		} catch (Exception e) {
			System.err.println("Ha ocurrido un error cifrando el archivo:" + e);
		}

		return null;
	}
	
	@SuppressWarnings("unused")
	private byte[] encrypt(byte[] inputData, byte[] keyBytes) {

		try {

			AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter) PublicKeyFactory.createKey(keyBytes);
			AsymmetricBlockCipher e = new RSAEngine();
			// http://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf
			e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
			e.init(true, publicKey);

			byte[] hexEncodedCipher = e.processBlock(inputData, 0, inputData.length);
			return hexEncodedCipher;
		} catch (Exception e) {
			System.err.println("Ha ocurrido un error cifrando el archivo:" + e);
		}

		return null;
	}

	@SuppressWarnings("unused")
	private byte[] decrypt(byte[] encryptedData, byte[] keyBytes) {

		try {

			AsymmetricKeyParameter privateKey = (AsymmetricKeyParameter) PrivateKeyFactory.createKey(keyBytes);
			AsymmetricBlockCipher e = new RSAEngine();
			e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
			e.init(false, privateKey);

			byte[] hexEncodedCipher = e.processBlock(encryptedData, 0, encryptedData.length);
			return hexEncodedCipher;

		} catch (Exception e) {
			System.err.println("Ha ocurrido un error descifrando el archivo:" + e);
		}

		return null;

	}
}
