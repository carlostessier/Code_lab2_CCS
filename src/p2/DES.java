package p2;


import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.generators.DESKeyGenerator;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * Demostración de cifrado DES con Bouncy Castle
*/
public class DES {
	private static final boolean ENCRYPT = true;
	private static final boolean DECRYPT = false;
	private static final int BYTE = 8;
	private static final String EXTENSION_ENCRYPT_FILE = "encdes";
	private static final String EXTENSION_KEY = "deskey";
	private static final int BLOCK_SIZE = 64;
	BlockCipher engine = new DESEngine();

	/**
	 * Gestiona la creación de una clave DES
	 */
	public void doGenerateKey() {
		byte[] key = generateKey();
		if (key != null) {
			System.out.println("Clave generada:" + new String(Hex.encode(key)));
			Utils.instance().saveFile(EXTENSION_KEY, Hex.encode(key));
		}
	}

	/**
	 * Gestiona el cifrado de un archivo usando el algoritmo DES y una clave alamcenada también en otro archivo
	 */
	public void doEncrypt() {
		// Archivo a cifrar
		byte[] text = Utils.instance().doSelectFile("Seleccione un archivo para cifrar", "txt");
		if (text!=null) {
			// Clave a usar
			byte[] key = Utils.instance().doSelectFile("Seleccione una clave",
					EXTENSION_KEY);
			if (key != null) {
				// La almacenamos en hexadecimal para que sea legible en el archivo
				byte[] res = des(Hex.decode(key),text,DES.ENCRYPT);
				System.out.println("Texto cifrado (en hexadecimal):"
						+ new String(Hex.encode(res)));
				Utils.instance().saveFile(EXTENSION_ENCRYPT_FILE, Hex.encode(res));
			}
		} else {
			// No se desea continuar con la ejecución
		}

	}
	/**
	 * Gestiona el descifrado de un archivo usando el algoritmo DES y una clave almacenada también en otro archivo
	 */
	public void doDecrypt() {
		// Archivo a descifrar
		byte[] fileContent = Utils.instance().doSelectFile(
				"Seleccione una archivo cifrado", EXTENSION_ENCRYPT_FILE);
		if (fileContent == null) {
			return;
		}
		// Clave a usar
		byte[] key = Utils.instance().doSelectFile("Seleccione una clave",
				EXTENSION_KEY);
		if (key != null) {
			// Desciframos el archivo
			byte[] res = des(Hex.decode(key), Hex.decode(fileContent),DES.DECRYPT);
			if (res != null) {
				System.out.println("Texto en claro:"
						+ new String(res));
			}
		}

	}
	
	/**
	 * Realiza el cifrado DES de los datos
	 * @param key Clave
	 * @param ptBytes Texto a cifrar
	 * @return Texto cifrado
	 */
	protected byte[] des(byte[] key, byte[] ptBytes, boolean decrypt) {
		// Creamos un cifrador de Bloque con Padding y con el modo de bloque CBC
		//BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
		//		new CBCBlockCipher(engine));
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
			new OFBBlockCipher(engine,BLOCK_SIZE));
		
		// Lo inicializamos con la clave
		cipher.init(decrypt, new KeyParameter(key));
		// Reservamos espacio para el texto cifrado
		byte[] rv = new byte[cipher.getOutputSize(ptBytes.length)];
		// Realizamos el procesamiento con DES
		int tam = cipher.processBytes(ptBytes, 0, ptBytes.length, rv, 0);
		try {
			// "flush" del cifrador
			cipher.doFinal(rv, tam);
		} catch (Exception ce) {
			System.err
			.println("Ha ocurrido un error al intentar "+(decrypt?"cifrar":"descifrar")+" el texto:"
					+ ce);
			return null;
		}
		// Devolvemos los datos cifrados
		return rv;
	}

	/**
	 * Realiza el cifrado DES de los datos
	 * @param key Clave
	 * @param ptBytes Texto a cifrar
	 * @return Texto cifrado
	 */
	protected byte[] encrypt(byte[] key, byte[] ptBytes) {
		// Creamos un cifrador de Bloque con Padding y con el modo de bloque CBC
		//BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
		//		new CBCBlockCipher(engine));
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
			new OFBBlockCipher(engine,BLOCK_SIZE));
		
		// Lo inicializamos con la clave
		cipher.init(ENCRYPT, new KeyParameter(key));
		// Reservamos espacio para el texto cifrado
		byte[] rv = new byte[cipher.getOutputSize(ptBytes.length)];
		// Realizamos el procesamiento con DES
		int tam = cipher.processBytes(ptBytes, 0, ptBytes.length, rv, 0);
		try {
			// "flush" del cifrador
			cipher.doFinal(rv, tam);
		} catch (Exception ce) {
			ce.printStackTrace();
			return null;
		}
		// Devolvemos los datos cifrados
		return rv;
	}

	/**
	 * Realiza el descifrado DES de los datos
	 * Este método podría obviarse y utilizarse el método encrypt para realizar el descifrado al ser
	 * el algoritmo DES un algoritmo simétrico, pero se mantiene por criterios de claridad para el alumno
	 * @param key Clave
	 * @param ptBytes Texto a descifrar
	 * @return Texto descifrado
	 */
	public byte[] decrypt(byte[] key, byte[] cipherText) {
		// Creamos un cifrador de Bloque con Padding y con el modo de bloque CBC
		//BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
		//		new CBCBlockCipher(engine));
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				new OFBBlockCipher(engine,BLOCK_SIZE));
		// Lo inicializamos con la clave
		cipher.init(DECRYPT, new KeyParameter(key));
		// Reservamos espacio para el texto descifrado
		byte[] rv = new byte[cipher.getOutputSize(cipherText.length)];
		// Realizamos el procesamiento con DES
		int tam = cipher.processBytes(cipherText, 0, cipherText.length, rv, 0);
		try {
			// "flush" del cifrador
			cipher.doFinal(rv, tam);
		} catch (Exception ce) {
			System.out.println("Ha ocurrido un error al intentar descifrar el archivo:"+ce.getLocalizedMessage());
			//			ce.printStackTrace();
			return null;
		}
		// Devolvemos los datos descifrados
		return rv;
	}

	/**
	 * Genera una Clave para el cifrado DES a partir de un número aleatorio
	 * "seguro"
	 * 
	 * @return Clave generada con la longitud de DESParameters
	 */
	public byte[] generateKey() {
		// Creamos un generador de aleatorios "seguro"
		SecureRandom sr = null;
		try {
			sr = new SecureRandom();
			sr.setSeed("UCTresM.".getBytes());
		} catch (Exception e) {
			System.err
					.println("Ha ocurrido un error generando el número aleatorio");
			return null;
		}
		
		// Generamos la clave DES con la longitud necesaria para el algoritmo
		KeyGenerationParameters kgp = new KeyGenerationParameters(sr,
				(DESParameters.DES_KEY_LENGTH) * BYTE);

		DESKeyGenerator kg = new DESKeyGenerator();
		kg.init(kgp);

		/*
		 * Third, and finally, generate the key
		 */
		byte[] key = kg.generateKey();
		return key;

	}
}
