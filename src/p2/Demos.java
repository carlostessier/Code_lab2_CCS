package p2;

import java.util.Scanner;


public class Demos {
	
	static Scanner scanner;

	public static void main(String[] args) {
		Demos instance = new Demos();
		scanner = new Scanner(System.in);
		instance.doMenu();
	}

	/**
	 * Menu options
	 */
	private static final int MENU_OPTION_CREATE_FILE = 0;
	private static final int MENU_OPTION_GENERATE_DES_KEY = 1;
	private static final int MENU_OPTION_ENCRYPT_DES = 2;
	private static final int MENU_OPTION_DECRYPT_DES = 3;
	private static final int MENU_OPTION_GENERATE_TRIPLE_DES_KEY = 4;
	private static final int MENU_OPTION_ENCRYPT_TRIPLE_DES = 5;
	private static final int MENU_OPTION_DECRYPT_TRIPLE_DES =6;
	private static final int MENU_OPTION_GENERATE_AES_KEY = 7;
	private static final int MENU_OPTION_ENCRYPT_AES = 8;
	private static final int MENU_OPTION_DECRYPT_AES = 9;
	private static final int MENU_OPTION_CREATE_MD5 = 10;
	private static final int MENU_OPTION_CREATE_SHA1 = 11;
	private static final int MENU_OPTION_CREATE_SHA512 = 12;
	private static final int MENU_OPTION_GENERATE_RSA_KEYS = 13;
	private static final int MENU_OPTION_ENCRYPT_RSA = 14;
	private static final int MENU_OPTION_DECRYPT_RSA = 15;
	private static final String MENU_OPTION_EXIT = "q";
	private static final String MENU_PATTERN = "-?\\d+?";


	
	/**
	 * Muestra el menú y gestiona las solicitudes de cada una de sus opciones
	 */
	private void doMenu() {
		System.out
				.println("\n\nPruebas de algoritmos criptográficos con Java y BouncyCastle");
		System.out
				.println("----------------------------------------------------------------");
		System.out.println("\t  "+MENU_OPTION_CREATE_FILE+". Crear un archivo de texto");
		System.out.println("DES");
		System.out
				.println("\t  "+MENU_OPTION_GENERATE_DES_KEY+". Generar clave para algoritmo de cifrado DES");
		System.out.println("\t  "+MENU_OPTION_ENCRYPT_DES+". Cifrar archivo con DES");
		System.out.println("\t  "+MENU_OPTION_DECRYPT_DES+". Descifrar archivo con DES");
		System.out.println("Triple DES");
		System.out
				.println("\t  "+MENU_OPTION_GENERATE_TRIPLE_DES_KEY+". Generar clave para algoritmo de cifrado Triple DES");
		System.out.println("\t  "+MENU_OPTION_ENCRYPT_TRIPLE_DES+". Cifrar archivo con Triple DES");
		System.out.println("\t  "+MENU_OPTION_DECRYPT_TRIPLE_DES+". Descifrar archivo con Triple DES");
		System.out.println("AES");
		System.out
				.println("\t  "+MENU_OPTION_GENERATE_AES_KEY+". Generar clave para algoritmo de cifrado AES");
		System.out.println("\t  "+MENU_OPTION_ENCRYPT_AES+". Cifrar archivo con AES");
		System.out.println("\t  "+MENU_OPTION_DECRYPT_AES+". Descifrar archivo con AES");
		System.out.println("FUNCIONES RESUMEN");
		System.out.println("\t  "+MENU_OPTION_CREATE_MD5+". Generar resumen MD5 de un archivo");
		System.out.println("\t  "+MENU_OPTION_CREATE_SHA1+". Generar resumen SHA1 de un archivo");
		System.out.println("\t  "+MENU_OPTION_CREATE_SHA512+". Generar resumen SHA512 de un archivo");
		System.out.println("RSA");
		System.out.println("\t  "+MENU_OPTION_GENERATE_RSA_KEYS+". Generar par de claves RSA");
		System.out.println("\t "+MENU_OPTION_ENCRYPT_RSA+". Cifrar archivo con RSA");
		System.out.println("\t "+MENU_OPTION_DECRYPT_RSA+". Descifrar archivo con RSA");
		System.out.println("\n "+MENU_OPTION_EXIT+". Terminar ejecución");
		System.out.print("\n\nSeleccione una opción y pulse ENTER:");
		String selectedOption = scanner.nextLine();

		if (!selectedOption.matches(MENU_PATTERN) && !selectedOption.equals(MENU_OPTION_EXIT)) {
			System.out.println("Opción incorrecta");
		} else {
			if(selectedOption.equals(MENU_OPTION_EXIT)){
				System.exit(0);
			}
			switch (Integer.parseInt(selectedOption)) {
			case MENU_OPTION_CREATE_FILE:
				Utils.instance().saveConsoleToFile();
				break;
			case MENU_OPTION_GENERATE_DES_KEY:
				new DES().doGenerateKey();
				break;
			case MENU_OPTION_ENCRYPT_DES:
				new DES().doEncrypt();
				break;
			case MENU_OPTION_DECRYPT_DES:
				new DES().doDecrypt();
				break;
			case MENU_OPTION_GENERATE_TRIPLE_DES_KEY:
				new TripleDES().doGenerateKey();
				break;
			case MENU_OPTION_ENCRYPT_TRIPLE_DES:
				new TripleDES().doEncrypt();
				break;
			case MENU_OPTION_DECRYPT_TRIPLE_DES:
				new TripleDES().doDecrypt();
				break;
			case MENU_OPTION_GENERATE_AES_KEY:
				new AES().doGenerateKey();
				break;
			case MENU_OPTION_ENCRYPT_AES:
				new AES().doEncrypt();
				break;
			case MENU_OPTION_DECRYPT_AES:
				new AES().doDecrypt();
				break;
			case MENU_OPTION_CREATE_MD5:
				new Hash().doMD5();
				break;
			case MENU_OPTION_CREATE_SHA1:
				new Hash().doSHA1();
				break;
			case MENU_OPTION_CREATE_SHA512:
				new Hash().doSHA512();
				break;
			case MENU_OPTION_GENERATE_RSA_KEYS:
				new RSA().doGenerateKeys();
				break;
				case MENU_OPTION_ENCRYPT_RSA:
				new RSA().doEncrypt();
				break;
			case MENU_OPTION_DECRYPT_RSA:
				new RSA().doDecrypt();
				break;
			default:
				System.out.println("Opción incorrecta");
				break;
			}
		}
		Utils.instance().clearConsole();
		doMenu();
	}
}
