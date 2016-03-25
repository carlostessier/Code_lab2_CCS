package p2;

import java.util.Scanner;


public class Demos {
	
	static Scanner scanner;

	public static void main(String[] args) {
		Demos instance = new Demos();
		instance.doMenu();
	}

	/**
	 * Menu options
	 */
	protected final int MENU_OPTION_CREATE_FILE = 0;
	protected final int MENU_OPTION_GENERATE_DES_KEY = 1;
	protected final int MENU_OPTION_ENCRYPT_DES = 2;
	protected final int MENU_OPTION_DECRYPT_DES = 3;
	protected final int MENU_OPTION_GENERATE_TRIPLE_DES_KEY = 4;
	protected final int MENU_OPTION_ENCRYPT_TRIPLE_DES = 5;
	protected final int MENU_OPTION_DECRYPT_TRIPLE_DES =6;
	protected final int MENU_OPTION_GENERATE_AES_KEY = 7;
	protected final int MENU_OPTION_ENCRYPT_AES = 8;
	protected final int MENU_OPTION_DECRYPT_AES = 9;
	protected final int MENU_OPTION_CREATE_MD5 = 10;
	protected final int MENU_OPTION_CREATE_SHA1 = 11;
	protected final int MENU_OPTION_GENERATE_RSA_KEYS = 12;
	protected final int MENU_OPTION_ENCRYPT_RSA = 13;
	protected final int MENU_OPTION_DECRYPT_RSA = 14;
	
	/**
	 * Muestra el menú y gestiona las solicitudes de cada una de sus opciones
	 */
	private void doMenu() {
		System.out
				.println("\n\nPruebas de algoritmos criptográficos con Java y BouncyCastle");
		System.out
				.println("----------------------------------------------------------------");
		System.out.println("\t  0. Crear un archivo de texto");
		System.out.println("DES");
		System.out
				.println("\t  1. Generar clave para algoritmo de cifrado DES");
		System.out.println("\t  2. Cifrar archivo con DES");
		System.out.println("\t  3. Descifrar archivo con DES");
		System.out.println("Triple DES");
		System.out
				.println("\t  4. Generar clave para algoritmo de cifrado DES");
		System.out.println("\t  5. Cifrar archivo con DES");
		System.out.println("\t  6. Descifrar archivo con DES");
		System.out.println("AES");
		System.out
				.println("\t  7. Generar clave para algoritmo de cifrado AES");
		System.out.println("\t  8. Cifrar archivo con AES");
		System.out.println("\t  9. Descifrar archivo con AES");
		System.out.println("FUNCIONES RESUMEN");
		System.out.println("\t  10. Generar resumen MD5 de un archivo");
		System.out.println("\t  11. Generar resumen SHA1 de un archivo");
		System.out.println("RSA");
		System.out.println("\t  12. Generar par de claves RSA");
		System.out.println("\t 13. Cifrar archivo con RSA");
		System.out.println("\t 14. Descifrar archivo con RSA");
		System.out.println("\n q. Terminar ejecución");
		System.out.print("\n\nSeleccione una opción y pulse ENTER:");
			scanner = new Scanner(System.in);
		String selectedOption = scanner.nextLine();

		if (!selectedOption.matches("-?\\d+?") && !selectedOption.equals("q")) {
			System.out.println("Opción incorrecta");
		} else {
			if(selectedOption.equals("q")){
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
