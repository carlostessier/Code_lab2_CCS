package p2;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.util.Scanner;

public class Utils {

	private static Scanner scan;

	private static final String EXTENSION_PLAIN_TEXT = "txt";

	private static final String FINALIZATION_WORD = "fin";

	private static Utils _singleton = null;

	public String filesPath;

	public static Utils instance() {
		if (_singleton == null) {
			_singleton = new Utils();
		}
		return _singleton;
	}

	public void clearConsole() {
		try {
			if (System.getProperty("os.name").contains("Windows")) {
				Runtime.getRuntime().exec("cls");
			} else {
				Runtime.getRuntime().exec("clear");
			}
		} catch (Exception e) {
		}
	}

	public boolean saveConsoleToFile() {
		System.out.println("Introduzca el texto del archivo \n(Escriba 'fin' en una línea para finalizar)");
		String text = "", line = "";
		try {
			while (!line.equals(FINALIZATION_WORD)) {

				line = scan.nextLine().toLowerCase();
				if (!line.equals(FINALIZATION_WORD)) {
					text = text + line + "\n";
				}
			}
			// scan.close();
			return saveFile(EXTENSION_PLAIN_TEXT, text.getBytes());
		} catch (Exception e) {
			System.err.println("Ha ocurrido un error: " + e);
			return false;
		}

	}

	protected Utils() {
		// Get files directory path
		filesPath = System.getProperty("user.dir") + "/files/";
		scan = new Scanner(System.in);

	}

	public boolean saveFile(String ext, byte[] data) {
		System.out.print("Introduzca el nombre del archivo a grabar \n(se almacenará con la extensión " + ext + "):");
		String fileName = scan.nextLine();
		if (fileName.trim().length() == 0) {
			saveFile(ext, data);
		}
		String filePath = filesPath + fileName + "." + ext;
		try {
			BufferedOutputStream keystream = new BufferedOutputStream(new FileOutputStream(filePath));
			keystream.write(data, 0, data.length);
			keystream.flush();
			keystream.close();
		} catch (Exception e) {
			System.out.println("** Ha ocurrido un error intentando grabar el archivo '" + filePath + "'\n");
			e.printStackTrace();
			return false;
		}

		System.out.println("Archivo almacenado en " + filePath + "\n");
		return true;

	}

	/*
	 * public String readTextFromConsole(String message) { if (message != null)
	 * { System.out.print(message + ":"); } return new
	 * Scanner(System.in).nextLine(); }
	 */

	public byte[] loadFile(String infile) {
		// read the key, and decode from hex encoding
		try (BufferedInputStream keystream = new BufferedInputStream(new FileInputStream(infile))) {
			int len = keystream.available();
			byte[] keyhex = new byte[len];
			keystream.read(keyhex, 0, len);
			return keyhex;
		} catch (Exception e) {
			System.err.println("** Error leyendo el archivo ");
			e.printStackTrace();
			return null;
		}
	}

	public byte[] doSelectFile(String message, String extension) {
		File dir = new File(filesPath);

		File[] files = dir.listFiles(new FilenameFilter() {
			public boolean accept(File dir, String filename) {
				return filename.endsWith(extension);
			}
		});
		if (files.length == 0) {
			System.out.println("** No se ha encontrado ningún archivo con la extensión " + extension);
			return null;
		}
		for (File file : files) {
			System.out.println("\t- " + file.getName());
		}

		if (message != null) {
			System.out.print(message + ":");
		}

		String fileName = scan.nextLine();

		if (new File(filesPath + fileName).exists()) {
			return loadFile(filesPath + fileName);
		}
		if (new File(filesPath + fileName + "." + extension).exists()) {
			return loadFile(filesPath + fileName + "." + extension);
		} else {

			System.out.println("** No se ha encontrado el archivo");
			return null;
		}

	}
}
