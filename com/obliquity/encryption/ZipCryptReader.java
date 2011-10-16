package com.obliquity.encryption;
import java.io.*;
import java.util.*;
import java.util.zip.*;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

public class ZipCryptReader {
	protected Cipher cipher;
	protected MessageDigest digester;

	public ZipCryptReader() throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
		digester = MessageDigest.getInstance("SHA-256");
	}

	public void decrypt(File infile, byte[] passphrase, boolean unpack) throws IOException,
			NoSuchAlgorithmException, InvalidParameterSpecException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(
				infile));

		String infilename = infile.getName();
		
		System.out.println("----- Processing file " + infilename + " -----");

		byte[] IV = new byte[16];

		bis.read(IV, 0, 16);

		// Generate the AES key from the SHA-256 hash of the passphrase

		byte[] digest = digester.digest(passphrase);

		byte[] key = null;
		
		if (Boolean.getBoolean("AES256")) {
			key = digest;
		} else {
			key = new byte[16];

			for (int i = 0; i < 16; i++)
				key[i] = digest[i];
		}

		IvParameterSpec ivps = new IvParameterSpec(IV);

		AlgorithmParameters params = AlgorithmParameters.getInstance("AES");

		params.init(ivps);

		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

		cipher.init(Cipher.DECRYPT_MODE, skeySpec, params);

		CipherInputStream cis = new CipherInputStream(bis, cipher);

		ZipInputStream zis = new ZipInputStream(cis);

		ZipEntry entry = null;
		
		File destdir = null;
		
		if (unpack) {
			File cwd = new File(System.getProperty("user.dir"));
			
			String[] fnparts = infilename.split("\\.");
			
			destdir = new File(cwd, fnparts[0]);
			
			destdir.mkdir();
		}
		
		while ((entry = zis.getNextEntry()) != null) {
			processZipEntry(entry, zis, destdir);
		}

		zis.close();
	}

	private void processZipEntry(ZipEntry zipentry, InputStream is, File destdir)
			throws IOException {
		String entryname = zipentry.getName();
		long size = zipentry.getSize();
		long csize = zipentry.getCompressedSize();
		Date modified = new Date(zipentry.getTime());

		if (zipentry.isDirectory()) {
			System.out.println("DIRECTORY: " + entryname + "(last modified "
					+ modified + ")");
			File dir = new File(entryname);
			dir.mkdirs();
		}

		System.out.println(entryname + " (" + size + " bytes, " + csize
				+ " compressed, last modified " + modified + ")");

		if (is != null && destdir != null) {
			File outfile = new File(destdir, entryname);
			
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outfile));
			
			int bytesread = readFromStream(is,bos);
			
			bos.close();

			System.out.println("\t" + bytesread + " bytes read from stream.");
		}
	}

	private int readFromStream(InputStream is, OutputStream os) throws IOException {
		byte[] buf = new byte[16384];

		int len;
		int totlen = 0;

		while ((len = is.read(buf)) > 0) {
			if (os != null)
				os.write(buf, 0, len);
			
			totlen += len;
		}

		return totlen;
	}

	private static final String UNPACK_PROPERTY_NAME = "unpack";
	
	public static void main(String[] args) {
		boolean unpack = (System.getProperty(UNPACK_PROPERTY_NAME) == null) ?
				true : Boolean.getBoolean(UNPACK_PROPERTY_NAME);

		try {
			File[] files = null;

			if (args.length > 0) {
				files = new File[args.length];
				for (int i = 0; i < args.length; i++)
					files[i] = new File(args[i]);
			} else {
				JFileChooser chooser = new JFileChooser();
				
				chooser.setMultiSelectionEnabled(true);
				
				File cwd = new File(System.getProperty("user.dir"));
				chooser.setCurrentDirectory(cwd);

				int returnVal = chooser.showOpenDialog(null);

				if (returnVal == JFileChooser.APPROVE_OPTION)
					files = chooser.getSelectedFiles();
				else
					System.exit(1);
			}

			if (files == null || files.length == 0)
				System.exit(0);
			
			ZipCryptReader decrypter = new ZipCryptReader();

			String s = (String) JOptionPane.showInputDialog(null,
					"Enter the passphrase for decryption",
					"Enter your passphrase", JOptionPane.PLAIN_MESSAGE, null,
					null, null);

			byte[] passphrase = s.getBytes();

			for (int i = 0; i < files.length; i++) {
				if (i > 0)
					System.out.println("\n\n");
				
				decrypter.decrypt(files[i], passphrase, unpack);
			}

			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
