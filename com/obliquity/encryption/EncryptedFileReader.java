package com.obliquity.encryption;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

public class EncryptedFileReader {
	protected Cipher cipher;
	protected MessageDigest digester;

	public EncryptedFileReader() throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
		digester = MessageDigest.getInstance("SHA-256");
	}

	public void decrypt(File[] infiles, byte[] passphrase, AbstractArchiveHandler handler, File destdir) throws IOException,
			NoSuchAlgorithmException, InvalidParameterSpecException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		
		BufferedInputStream bis = createInputStream(infiles);

		byte[] IV = new byte[16];

		bis.read(IV, 0, 16);

		// Generate the AES key from the SHA-256 hash of the passphrase

		byte[] digest = digester.digest(passphrase);

		byte[] key = new byte[16];

		for (int i = 0; i < 16; i++)
			key[i] = digest[i];

		IvParameterSpec ivps = new IvParameterSpec(IV);

		AlgorithmParameters params = AlgorithmParameters.getInstance("AES");

		params.init(ivps);

		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

		cipher.init(Cipher.DECRYPT_MODE, skeySpec, params);

		CipherInputStream cis = new CipherInputStream(bis, cipher);
		
		handler.processArchive(cis, this, destdir);
	}
	
	private BufferedInputStream createInputStream(File[] files) throws IOException {
		Vector<InputStream> streams = new Vector<InputStream>(files.length);
		
		for (int i = 0; i < files.length; i++)
			streams.add(new FileInputStream(files[i]));
		
		SequenceInputStream sis = new SequenceInputStream(streams.elements());
		
		return new BufferedInputStream(sis);
	}
	
	void processDirectoryEntry(String entryName, Date modified, File destdir) {
		System.out.println("DIRECTORY: " + entryName + " [last modified: " + modified + "]");
		
		if (destdir != null) {
			File dir = new File(destdir, entryName);
			dir.mkdirs();
		}
	}
	
	void processFileEntry(String entryName, Date modified, long size, InputStream is, File destdir) throws IOException {
		System.out.println("FILE: " + entryName + " [size: " + size + " bytes, last modified " + modified + "]");
		
		if (destdir != null) {
			File outfile = new File(destdir, entryName);
			
			BufferedOutputStream bos = null;
			
			try {
				bos = new BufferedOutputStream(new FileOutputStream(outfile));
			}
			catch (FileNotFoundException fnfe) {
				System.err.println("Failed to open " + outfile.getAbsolutePath() + " for writing : " +
						fnfe.getMessage());
			}
		
			int bytesread = readFromStream(is,bos);
		
			if (bos != null) {
				bos.close();

				System.out.println("\t" + bytesread + " bytes written to " + outfile);
			}
			
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
	
	public static void main(String[] args) {
		boolean unpack = false;
		String format = null;
		
		for (int i = 0; i < args.length; i++) {
			if (args[i].equalsIgnoreCase("-unpack"))
				unpack = true;
			else if (args[i].equalsIgnoreCase("-format"))
				format = args[++i];
			else {
				System.err.println("Unknown option: " + args[i]);
				System.exit(1);
			}
		}
		
		if (format == null) {
			System.err.println("You must specify the format");
			System.exit(2);
		}
		
		AbstractArchiveHandler handler = null;
		
		if (format.equalsIgnoreCase("tar"))
			handler = new TarArchiveHandler(false);
		else if (format.equalsIgnoreCase("tgz"))
			handler = new TarArchiveHandler(true);
		else if (format.equalsIgnoreCase("zip"))
			handler = new ZipArchiveHandler();
		else {
			System.err.println("Format not recognised: " + format);
			System.exit(3);
		}		

		try {
			File[] files = null;
			File destdir = null;

			JFileChooser chooser = new JFileChooser();
				
			chooser.setMultiSelectionEnabled(true);
				
			File cwd = new File(System.getProperty("user.dir"));
			chooser.setCurrentDirectory(cwd);

			int returnVal = chooser.showOpenDialog(null);

			if (returnVal == JFileChooser.APPROVE_OPTION)
				files = chooser.getSelectedFiles();
			else
				System.exit(1);

			if (files == null || files.length == 0)
				System.exit(0);
			
			if (unpack) {
				chooser.setMultiSelectionEnabled(false);
			
				chooser.setCurrentDirectory(cwd);
			
				chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

				returnVal = chooser.showOpenDialog(null);

				if (returnVal == JFileChooser.APPROVE_OPTION)
					destdir = chooser.getSelectedFile();
				else
					destdir = null;	
			}

			String s = (String) JOptionPane.showInputDialog(null,
					"Enter the passphrase for decryption",
					"Enter your passphrase", JOptionPane.PLAIN_MESSAGE, null,
					null, null);

			byte[] passphrase = s.getBytes();
			
			EncryptedFileReader decrypter = new EncryptedFileReader();
				
			decrypter.decrypt(files, passphrase, handler, destdir);

			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
