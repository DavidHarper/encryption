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

import org.apache.tools.tar.*;

public class TarCryptReader {
	protected Cipher cipher;
	protected MessageDigest digester;

	public TarCryptReader() throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
		digester = MessageDigest.getInstance("SHA-256");
	}

	public void decrypt(File[] infiles, byte[] passphrase, boolean unpack) throws IOException,
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
		
		GZIPInputStream gis = new GZIPInputStream(cis);

		TarInputStream tis = new TarInputStream(gis);

		TarEntry entry = null;
		
		while ((entry = tis.getNextEntry()) != null)
			processTarEntry(entry, tis, unpack);

		tis.close();
	}
	
	private BufferedInputStream createInputStream(File[] files) throws IOException {
		Vector<InputStream> streams = new Vector<InputStream>(files.length);
		
		for (int i = 0; i < files.length; i++)
			streams.add(new FileInputStream(files[i]));
		
		SequenceInputStream sis = new SequenceInputStream(streams.elements());
		
		return new BufferedInputStream(sis);
	}

	private void processTarEntry(TarEntry tarentry, InputStream is, boolean unpack)
			throws IOException {
		String entryname = tarentry.getName();
		long size = tarentry.getSize();
		Date modified = tarentry.getModTime();

		System.out.println(entryname + " (" +
				(tarentry.isDirectory() ? "directory" : size + " bytes") +
				", last modified " + modified + ")");
		
		if (unpack) {
			if (tarentry.isDirectory()) {
				File dir = new File(entryname);
				dir.mkdirs();
			} else {
				File outfile = new File(entryname);
			
				BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outfile));
			
				int bytesread = readFromStream(is,bos);
			
				bos.close();

				System.out.println("\t" + bytesread + " bytes read from stream.");
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
			
			TarCryptReader decrypter = new TarCryptReader();

			String s = (String) JOptionPane.showInputDialog(null,
					"Enter the passphrase for decryption",
					"Enter your passphrase", JOptionPane.PLAIN_MESSAGE, null,
					null, null);

			byte[] passphrase = s.getBytes();
				
			decrypter.decrypt(files, passphrase, unpack);

			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
