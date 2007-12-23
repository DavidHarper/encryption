package com.obliquity.encryption;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import java.io.*;
import java.util.Random;

public class FileEncrypter {
	public static final int BLOCKSIZE = 16;

	Cipher cipher;
	MessageDigest digester;
	Random random = new Random();

	public FileEncrypter() throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
		digester = MessageDigest.getInstance("SHA-256");
	}

	public void encrypt(File infile, byte[] passphrase)
			throws IOException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalStateException,
			ShortBufferException, DigestException, IllegalBlockSizeException,
			BadPaddingException {
		String infilename = infile.getName();
		
		if (!infile.exists())
			throw new FileNotFoundException();

		if (!infile.canRead())
			throw new IOException("Cannot read file " + infilename);
		
		int dot = infilename.lastIndexOf('.');
		
		String extension = System.getProperty("encryption.extension", ".aes");
		
		String outfilename = ((dot < 0) ? infilename : infilename.substring(0, dot)) + extension;
		
		System.err.println("Encrypting " + infilename + " to " + outfilename);
		
		File outfile = new File(infile.getParent(), outfilename);

		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(
				infile));

		BufferedOutputStream bos = new BufferedOutputStream(
				new FileOutputStream(outfile));

		// Generate an initialisation vector from the SHA-256 hash of 1024
		// random bytes

		byte[] buffer = new byte[1024];

		random.nextBytes(buffer);

		byte[] digest = digester.digest(buffer);

		byte[] IV = new byte[16];

		for (int i = 0; i < 16; i++)
			IV[i] = digest[i];

		bos.write(digest, 0, 16);

		System.err.println("Wrote 16 bytes of IV");

		// Generate the AES key from the SHA-256 hash of the passphrase

		digest = digester.digest(passphrase);

		byte[] key = new byte[16];

		for (int i = 0; i < 16; i++)
			key[i] = digest[i];

		IvParameterSpec ivps = new IvParameterSpec(IV);

		AlgorithmParameters params = AlgorithmParameters.getInstance("AES");

		params.init(ivps);

		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, params);

		byte[] input = new byte[BLOCKSIZE];
		byte[] output = new byte[BLOCKSIZE];

		int inbytes;

		int intotal = 0;
		int outtotal = 0;

		while ((inbytes = bis.read(input, 0, BLOCKSIZE)) != -1) {
			int outbytes = (inbytes < BLOCKSIZE) ? cipher.doFinal(input, 0,
					inbytes, output, 0) : cipher.update(input, 0, inbytes,
					output, 0);

			bos.write(output, 0, outbytes);

			intotal += inbytes;
			outtotal += outbytes;
		}

		outtotal += output.length;

		System.err
				.println("Read " + intotal + ", wrote " + outtotal + " bytes");

		bos.close();
		bis.close();
	}

	public static void main(String[] args) {
		try {
			JFileChooser chooser = new JFileChooser();
			chooser.setMultiSelectionEnabled(true);
			
			File cwd = new File(System.getProperty("user.dir"));
			chooser.setCurrentDirectory(cwd);

			int rc = chooser.showOpenDialog(null);

			if (rc == JFileChooser.APPROVE_OPTION) {
				File[] files = chooser.getSelectedFiles();
					
				FileEncrypter encrypter = new FileEncrypter();

				String s = (String) JOptionPane.showInputDialog(null,
						"Enter the passphrase for encryption",
						"Enter your passphrase", JOptionPane.PLAIN_MESSAGE,
						null, null, null);

				byte[] passphrase = s.getBytes();

				for (int i = 0; i < files.length; i++)
					encrypter.encrypt(files[i], passphrase);
			}

			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
