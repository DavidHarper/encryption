package com.obliquity.encryption;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.JOptionPane;

import java.io.*;

public class FileDecrypter {
	public static final int BLOCKSIZE = 16;
	
	Cipher cipher;
	MessageDigest digester;

	public FileDecrypter() throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
		digester = MessageDigest.getInstance("SHA-256");
	}

	public void decrypt(String infilename, String outfilename, byte[] passphrase)
			throws IOException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalStateException,
			ShortBufferException, DigestException, IllegalBlockSizeException, BadPaddingException {
		File infile = new File(infilename);
		File outfile = new File(outfilename);

		if (!infile.exists())
			throw new FileNotFoundException();

		if (!infile.canRead())
			throw new IOException("Cannot read file " + infilename);

		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(
				infile));

		BufferedOutputStream bos = new BufferedOutputStream(
				new FileOutputStream(outfile));

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
		
		byte[] input = new byte[BLOCKSIZE];
		byte[] output = new byte[BLOCKSIZE];
		
		int inbytes = -1;
		
		int intotal = 0;
		int outtotal = 0;
		
		digester.reset();
		
		while ((inbytes = bis.read(input, 0, BLOCKSIZE)) != -1) {
			int nbytes = cipher.update(input, 0, inbytes, output, 0);
		
			bos.write(output, 0, nbytes);
			
			intotal += inbytes;
			outtotal += nbytes;
		}
		
		int nbytes = cipher.doFinal(output, 0);
		
		bos.write(output, 0, nbytes);
		
		outtotal += nbytes;
		
		System.err.println("Read " + intotal + ", wrote " + outtotal + " bytes");
		
		bos.close();
		bis.close();
	}

	public static void main(String[] args) {
		if (args.length != 2) {
			System.err.println("Usage: FileDecrypter input-file output-file");
			System.exit(1);
		}

		try {
			FileDecrypter decrypter = new FileDecrypter();

			String s = (String) JOptionPane.showInputDialog(null,
					"Enter the passphrase for decryption",
					"Enter your passphrase", JOptionPane.PLAIN_MESSAGE, null,
					null, null);

			byte[] passphrase = s.getBytes();

			decrypter.decrypt(args[0], args[1], passphrase);
			
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
