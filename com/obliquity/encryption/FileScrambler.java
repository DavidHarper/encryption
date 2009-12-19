package com.obliquity.encryption;

import java.io.*;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileScrambler {
	private final int BUFFER_SIZE = 1024;
	
	private Cipher cipher;
	private MessageDigest digester;

	public FileScrambler() throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
		digester = MessageDigest.getInstance("SHA-256");
	}

	public static void main(String[] args) {
		if (args.length < 3
				|| (!args[0].equalsIgnoreCase("-encrypt") && !args[0]
						.equalsIgnoreCase("-decrypt"))) {
			System.err
					.println("Usage: FileScrambler -encrypt|decrypt input-file output-file");
			System.exit(1);
		}

		FileScrambler tester = null;

		try {
			tester = new FileScrambler();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		File infile = new File(args[1]);
		File outfile = new File(args[2]);

		if (args[0].equalsIgnoreCase("-encrypt"))
			tester.encryptFile(infile, outfile);
		else
			tester.decryptFile(infile, outfile);
	}

	private void encryptFile(File infile, File outfile) {
		try {
			OutputStream os = makeEncryptingOutputStream(outfile);

			InputStream is = new BufferedInputStream(new FileInputStream(infile));
			
			copyFile(is, os);
			
			is.close();
			os.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void copyFile(InputStream is, OutputStream os) throws IOException {
		byte[] buffer = new byte[BUFFER_SIZE];
		
		int inbytes = -1;
		
		while ((inbytes = is.read(buffer)) != -1) {
			os.write(buffer, 0, inbytes);
		}
	}

	private OutputStream makeEncryptingOutputStream(File file)
			throws IOException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException,
			InvalidAlgorithmParameterException, PasswordMismatchException {
		BufferedOutputStream bos = new BufferedOutputStream(
				new FileOutputStream(file));
		byte[] digest = getDigestFromPassphrase("Enter passphrase>",
				true);
		
		byte[] IV = new byte[16];
		
		for (int i = 0; i < 16; i++)
			IV[i] = digest[i+16];

		IvParameterSpec ivps = new IvParameterSpec(IV);

		AlgorithmParameters params = AlgorithmParameters.getInstance("AES");

		params.init(ivps);

		SecretKeySpec keySpec = getKeySpecFromDigest(digest);

		cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);

		bos.write(IV, 0, 16);

		return new CipherOutputStream(bos, cipher);
	}

	private byte[] getDigestFromPassphrase(String prompt,
			boolean askTwice) throws PasswordMismatchException {
		char[] pwchars = System.console().readPassword(prompt, (Object[]) null);

		char[] pwchars2 = askTwice ? System.console().readPassword(prompt,
				(Object[]) null) : null;

		if (askTwice) {
			if (pwchars.length != pwchars2.length)
				throw new PasswordMismatchException("Password length mismatch");

			for (int i = 0; i < pwchars.length; i++)
				if (pwchars[i] != pwchars2[i])
					throw new PasswordMismatchException(
							"Password content mismatch");
		}

		String pp = new String(pwchars);

		byte[] passphrase = pp.getBytes();

		return digester.digest(passphrase);
	}
	
	private SecretKeySpec getKeySpecFromDigest(byte[] digest) {
		if (digest == null || digest.length < 16)
			throw new IllegalArgumentException("Digest is null or too short");
		
		byte[] key = new byte[16];

		for (int i = 0; i < 16; i++)
			key[i] = digest[i];

		return new SecretKeySpec(key, "AES");
	}

	private void decryptFile(File infile, File outfile) {
		try {
			InputStream is = makeDecryptingInputStream(infile);
			
			OutputStream os = new BufferedOutputStream(new FileOutputStream(outfile));

			copyFile(is, os);
			
			is.close();
			os.close();
		} catch (StreamCorruptedException sce) {
			System.err.println("The input stream was corrupted: "
					+ sce.getMessage());
			sce.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private InputStream makeDecryptingInputStream(File file)
			throws IOException, PasswordMismatchException,
			NoSuchAlgorithmException, InvalidParameterSpecException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(
				file));

		byte[] IV = new byte[16];

		bis.read(IV, 0, 16);
		
		byte[] digest = getDigestFromPassphrase("Enter passphrase",
				false);

		SecretKeySpec keySpec = getKeySpecFromDigest(digest);

		IvParameterSpec ivps = new IvParameterSpec(IV);

		AlgorithmParameters params = AlgorithmParameters.getInstance("AES");

		params.init(ivps);

		cipher.init(Cipher.DECRYPT_MODE, keySpec, params);

		return new CipherInputStream(bis, cipher);
	}
}
