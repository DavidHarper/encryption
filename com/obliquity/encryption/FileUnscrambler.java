package com.obliquity.encryption;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.ProgressMonitor;
import javax.swing.SwingUtilities;

public class FileUnscrambler {
	protected Cipher cipher;
	protected MessageDigest digester;
	
	public static final int DEFAULT_BUFFER_SIZE = 16384;

	public FileUnscrambler() throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
		digester = MessageDigest.getInstance("SHA-256");
	}

	public long decrypt(File[] infiles, byte[] passphrase, File destfile) throws IOException,
			NoSuchAlgorithmException, InvalidParameterSpecException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		long totalBytes = calculateTotalBytes(infiles);
		
		FileOutputStream fos = new FileOutputStream(destfile);
		
		BufferedInputStream bis = createInputStream(infiles);

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
		
		int totalMB = (int)(totalBytes/(1024*1024));
		
		ProgressMonitor monitor = new ProgressMonitor(null, "Decrypting " + totalMB + " MB of data", 
				"Copying ...", 0, totalMB);
		
		long bytesCopied = copyStream(cis, fos, monitor);
		
		cis.close();
		fos.close();
		
		monitor.close();
		
		return bytesCopied;
	}
	
	private long calculateTotalBytes(File[] files) {
		long total = 0;
		
		for (int i = 0; i < files.length; i++)
			total += files[i].length();
		
		return total;
	}
	
	private BufferedInputStream createInputStream(File[] files) throws IOException {
		Vector<InputStream> streams = new Vector<InputStream>(files.length);
		
		for (int i = 0; i < files.length; i++)
			streams.add(new FileInputStream(files[i]));
		
		SequenceInputStream sis = new SequenceInputStream(streams.elements());
		
		return new BufferedInputStream(sis);
	}

	private long copyStream(InputStream is, OutputStream os, final ProgressMonitor monitor) throws IOException {
		byte[] buf = new byte[DEFAULT_BUFFER_SIZE];

		int len;
		long totlen = 0;
		int totMB = 0;
		int lastTotMB = 0;

		while ((len = is.read(buf)) > 0) {
			if (os != null)
				os.write(buf, 0, len);
			
			totlen += len;
			
			totMB = (int)(totlen/(1024*1024));
			
			if (totMB > lastTotMB) {
				final int value = totMB;
				
				SwingUtilities.invokeLater(new Runnable() {
					public void run() {
						monitor.setProgress(value);
						monitor.setNote("Copied " + value + " MB");
					}
				});
				
				lastTotMB = totMB;
			}
		}

		return totlen;
	}
	
	public static void main(String[] args) {
		try {
			File[] files = null;
			File destfile = null;

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
			
			JFileChooser chooser = new JFileChooser();
			
			chooser.setMultiSelectionEnabled(false);
			
			File cwd = new File(System.getProperty("user.dir"));
			chooser.setCurrentDirectory(cwd);
			
			chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

			int returnVal = chooser.showOpenDialog(null);

			if (returnVal == JFileChooser.APPROVE_OPTION)
				destfile = chooser.getSelectedFile();
			else
				destfile = null;	
			
			FileUnscrambler decrypter = new FileUnscrambler();

			String s = (String) JOptionPane.showInputDialog(null,
					"Enter the passphrase for decryption",
					"Enter your passphrase", JOptionPane.PLAIN_MESSAGE, null,
					null, null);

			byte[] passphrase = s.getBytes();
				
			long bytesCopied = decrypter.decrypt(files, passphrase, destfile);
			
			String message = "Bytes copied: " + bytesCopied;
			
			System.err.println(message);
			
			JOptionPane.showMessageDialog(null, message,
					"File decrypted", JOptionPane.INFORMATION_MESSAGE);

			System.exit(0);
		} catch (Exception e) {
			showExceptionDialog(e);
		}
	}

	private static void showExceptionDialog(Exception e) {
		String title = "A " + e.getClass().getName() + " occurred";
		
		StringBuffer sb = new StringBuffer();
		
		sb.append("A "+ e.getClass() + " occurred:\n");
		sb.append(e.getMessage() + "\n\n");
		
		StackTraceElement[] ste = e.getStackTrace();
		
		for (int i = 0; i < ste.length; i++)
			sb.append("  [" + i + "]: " + ste[i] + "\n");
		
		String message = sb.toString();
		
		JOptionPane.showMessageDialog(null, message, title, JOptionPane.ERROR_MESSAGE);
	}
}
