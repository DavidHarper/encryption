package com.obliquity.encryption;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ZipArchiveHandler extends AbstractArchiveHandler {
	public void processArchive(InputStream is, EncryptedFileReader reader, File destdir) throws IOException {
		ZipInputStream zis = new ZipInputStream(is);

		ZipEntry entry = null;

		while ((entry = zis.getNextEntry()) != null) {
			String entryName = entry.getName();
			long size = entry.getSize();
			Date modified = new Date(entry.getTime());

			if (entry.isDirectory()) {
				reader.processDirectoryEntry(entryName, modified, destdir);
			} else {
				reader.processFileEntry(entryName, modified, size, zis, destdir);
			}
		}
		
		zis.close();
	}

}
