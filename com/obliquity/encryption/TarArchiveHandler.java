package com.obliquity.encryption;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.zip.GZIPInputStream;

import org.apache.tools.tar.TarEntry;
import org.apache.tools.tar.TarInputStream;

public class TarArchiveHandler extends AbstractArchiveHandler {
	private boolean compressed;
	
	public TarArchiveHandler(boolean compressed) {
		this.compressed = compressed;
	}
	
	public void processArchive(InputStream is, EncryptedFileReader reader,
			File destdir) throws IOException {
		InputStream is2 = compressed ? new GZIPInputStream(is) : is;

		TarInputStream tis = new TarInputStream(is2);

		TarEntry entry = null;
		
		while ((entry = tis.getNextEntry()) != null) {
			String entryName = entry.getName();
			long size = entry.getSize();
			Date modified = entry.getModTime();

			if (entry.isDirectory())
				reader.processDirectoryEntry(entryName, modified, destdir);
			else
				reader.processFileEntry(entryName, modified, size, tis, destdir);
		}

		tis.close();
	}

}
