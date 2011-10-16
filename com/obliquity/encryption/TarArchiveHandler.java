package com.obliquity.encryption;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.zip.GZIPInputStream;

import org.apache.tools.tar.TarEntry;
import org.apache.tools.tar.TarInputStream;

public class TarArchiveHandler extends AbstractArchiveHandler {
	public void processArchive(InputStream is, EncryptedFileReader reader,
			File destdir) throws IOException {
		GZIPInputStream gis = new GZIPInputStream(is);

		TarInputStream tis = new TarInputStream(gis);

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
