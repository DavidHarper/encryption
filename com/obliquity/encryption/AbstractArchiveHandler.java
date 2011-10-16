package com.obliquity.encryption;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public abstract class AbstractArchiveHandler {
	public abstract void processArchive(InputStream is, EncryptedFileReader reader, File destdir) throws IOException;
}
