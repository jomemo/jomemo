package net.jomemo.elements;

import java.net.URL;

public interface OmemoMessage {

	int STATUS_SEND_FAILED = 3;

	class FileParams {
		public URL url;
		public long size = 0;
		public int width = 0;
		public int height = 0;
	}

	boolean hasFileOnRemoteHost();

	FileParams getFileParams();

	String getBody();

	String getUuid();

	OmemoContact getContact();
}
