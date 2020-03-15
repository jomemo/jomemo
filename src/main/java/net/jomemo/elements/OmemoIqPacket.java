package net.jomemo.elements;

public interface OmemoIqPacket {

	enum TYPE {
		ERROR,
		SET,
		RESULT,
		GET,
		INVALID,
		TIMEOUT
	}

	TYPE getType();

	OmemoElement findChild(String error);
}
