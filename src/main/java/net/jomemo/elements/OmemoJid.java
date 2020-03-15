package net.jomemo.elements;

public abstract class OmemoJid {

	public static String LOGPREFIX = null;
	public static String PEP_PREFIX = null;

	public static String getLogprefix(OmemoAccount account) { throw new UnsupportedOperationException(); }

	public static OmemoJid fromString(final String jid) throws OmemoInvalidJidException { throw new UnsupportedOperationException(); }

	public OmemoJid toBareJid() { throw new UnsupportedOperationException(); }
}
