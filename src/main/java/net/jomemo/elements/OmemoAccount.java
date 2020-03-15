package net.jomemo.elements;

public interface OmemoAccount {

	boolean setKey(String keyId, String value);

	String getKey(String keyId);

	OmemoJid getJid();

	OmemoRoster getRoster();

	String getPrivateKeyAlias();

	OmemoXmppConnection getXmppConnection();
}
