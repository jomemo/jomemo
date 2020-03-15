package net.jomemo.axolotl;

public class CryptoFailedException extends Exception {
	public CryptoFailedException(final Exception ex) {
		super(ex);
	}
}
