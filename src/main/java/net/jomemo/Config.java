package net.jomemo;

import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/**
 * TODO
 */
public final class Config {

	private Config() {}

	public static final Marker LOGTAG = MarkerFactory.getDetachedMarker("XXX");
	public static final boolean X509_VERIFICATION = true; // FIXME arbitrary, fixed value!
}
