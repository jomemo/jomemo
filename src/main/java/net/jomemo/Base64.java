package net.jomemo;

//import android.util.Base64;
import javax.xml.bind.DatatypeConverter;

/**
 * TODO
 * NOTE in Java 1.8+ we can use java.util.Base64
 * NOTE on Android we can use android.util.Base64
 */
public final class Base64 {

	private Base64() {}

	public static String encode(final byte[] input, final boolean noWrap) {

		final String encoded;
//		if (noWrap) {
//			encoded = Base64.encodeToString(input, Base64.NO_WRAP);
//		} else {
//			encoded = Base64.encodeToString(input, Base64.DEFAULT);
//		}
		encoded = DatatypeConverter.printBase64Binary(input);
		return encoded;
	}

	public static String encode(final byte[] input) {
		return encode(input, false);
	}

	public static byte[] decode(final String input, final boolean noWrap) {

		final byte[] decoded;
//		if (noWrap) {
//			decoded = Base64.decode(input, Base64.NO_WRAP);
//		} else {
//			decoded = Base64.decode(input, Base64.DEFAULT);
//		}
		decoded = DatatypeConverter.parseBase64Binary(input);
		return decoded;
	}

	public static byte[] decode(final String input) {
		return decode(input, false);
	}
}
