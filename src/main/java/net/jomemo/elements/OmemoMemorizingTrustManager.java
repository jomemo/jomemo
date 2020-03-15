package net.jomemo.elements;

import java.security.cert.X509Certificate;

public interface OmemoMemorizingTrustManager {

	void checkClientTrusted(X509Certificate[] key, String rsa);
}
