//package net.jomemo;
//
////import android.util.Log;
////import android.util.Pair;
//
//import org.bouncycastle.asn1.ASN1Primitive;
//import org.bouncycastle.asn1.DERIA5String;
//import org.bouncycastle.asn1.DERTaggedObject;
//import org.bouncycastle.asn1.DERUTF8String;
//import org.bouncycastle.asn1.DLSequence;
//import org.bouncycastle.asn1.x500.RDN;
//import org.bouncycastle.asn1.x500.X500Name;
//import org.bouncycastle.asn1.x500.style.BCStyle;
//import org.bouncycastle.asn1.x500.style.IETFUtils;
//import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
//
//import java.io.IOException;
//import java.security.cert.Certificate;
//import java.security.cert.X509Certificate;
//import java.util.AbstractMap;
//import java.util.ArrayList;
//import java.util.Collection;
//import java.util.List;
//import java.util.Map;
//
//import javax.net.ssl.HostnameVerifier;
//import javax.net.ssl.SSLSession;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//
//public class XmppDomainVerifier implements HostnameVerifier {
//
//	private static final String LOGTAG = "XmppDomainVerifier";
//
//	private final String SRVName = "1.3.6.1.5.5.7.8.7";
//	private final String xmppAddr = "1.3.6.1.5.5.7.8.5";
//
//	private static final Logger logger = LoggerFactory.getLogger(XmppDomainVerifier.class);
//
//	@Override
//	public boolean verify(String domain, SSLSession sslSession) {
//		try {
//			Certificate[] chain = sslSession.getPeerCertificates();
//			if (chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
//				return false;
//			}
//			X509Certificate certificate = (X509Certificate) chain[0];
//			Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
//			List<String> xmppAddrs = new ArrayList<String>();
//			List<String> srvNames = new ArrayList<String>();
//			List<String> domains = new ArrayList<String>();
//			if (alternativeNames != null) {
//				for (List<?> san : alternativeNames) {
//					Integer type = (Integer) san.get(0);
//					if (type == 0) {
//						Map.Entry<String, String> otherName = parseOtherName((byte[]) san.get(1));
//						if (otherName != null) {
//							switch (otherName.getKey()) {
//								case SRVName:
//									srvNames.add(otherName.getValue());
//									break;
//								case xmppAddr:
//									xmppAddrs.add(otherName.getValue());
//									break;
//								default:
//									logger.debug(LOGTAG, "oid: " + otherName.getKey() + " value: " + otherName.getValue());
//							}
//						}
//					} else if (type == 2) {
//						Object value = san.get(1);
//						if (value instanceof String) {
//							domains.add((String) value);
//						}
//					}
//				}
//			}
//			if (srvNames.size() == 0 && xmppAddrs.size() == 0 && domains.size() == 0) {
//				X500Name x500name = new JcaX509CertificateHolder(certificate).getSubject();
//				RDN[] rdns = x500name.getRDNs(BCStyle.CN);
//				for (int i = 0; i < rdns.length; ++i) {
//					domains.add(IETFUtils.valueToString(x500name.getRDNs(BCStyle.CN)[i].getFirst().getValue()));
//				}
//			}
//			logger.debug(LOGTAG, "searching for " + domain + " in srvNames: " + srvNames + " xmppAddrs: " + xmppAddrs + " domains:" + domains);
//			return xmppAddrs.contains(domain) || srvNames.contains("_xmpp-client." + domain) || matchDomain(domain, domains);
//		} catch (Exception e) {
//			return false;
//		}
//	}
//
//	private static Map.Entry<String, String> parseOtherName(byte[] otherName) {
//		try {
//			ASN1Primitive asn1Primitive = ASN1Primitive.fromByteArray(otherName);
//			if (asn1Primitive instanceof DERTaggedObject) {
//				ASN1Primitive inner = ((DERTaggedObject) asn1Primitive).getObject();
//				if (inner instanceof DLSequence) {
//					DLSequence sequence = (DLSequence) inner;
//					if (sequence.size() >= 2 && sequence.getObjectAt(1) instanceof DERTaggedObject) {
//						String oid = sequence.getObjectAt(0).toString();
//						ASN1Primitive value = ((DERTaggedObject) sequence.getObjectAt(1)).getObject();
//						if (value instanceof DERUTF8String) {
//							return new AbstractMap.SimpleImmutableEntry<String, String>(oid, ((DERUTF8String) value).getString());
//						} else if (value instanceof DERIA5String) {
//							return new AbstractMap.SimpleImmutableEntry<String, String>(oid, ((DERIA5String) value).getString());
//						}
//					}
//				}
//			}
//			return null;
//		} catch (IOException e) {
//			return null;
//		}
//	}
//
//	private static boolean matchDomain(String needle, List<String> haystack) {
//		for (String entry : haystack) {
//			if (entry.startsWith("*.")) {
//				int i = needle.indexOf('.');
//				logger.debug(LOGTAG, "comparing " + needle.substring(i) + " and " + entry.substring(1));
//				if (i != -1 && needle.substring(i).equals(entry.substring(1))) {
//					logger.debug(LOGTAG, "domain " + needle + " matched " + entry);
//					return true;
//				}
//			} else {
//				if (entry.equals(needle)) {
//					logger.debug(LOGTAG, "domain " + needle + " matched " + entry);
//					return true;
//				}
//			}
//		}
//		return false;
//	}
//}
