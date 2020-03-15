//package net.jomemo.sasl;
//
//import java.nio.charset.Charset;
//
//import eu.siacs.conversations.entities.Account;
//import eu.siacs.conversations.xml.TagWriter;
//import net.jomemo.Base64;
//
//public class Plain extends SaslMechanism {
//	public Plain(final TagWriter tagWriter, final Account account) {
//		super(tagWriter, account, null);
//	}
//
//	@Override
//	public int getPriority() {
//		return 10;
//	}
//
//	@Override
//	public String getMechanism() {
//		return "PLAIN";
//	}
//
//	@Override
//	public String getClientFirstMessage() {
//		final String sasl = '\u0000' + account.getUsername() + '\u0000' + account.getPassword();
//		return Base64.encode(sasl.getBytes(Charset.defaultCharset()), true);
//	}
//}
