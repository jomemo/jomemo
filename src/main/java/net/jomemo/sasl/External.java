//package net.jomemo.sasl;
//
//import java.security.SecureRandom;
//
//import eu.siacs.conversations.entities.Account;
//import eu.siacs.conversations.xml.TagWriter;
//import net.jomemo.Base64;
//
//public class External extends SaslMechanism {
//
//	public External(TagWriter tagWriter, Account account, SecureRandom rng) {
//		super(tagWriter, account, rng);
//	}
//
//	@Override
//	public int getPriority() {
//		return 25;
//	}
//
//	@Override
//	public String getMechanism() {
//		return "EXTERNAL";
//	}
//
//	@Override
//	public String getClientFirstMessage() {
//		return Base64.encode(account.getJid().toBareJid().toString().getBytes(),true);
//	}
//}
