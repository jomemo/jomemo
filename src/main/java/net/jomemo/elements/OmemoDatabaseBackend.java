package net.jomemo.elements;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import net.jomemo.axolotl.XmppAxolotlSession;
import org.whispersystems.libaxolotl.AxolotlAddress;
import org.whispersystems.libaxolotl.IdentityKey;
import org.whispersystems.libaxolotl.IdentityKeyPair;
import org.whispersystems.libaxolotl.state.PreKeyRecord;
import org.whispersystems.libaxolotl.state.SessionRecord;
import org.whispersystems.libaxolotl.state.SignedPreKeyRecord;

public interface OmemoDatabaseBackend {

	void storeOwnIdentityKeyPair(OmemoAccount account, IdentityKeyPair ownKey);

	IdentityKeyPair loadOwnIdentityKeyPair(OmemoAccount account);

	void storeSession(OmemoAccount account, AxolotlAddress address, SessionRecord record);

	boolean containsPreKey(OmemoAccount account, int preKeyId);

	SignedPreKeyRecord loadSignedPreKey(OmemoAccount account, int signedPreKeyId);

	boolean containsSession(OmemoAccount account, AxolotlAddress address);

	void storePreKey(OmemoAccount account, PreKeyRecord record);

	void updateAccount(OmemoAccount account);

	void storeSignedPreKey(OmemoAccount account, SignedPreKeyRecord record);

	List<SignedPreKeyRecord> loadSignedPreKeys(OmemoAccount account);

	List<Integer> getSubDeviceSessions(OmemoAccount account, AxolotlAddress axolotlAddress);

	void setIdentityKeyCertificate(OmemoAccount account, String fingerprint, X509Certificate x509Certificate);

	void setIdentityKeyTrust(OmemoAccount account, String fingerprint, XmppAxolotlSession.Trust trust);

	X509Certificate getIdentityKeyCertifcate(OmemoAccount account, String fingerprint);

	Set<IdentityKey> loadIdentityKeys(OmemoAccount account, String bareJid, XmppAxolotlSession.Trust trust);

	void deleteAllSessions(OmemoAccount account, AxolotlAddress address);

	PreKeyRecord loadPreKey(OmemoAccount account, int preKeyId);

	boolean containsSignedPreKey(OmemoAccount account, int signedPreKeyId);

	void deletePreKey(OmemoAccount account, int preKeyId);

	Collection<IdentityKey> loadIdentityKeys(OmemoAccount account, String name);

	void storeIdentityKey(OmemoAccount account, String name, IdentityKey identityKey);

	XmppAxolotlSession.Trust isIdentityKeyTrusted(OmemoAccount account, String fingerprint);

	void wipeAxolotlDb(OmemoAccount account);

	void deleteSignedPreKey(OmemoAccount account, int signedPreKeyId);

	SessionRecord loadSession(OmemoAccount account, AxolotlAddress address);

	void deleteSession(OmemoAccount account, AxolotlAddress address);

	long numTrustedKeys(OmemoAccount account, String bareJid);
}
