package net.jomemo.axolotl;

//import android.security.KeyChain;
//import android.support.annotation.NonNull;
//import android.support.annotation.Nullable;
//import android.util.Log;
//import android.util.Pair;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.whispersystems.libaxolotl.AxolotlAddress;
import org.whispersystems.libaxolotl.IdentityKey;
import org.whispersystems.libaxolotl.IdentityKeyPair;
import org.whispersystems.libaxolotl.InvalidKeyException;
import org.whispersystems.libaxolotl.InvalidKeyIdException;
import org.whispersystems.libaxolotl.SessionBuilder;
import org.whispersystems.libaxolotl.UntrustedIdentityException;
import org.whispersystems.libaxolotl.ecc.ECPublicKey;
import org.whispersystems.libaxolotl.state.PreKeyBundle;
import org.whispersystems.libaxolotl.state.PreKeyRecord;
import org.whispersystems.libaxolotl.state.SignedPreKeyRecord;
import org.whispersystems.libaxolotl.util.KeyHelper;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

//import eu.siacs.conversations.Config;
//import eu.siacs.conversations.entities.OmemoAccount;
//import eu.siacs.conversations.entities.OmemoContact;
//import eu.siacs.conversations.entities.Conversation;
//import eu.siacs.conversations.entities.OmemoMessage;
//import eu.siacs.conversations.parser.OmemoIqParser;
//import eu.siacs.conversations.services.OmemoXmppConnectionService;
//import eu.siacs.conversations.utils.SerialSingleThreadExecutor;
//import eu.siacs.conversations.xml.OmemoElement;
//import eu.siacs.conversations.xmpp.OmemoOnAdvancedStreamFeaturesLoaded;
//import eu.siacs.conversations.xmpp.OmemoOnIqPacketReceived;
//import eu.siacs.conversations.xmpp.jid.OmemoInvalidJidException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
//import eu.siacs.conversations.xmpp.jid.OmemoJid;
//import eu.siacs.conversations.xmpp.stanzas.OmemoIqPacket;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.jomemo.Config;
import net.jomemo.elements.OmemoElement;
import net.jomemo.elements.OmemoInvalidJidException;
import net.jomemo.elements.OmemoJid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.jomemo.elements.OmemoAccount;
import net.jomemo.elements.OmemoContact;
import net.jomemo.elements.OmemoMessage;
import net.jomemo.elements.OmemoIqParser;
import net.jomemo.elements.OmemoIqPacket;
import net.jomemo.elements.OmemoOnAdvancedStreamFeaturesLoaded;
import net.jomemo.elements.OmemoOnIqPacketReceived;
import net.jomemo.elements.OmemoXmppConnectionService;

public class AxolotlService implements OmemoOnAdvancedStreamFeaturesLoaded {

	public static final String PEP_PREFIX = "eu.siacs.conversations.axolotl";
	public static final String PEP_DEVICE_LIST = PEP_PREFIX + ".devicelist";
	public static final String PEP_BUNDLES = PEP_PREFIX + ".bundles";
	public static final String PEP_VERIFICATION = PEP_PREFIX + ".verification";

	public static final String LOGPREFIX = "AxolotlService";

	public static final int NUM_KEYS_TO_PUBLISH = 100;
	public static final int publishTriesThreshold = 3;

	private static final Logger logger = LoggerFactory.getLogger(AxolotlService.class);

	private final OmemoAccount account;
	private final OmemoXmppConnectionService mXmppConnectionService;
	private final SQLiteAxolotlStore axolotlStore;
	private final SessionMap sessions;
	private final Map<OmemoJid, Set<Integer>> deviceIds;
	private final Map<String, XmppAxolotlMessage> messageCache;
	private final FetchStatusMap fetchStatusMap;
	private final Executor executor;
	private int numPublishTriesOnEmptyPep = 0;
	private boolean pepBroken = false;

	@Override
	public void onAdvancedStreamFeaturesAvailable(OmemoAccount account) {
		if (account.getXmppConnection() != null && account.getXmppConnection().getFeatures().pep()) {
			publishBundlesIfNeeded(true, false);
		} else {
			logger.debug(Config.LOGTAG, "{}: skipping OMEMO initialization", account.getJid().toBareJid());
		}
	}

	public boolean fetchMapHasErrors(OmemoContact contact) {
		OmemoJid jid = contact.getJid().toBareJid();
		if (deviceIds.get(jid) != null) {
			for (Integer foreignId : this.deviceIds.get(jid)) {
				AxolotlAddress address = new AxolotlAddress(jid.toString(), foreignId);
				if (fetchStatusMap.getAll(address).containsValue(FetchStatus.ERROR)) {
					return true;
				}
			}
		}
		return false;
	}

	private static class AxolotlAddressMap<T> {
		protected Map<String, Map<Integer, T>> map;
		protected final Object MAP_LOCK = new Object();

		AxolotlAddressMap() {
			this.map = new HashMap<String, Map<Integer, T>>();
		}

		public void put(AxolotlAddress address, T value) {
			synchronized (MAP_LOCK) {
				Map<Integer, T> devices = map.get(address.getName());
				if (devices == null) {
					devices = new HashMap<Integer, T>();
					map.put(address.getName(), devices);
				}
				devices.put(address.getDeviceId(), value);
			}
		}

		public T get(AxolotlAddress address) {
			synchronized (MAP_LOCK) {
				Map<Integer, T> devices = map.get(address.getName());
				if (devices == null) {
					return null;
				}
				return devices.get(address.getDeviceId());
			}
		}

		public Map<Integer, T> getAll(AxolotlAddress address) {
			synchronized (MAP_LOCK) {
				Map<Integer, T> devices = map.get(address.getName());
				if (devices == null) {
					return new HashMap<Integer, T>();
				}
				return devices;
			}
		}

		public boolean hasAny(AxolotlAddress address) {
			synchronized (MAP_LOCK) {
				Map<Integer, T> devices = map.get(address.getName());
				return devices != null && !devices.isEmpty();
			}
		}

		public void clear() {
			map.clear();
		}

	}

	private static class SessionMap extends AxolotlAddressMap<XmppAxolotlSession> {

		private final OmemoXmppConnectionService xmppConnectionService;
		private final OmemoAccount account;

		SessionMap(OmemoXmppConnectionService service, SQLiteAxolotlStore store, OmemoAccount account) {
			super();
			this.xmppConnectionService = service;
			this.account = account;
			this.fillMap(store);
		}

		private void putDevicesForJid(String bareJid, List<Integer> deviceIds, SQLiteAxolotlStore store) {
			for (Integer deviceId : deviceIds) {
				AxolotlAddress axolotlAddress = new AxolotlAddress(bareJid, deviceId);
				logger.debug(Config.LOGTAG,
						"{}Building session for remote address: {}",
						OmemoJid.getLogprefix(account),
						axolotlAddress.toString());
				IdentityKey identityKey = store.loadSession(axolotlAddress).getSessionState().getRemoteIdentityKey();
				this.put(axolotlAddress, new XmppAxolotlSession(account, store, axolotlAddress, identityKey));
			}
		}

		private void fillMap(SQLiteAxolotlStore store) {
			List<Integer> deviceIds = store.getSubDeviceSessions(account.getJid().toBareJid().toString());
			putDevicesForJid(account.getJid().toBareJid().toString(), deviceIds, store);
			for (OmemoContact contact : account.getRoster().getContacts()) {
				OmemoJid bareJid = contact.getJid().toBareJid();
				String address = bareJid.toString();
				deviceIds = store.getSubDeviceSessions(address);
				putDevicesForJid(address, deviceIds, store);
			}

		}

		@Override
		public void put(AxolotlAddress address, XmppAxolotlSession value) {
			super.put(address, value);
			value.setNotFresh();
			xmppConnectionService.syncRosterToDisk(account);
		}

		public void put(XmppAxolotlSession session) {
			this.put(session.getRemoteAddress(), session);
		}
	}

	public enum FetchStatus {
		PENDING,
		SUCCESS,
		SUCCESS_VERIFIED,
		TIMEOUT,
		ERROR
	}

	private static class FetchStatusMap extends AxolotlAddressMap<FetchStatus> {

	}

	public static String getLogprefix(OmemoAccount account) {
		return LOGPREFIX + " (" + account.getJid().toBareJid().toString() + "): ";
	}

	public AxolotlService(OmemoAccount account, OmemoXmppConnectionService connectionService) {
//		if (Security.getProvider("BC") == null) {
//			Security.addProvider(new BouncyCastleProvider());
//		}
		if (Security.getProvider("SC") == null) {
			Security.insertProviderAt(new BouncyCastleProvider(), 1);
		}
		this.mXmppConnectionService = connectionService;
		this.account = account;
		this.axolotlStore = new SQLiteAxolotlStore(this.account, this.mXmppConnectionService);
		this.deviceIds = new HashMap<OmemoJid, Set<Integer>>();
		this.messageCache = new HashMap<String, XmppAxolotlMessage>();
		this.sessions = new SessionMap(mXmppConnectionService, axolotlStore, account);
		this.fetchStatusMap = new FetchStatusMap();
//		this.executor = new SerialSingleThreadExecutor(); // XXX Why did they do this in Conversations? can't see what their SerialSingleThreadExecutor does differently then the next line:
		this.executor = Executors.newSingleThreadExecutor();
	}

	public String getOwnFingerprint() {
		return axolotlStore.getIdentityKeyPair().getPublicKey().getFingerprint().replaceAll("\\s", "");
	}

	public Set<IdentityKey> getKeysWithTrust(XmppAxolotlSession.Trust trust) {
		return axolotlStore.getContactKeysWithTrust(account.getJid().toBareJid().toString(), trust);
	}

	public Set<IdentityKey> getKeysWithTrust(XmppAxolotlSession.Trust trust, OmemoContact contact) {
		return axolotlStore.getContactKeysWithTrust(contact.getJid().toBareJid().toString(), trust);
	}

	public long getNumTrustedKeys(OmemoContact contact) {
		return axolotlStore.getContactNumTrustedKeys(contact.getJid().toBareJid().toString());
	}

	private AxolotlAddress getAddressForJid(OmemoJid jid) {
		return new AxolotlAddress(jid.toString(), 0);
	}

	private Set<XmppAxolotlSession> findOwnSessions() {
		AxolotlAddress ownAddress = getAddressForJid(account.getJid().toBareJid());
		return new HashSet<XmppAxolotlSession>(this.sessions.getAll(ownAddress).values());
	}

	private Set<XmppAxolotlSession> findSessionsforContact(OmemoContact contact) {
		AxolotlAddress contactAddress = getAddressForJid(contact.getJid());
		return new HashSet<XmppAxolotlSession>(this.sessions.getAll(contactAddress).values());
	}

	public Set<String> getFingerprintsForOwnSessions() {
		Set<String> fingerprints = new HashSet<String>();
		for (XmppAxolotlSession session : findOwnSessions()) {
			fingerprints.add(session.getFingerprint());
		}
		return fingerprints;
	}

	public Set<String> getFingerprintsForContact(final OmemoContact contact) {
		Set<String> fingerprints = new HashSet<String>();
		for (XmppAxolotlSession session : findSessionsforContact(contact)) {
			fingerprints.add(session.getFingerprint());
		}
		return fingerprints;
	}

	private boolean hasAny(OmemoContact contact) {
		AxolotlAddress contactAddress = getAddressForJid(contact.getJid());
		return sessions.hasAny(contactAddress);
	}

	public boolean isPepBroken() {
		return this.pepBroken;
	}

	public void regenerateKeys(boolean wipeOther) {
		axolotlStore.regenerate();
		sessions.clear();
		fetchStatusMap.clear();
		publishBundlesIfNeeded(true, wipeOther);
	}

	public int getOwnDeviceId() {
		return axolotlStore.getLocalRegistrationId();
	}

	public Set<Integer> getOwnDeviceIds() {
		return this.deviceIds.get(account.getJid().toBareJid());
	}

	private void setTrustOnSessions(final OmemoJid jid, @Nonnull final Set<Integer> deviceIds,
	                                final XmppAxolotlSession.Trust from,
	                                final XmppAxolotlSession.Trust to)
	{
		for (Integer deviceId : deviceIds) {
			AxolotlAddress address = new AxolotlAddress(jid.toBareJid().toString(), deviceId);
			XmppAxolotlSession session = sessions.get(address);
			if (session != null && session.getFingerprint() != null
					&& session.getTrust() == from)
			{
				session.setTrust(to);
			}
		}
	}

	public void registerDevices(final OmemoJid jid, @Nonnull final Set<Integer> deviceIds) {
		if (jid.toBareJid().equals(account.getJid().toBareJid())) {
			if (!deviceIds.isEmpty()) {
				logger.debug(Config.LOGTAG,
						"{}Received non-empty own device list. Resetting publish attemps and pepBroken status.",
						getLogprefix(account));
				pepBroken = false;
				numPublishTriesOnEmptyPep = 0;
			}
			if (deviceIds.contains(getOwnDeviceId())) {
				deviceIds.remove(getOwnDeviceId());
			} else {
				publishOwnDeviceId(deviceIds);
			}
			for (Integer deviceId : deviceIds) {
				AxolotlAddress ownDeviceAddress = new AxolotlAddress(jid.toBareJid().toString(), deviceId);
				if (sessions.get(ownDeviceAddress) == null) {
					buildSessionFromPEP(ownDeviceAddress);
				}
			}
		}
		Set<Integer> expiredDevices = new HashSet<Integer>(axolotlStore.getSubDeviceSessions(jid.toBareJid().toString()));
		expiredDevices.removeAll(deviceIds);
		setTrustOnSessions(jid, expiredDevices, XmppAxolotlSession.Trust.TRUSTED,
				XmppAxolotlSession.Trust.INACTIVE_TRUSTED);
		setTrustOnSessions(jid, expiredDevices, XmppAxolotlSession.Trust.TRUSTED_X509,
				XmppAxolotlSession.Trust.INACTIVE_TRUSTED_X509);
		setTrustOnSessions(jid, expiredDevices, XmppAxolotlSession.Trust.UNDECIDED,
				XmppAxolotlSession.Trust.INACTIVE_UNDECIDED);
		setTrustOnSessions(jid, expiredDevices, XmppAxolotlSession.Trust.UNTRUSTED,
				XmppAxolotlSession.Trust.INACTIVE_UNTRUSTED);
		Set<Integer> newDevices = new HashSet<Integer>(deviceIds);
		setTrustOnSessions(jid, newDevices, XmppAxolotlSession.Trust.INACTIVE_TRUSTED,
				XmppAxolotlSession.Trust.TRUSTED);
		setTrustOnSessions(jid, newDevices, XmppAxolotlSession.Trust.INACTIVE_TRUSTED_X509,
				XmppAxolotlSession.Trust.TRUSTED_X509);
		setTrustOnSessions(jid, newDevices, XmppAxolotlSession.Trust.INACTIVE_UNDECIDED,
				XmppAxolotlSession.Trust.UNDECIDED);
		setTrustOnSessions(jid, newDevices, XmppAxolotlSession.Trust.INACTIVE_UNTRUSTED,
				XmppAxolotlSession.Trust.UNTRUSTED);
		this.deviceIds.put(jid, deviceIds);
		mXmppConnectionService.keyStatusUpdated(null);
	}

	public void wipeOtherPepDevices() {
		if (pepBroken) {
			logger.debug(Config.LOGTAG, "{}wipeOtherPepDevices called, but PEP is broken. Ignoring... ", getLogprefix(account));
			return;
		}
		Set<Integer> deviceIds = new HashSet<Integer>();
		deviceIds.add(getOwnDeviceId());
		OmemoIqPacket publish = mXmppConnectionService.getIqGenerator().publishDeviceIds(deviceIds);
		logger.debug(Config.LOGTAG, "{}Wiping all other devices from Pep:{}", OmemoJid.getLogprefix(account), publish);
		mXmppConnectionService.sendIqPacket(account, publish, new OmemoOnIqPacketReceived() {
			@Override
			public void onIqPacketReceived(OmemoAccount account, OmemoIqPacket packet) {
				// TODO: implement this!
			}
		});
	}

	public void purgeKey(final String fingerprint) {
		axolotlStore.setFingerprintTrust(fingerprint.replaceAll("\\s", ""), XmppAxolotlSession.Trust.COMPROMISED);
	}

	public void publishOwnDeviceIdIfNeeded() {
		if (pepBroken) {
			logger.debug(Config.LOGTAG, "{}publishOwnDeviceIdIfNeeded called, but PEP is broken. Ignoring... ", getLogprefix(account));
			return;
		}
		OmemoIqPacket packet = mXmppConnectionService.getIqGenerator().retrieveDeviceIds(account.getJid().toBareJid());
		mXmppConnectionService.sendIqPacket(account, packet, new OmemoOnIqPacketReceived() {
			@Override
			public void onIqPacketReceived(OmemoAccount account, OmemoIqPacket packet) {
				if (packet.getType() == OmemoIqPacket.TYPE.TIMEOUT) {
					logger.debug(Config.LOGTAG, "{}Timeout received while retrieving own Device Ids.", getLogprefix(account));
				} else {
					OmemoElement item = mXmppConnectionService.getIqParser().getItem(packet);
					Set<Integer> deviceIds = mXmppConnectionService.getIqParser().deviceIds(item);
					if (!deviceIds.contains(getOwnDeviceId())) {
						publishOwnDeviceId(deviceIds);
					}
				}
			}
		});
	}

	public void publishOwnDeviceId(Set<Integer> deviceIds) {
		Set<Integer> deviceIdsCopy = new HashSet<Integer>(deviceIds);
		if (!deviceIdsCopy.contains(getOwnDeviceId())) {
			logger.debug(Config.LOGTAG, "{}Own device {} not in PEP devicelist.", OmemoJid.getLogprefix(account), getOwnDeviceId());
			if (deviceIdsCopy.isEmpty()) {
				if (numPublishTriesOnEmptyPep >= publishTriesThreshold) {
					logger.warn(Config.LOGTAG, "{}Own device publish attempt threshold exceeded, aborting...", getLogprefix(account));
					pepBroken = true;
					return;
				} else {
					numPublishTriesOnEmptyPep++;
					logger.warn(Config.LOGTAG,
							"{}Own device list empty, attempting to publish (try {})",
							getLogprefix(account), numPublishTriesOnEmptyPep);
				}
			} else {
				numPublishTriesOnEmptyPep = 0;
			}
			deviceIdsCopy.add(getOwnDeviceId());
			OmemoIqPacket publish = mXmppConnectionService.getIqGenerator().publishDeviceIds(deviceIdsCopy);
			mXmppConnectionService.sendIqPacket(account, publish, new OmemoOnIqPacketReceived() {
				@Override
				public void onIqPacketReceived(OmemoAccount account, OmemoIqPacket packet) {
					if (packet.getType() != OmemoIqPacket.TYPE.RESULT) {
						logger.debug(Config.LOGTAG, "{}Error received while publishing own device id{}", getLogprefix(account), packet.findChild("error"));
					}
				}
			});
		}
	}

	public void publishDeviceVerificationAndBundle(final SignedPreKeyRecord signedPreKeyRecord,
												   final Set<PreKeyRecord> preKeyRecords,
												   final boolean announceAfter,
												   final boolean wipe)
	{
		try {
			// from here on: the Java 7 way
			final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			final char[] password = null;
			final PrivateKey x509PrivateKey = (PrivateKey) ks.getKey(account.getPrivateKeyAlias(), password);
			final X509Certificate[] chain = (X509Certificate[]) ks.getCertificateChain(account.getPrivateKeyAlias());

			// from here on: the Android way
			IdentityKey axolotlPublicKey = axolotlStore.getIdentityKeyPair().getPublicKey();
//			PrivateKey x509PrivateKey = KeyChain.getPrivateKey(mXmppConnectionService, account.getPrivateKeyAlias());
//			X509Certificate[] chain = KeyChain.getCertificateChain(mXmppConnectionService, account.getPrivateKeyAlias());
			Signature verifier = Signature.getInstance("sha256WithRSA");
			verifier.initSign(x509PrivateKey, mXmppConnectionService.getRNG());
			verifier.update(axolotlPublicKey.serialize());
			byte[] signature = verifier.sign();
			OmemoIqPacket packet = mXmppConnectionService.getIqGenerator().publishVerification(signature, chain, getOwnDeviceId());
			logger.debug(Config.LOGTAG,  "{}: publish verification for device {}", OmemoJid.getLogprefix(account), getOwnDeviceId());
			mXmppConnectionService.sendIqPacket(account, packet, new OmemoOnIqPacketReceived() {
				@Override
				public void onIqPacketReceived(OmemoAccount account, OmemoIqPacket packet) {
					publishDeviceBundle(signedPreKeyRecord, preKeyRecords, announceAfter, wipe);
				}
			});
		} catch (Exception  e) {
			e.printStackTrace();
		}
	}

	public void publishBundlesIfNeeded(final boolean announce, final boolean wipe) {
		if (pepBroken) {
			logger.debug(Config.LOGTAG, getLogprefix(account) + "publishBundlesIfNeeded called, but PEP is broken. Ignoring... ");
			return;
		}
		OmemoIqPacket packet = mXmppConnectionService.getIqGenerator().retrieveBundlesForDevice(account.getJid().toBareJid(), getOwnDeviceId());
		mXmppConnectionService.sendIqPacket(account, packet, new OmemoOnIqPacketReceived() {
			@Override
			public void onIqPacketReceived(OmemoAccount account, OmemoIqPacket packet) {

				if (packet.getType() == OmemoIqPacket.TYPE.TIMEOUT) {
					return; // ignore timeout. do nothing
				}

				if (packet.getType() == OmemoIqPacket.TYPE.ERROR) {
					OmemoElement error = packet.findChild("error");
					if (error == null || !error.hasChild("item-not-found")) {
						pepBroken = true;
						logger.warn(Config.LOGTAG, OmemoJid.getLogprefix(account) + "request for device bundles came back with something other than item-not-found" + packet);
						return;
					}
				}

				PreKeyBundle bundle = mXmppConnectionService.getIqParser().bundle(packet);
				Map<Integer, ECPublicKey> keys = mXmppConnectionService.getIqParser().preKeyPublics(packet);
				boolean flush = false;
				if (bundle == null) {
					logger.warn(Config.LOGTAG, "{}Received invalid bundle:{}", OmemoJid.getLogprefix(account), packet);
					bundle = new PreKeyBundle(-1, -1, -1, null, -1, null, null, null);
					flush = true;
				}
				if (keys == null) {
					logger.warn(Config.LOGTAG, "{}Received invalid prekeys:{}", OmemoJid.getLogprefix(account), packet);
				}
				try {
					boolean changed = false;
					// Validate IdentityKey
					IdentityKeyPair identityKeyPair = axolotlStore.getIdentityKeyPair();
					if (flush || !identityKeyPair.getPublicKey().equals(bundle.getIdentityKey())) {
						logger.info(Config.LOGTAG, "{}Adding own IdentityKey {} to PEP.", OmemoJid.getLogprefix(account), identityKeyPair.getPublicKey());
						changed = true;
					}

					// Validate signedPreKeyRecord + ID
					SignedPreKeyRecord signedPreKeyRecord;
					int numSignedPreKeys = axolotlStore.loadSignedPreKeys().size();
					try {
						signedPreKeyRecord = axolotlStore.loadSignedPreKey(bundle.getSignedPreKeyId());
						if (flush
								|| !bundle.getSignedPreKey().equals(signedPreKeyRecord.getKeyPair().getPublicKey())
								|| !Arrays.equals(bundle.getSignedPreKeySignature(), signedPreKeyRecord.getSignature()))
						{
							logger.info(Config.LOGTAG, "{}Adding new signedPreKey with ID {} to PEP.", OmemoJid.getLogprefix(account), (numSignedPreKeys + 1));
							signedPreKeyRecord = KeyHelper.generateSignedPreKey(identityKeyPair, numSignedPreKeys + 1);
							axolotlStore.storeSignedPreKey(signedPreKeyRecord.getId(), signedPreKeyRecord);
							changed = true;
						}
					} catch (InvalidKeyIdException e) {
						logger.info(Config.LOGTAG, OmemoJid.getLogprefix(account) + "Adding new signedPreKey with ID " + (numSignedPreKeys + 1) + " to PEP.");
						signedPreKeyRecord = KeyHelper.generateSignedPreKey(identityKeyPair, numSignedPreKeys + 1);
						axolotlStore.storeSignedPreKey(signedPreKeyRecord.getId(), signedPreKeyRecord);
						changed = true;
					}

					// Validate PreKeys
					Set<PreKeyRecord> preKeyRecords = new HashSet<PreKeyRecord>();
					if (keys != null) {
						for (Integer id : keys.keySet()) {
							try {
								PreKeyRecord preKeyRecord = axolotlStore.loadPreKey(id);
								if (preKeyRecord.getKeyPair().getPublicKey().equals(keys.get(id))) {
									preKeyRecords.add(preKeyRecord);
								}
							} catch (InvalidKeyIdException ignored) {
							}
						}
					}
					int newKeys = NUM_KEYS_TO_PUBLISH - preKeyRecords.size();
					if (newKeys > 0) {
						List<PreKeyRecord> newRecords = KeyHelper.generatePreKeys(
								axolotlStore.getCurrentPreKeyId() + 1, newKeys);
						preKeyRecords.addAll(newRecords);
						for (PreKeyRecord record : newRecords) {
							axolotlStore.storePreKey(record.getId(), record);
						}
						changed = true;
						logger.info(Config.LOGTAG, "{}Adding {} new preKeys to PEP.", OmemoJid.getLogprefix(account), newKeys);
					}


					if (changed) {
						if (account.getPrivateKeyAlias() != null && Config.X509_VERIFICATION) {
							mXmppConnectionService.publishDisplayName(account);
							publishDeviceVerificationAndBundle(signedPreKeyRecord, preKeyRecords, announce, wipe);
						} else {
							publishDeviceBundle(signedPreKeyRecord, preKeyRecords, announce, wipe);
						}
					} else {
						logger.debug(Config.LOGTAG, "{}Bundle {} in PEP was current", getLogprefix(account), getOwnDeviceId());
						if (wipe) {
							wipeOtherPepDevices();
						} else if (announce) {
							logger.debug(Config.LOGTAG, "{}Announcing device {}", getLogprefix(account), getOwnDeviceId());
							publishOwnDeviceIdIfNeeded();
						}
					}
				} catch (InvalidKeyException e) {
					logger.error(Config.LOGTAG, "{}Failed to publish bundle {}, reason: {}", OmemoJid.getLogprefix(account), getOwnDeviceId(), e.getMessage());
				}
			}
		});
	}

	private void publishDeviceBundle(SignedPreKeyRecord signedPreKeyRecord,
									 Set<PreKeyRecord> preKeyRecords,
									 final boolean announceAfter,
									 final boolean wipe)
	{
		OmemoIqPacket publish = mXmppConnectionService.getIqGenerator().publishBundles(
				signedPreKeyRecord, axolotlStore.getIdentityKeyPair().getPublicKey(),
				preKeyRecords, getOwnDeviceId());
		logger.debug(Config.LOGTAG, "{}: Bundle {} in PEP not current. Publishing: {}", OmemoJid.getLogprefix(account), getOwnDeviceId(), publish);
		mXmppConnectionService.sendIqPacket(account, publish, new OmemoOnIqPacketReceived() {
			@Override
			public void onIqPacketReceived(OmemoAccount account, OmemoIqPacket packet) {
				if (packet.getType() == OmemoIqPacket.TYPE.RESULT) {
					logger.debug(Config.LOGTAG, "{}Successfully published bundle.", OmemoJid.getLogprefix(account));
					if (wipe) {
						wipeOtherPepDevices();
					} else if (announceAfter) {
						logger.debug(Config.LOGTAG, "{}Announcing device {}", getLogprefix(account), getOwnDeviceId());
						publishOwnDeviceIdIfNeeded();
					}
				} else {
					logger.debug(Config.LOGTAG, "{}Error received while publishing bundle: {}", getLogprefix(account), packet.findChild("error"));
				}
			}
		});
	}

	public boolean isContactAxolotlCapable(OmemoContact contact) {
		OmemoJid jid = contact.getJid().toBareJid();
		return hasAny(contact) ||
				(deviceIds.containsKey(jid) && !deviceIds.get(jid).isEmpty());
	}

	public XmppAxolotlSession.Trust getFingerprintTrust(String fingerprint) {
		return axolotlStore.getFingerprintTrust(fingerprint);
	}

	public X509Certificate getFingerprintCertificate(String fingerprint) {
		return axolotlStore.getFingerprintCertificate(fingerprint);
	}

	public void setFingerprintTrust(String fingerprint, XmppAxolotlSession.Trust trust) {
		axolotlStore.setFingerprintTrust(fingerprint, trust);
	}

	private void verifySessionWithPEP(final XmppAxolotlSession session) {
		logger.debug(Config.LOGTAG, "trying to verify fresh session ({}) with pep", session.getRemoteAddress().getName());
		final AxolotlAddress address = session.getRemoteAddress();
		final IdentityKey identityKey = session.getIdentityKey();
		try {
			OmemoIqPacket packet = mXmppConnectionService.getIqGenerator().retrieveVerificationForDevice(OmemoJid.fromString(address.getName()), address.getDeviceId());
			mXmppConnectionService.sendIqPacket(account, packet, new OmemoOnIqPacketReceived() {
				@Override
				public void onIqPacketReceived(OmemoAccount account, OmemoIqPacket packet) {
					Map.Entry<X509Certificate[], byte[]> verification = mXmppConnectionService.getIqParser().verification(packet);
					if (verification != null) {
						try {
							Signature verifier = Signature.getInstance("sha256WithRSA");
							verifier.initVerify(verification.getKey()[0]);
							verifier.update(identityKey.serialize());
							if (verifier.verify(verification.getValue())) {
								try {
									mXmppConnectionService.getMemorizingTrustManager().checkClientTrusted(verification.getKey(), "RSA");
									String fingerprint = session.getFingerprint();
									logger.debug(Config.LOGTAG, "verified session with x.509 signature. fingerprint was: {}", fingerprint);
									setFingerprintTrust(fingerprint, XmppAxolotlSession.Trust.TRUSTED_X509);
									axolotlStore.setFingerprintCertificate(fingerprint, verification.getKey()[0]);
									fetchStatusMap.put(address, FetchStatus.SUCCESS_VERIFIED);
									finishBuildingSessionsFromPEP(address);
									return;
								} catch (Exception e) {
									logger.debug(Config.LOGTAG, "could not verify certificate");
								}
							}
						} catch (Exception e) {
							logger.debug(Config.LOGTAG, "error during verification {}", e.getMessage());
						}
					} else {
						logger.debug(Config.LOGTAG, "no verification found");
					}
					fetchStatusMap.put(address, FetchStatus.SUCCESS);
					finishBuildingSessionsFromPEP(address);
				}
			});
		} catch (OmemoInvalidJidException e) {
			fetchStatusMap.put(address, FetchStatus.SUCCESS);
			finishBuildingSessionsFromPEP(address);
		}
	}

	private void finishBuildingSessionsFromPEP(final AxolotlAddress address) {
		AxolotlAddress ownAddress = new AxolotlAddress(account.getJid().toBareJid().toString(), 0);
		if (!fetchStatusMap.getAll(ownAddress).containsValue(FetchStatus.PENDING)
				&& !fetchStatusMap.getAll(address).containsValue(FetchStatus.PENDING))
		{
			FetchStatus report = null;
			if (fetchStatusMap.getAll(ownAddress).containsValue(FetchStatus.SUCCESS_VERIFIED)
					| fetchStatusMap.getAll(address).containsValue(FetchStatus.SUCCESS_VERIFIED))
			{
				report = FetchStatus.SUCCESS_VERIFIED;
			} else if (fetchStatusMap.getAll(ownAddress).containsValue(FetchStatus.ERROR)
					|| fetchStatusMap.getAll(address).containsValue(FetchStatus.ERROR))
			{
				report = FetchStatus.ERROR;
			}
			mXmppConnectionService.keyStatusUpdated(report);
		}
	}

	private void buildSessionFromPEP(final AxolotlAddress address) {
		logger.info(Config.LOGTAG, "{}Building new sesstion for {}", OmemoJid.getLogprefix(account), address);
		if (address.getDeviceId() == getOwnDeviceId()) {
			throw new AssertionError("We should NEVER build a session with ourselves. What happened here?!");
		}

		try {
			OmemoIqPacket bundlesPacket = mXmppConnectionService.getIqGenerator().retrieveBundlesForDevice(OmemoJid.fromString(address.getName()), address.getDeviceId());
			logger.debug(Config.LOGTAG, "{}Retrieving bundle: {}", OmemoJid.getLogprefix(account), bundlesPacket);
			mXmppConnectionService.sendIqPacket(account, bundlesPacket, new OmemoOnIqPacketReceived() {

				@Override
				public void onIqPacketReceived(OmemoAccount account, OmemoIqPacket packet) {
					if (packet.getType() == OmemoIqPacket.TYPE.TIMEOUT) {
						fetchStatusMap.put(address, FetchStatus.TIMEOUT);
					} else if (packet.getType() == OmemoIqPacket.TYPE.RESULT) {
						logger.debug(Config.LOGTAG, "{}Received preKey IQ packet, processing...", OmemoJid.getLogprefix(account));
						final OmemoIqParser parser = mXmppConnectionService.getIqParser();
						final List<PreKeyBundle> preKeyBundleList = parser.preKeys(packet);
						final PreKeyBundle bundle = parser.bundle(packet);
						if (preKeyBundleList.isEmpty() || bundle == null) {
							logger.error(Config.LOGTAG, "{}preKey IQ packet invalid: {}", OmemoJid.getLogprefix(account), packet);
							fetchStatusMap.put(address, FetchStatus.ERROR);
							finishBuildingSessionsFromPEP(address);
							return;
						}
						Random random = new Random();
						final PreKeyBundle preKey = preKeyBundleList.get(random.nextInt(preKeyBundleList.size()));
						if (preKey == null) {
							//should never happen
							fetchStatusMap.put(address, FetchStatus.ERROR);
							finishBuildingSessionsFromPEP(address);
							return;
						}

						final PreKeyBundle preKeyBundle = new PreKeyBundle(0, address.getDeviceId(),
								preKey.getPreKeyId(), preKey.getPreKey(),
								bundle.getSignedPreKeyId(), bundle.getSignedPreKey(),
								bundle.getSignedPreKeySignature(), bundle.getIdentityKey());

						try {
							SessionBuilder builder = new SessionBuilder(axolotlStore, address);
							builder.process(preKeyBundle);
							XmppAxolotlSession session = new XmppAxolotlSession(account, axolotlStore, address, bundle.getIdentityKey());
							sessions.put(address, session);
							if (Config.X509_VERIFICATION) {
								verifySessionWithPEP(session);
							} else {
								fetchStatusMap.put(address, FetchStatus.SUCCESS);
								finishBuildingSessionsFromPEP(address);
							}
						} catch (UntrustedIdentityException e) {
							logger.error(Config.LOGTAG, "{}Error building session for {}: {}, {}", OmemoJid.getLogprefix(account), address, e.getClass().getName(), e.getMessage());
							fetchStatusMap.put(address, FetchStatus.ERROR);
							finishBuildingSessionsFromPEP(address);
						} catch (InvalidKeyException e) {
							logger.error(Config.LOGTAG, "{}Error building session for {}: {}, {}", OmemoJid.getLogprefix(account), address, e.getClass().getName(), e.getMessage());
							fetchStatusMap.put(address, FetchStatus.ERROR);
							finishBuildingSessionsFromPEP(address);
						}
					} else {
						fetchStatusMap.put(address, FetchStatus.ERROR);
						logger.debug(Config.LOGTAG, "{}Error received while building session:{}", getLogprefix(account), packet.findChild("error"));
						finishBuildingSessionsFromPEP(address);
					}
				}
			});
		} catch (OmemoInvalidJidException e) {
			logger.error(Config.LOGTAG, "{}Got address with invalid jid: {}", OmemoJid.getLogprefix(account), address.getName());
		}
	}

	public Set<AxolotlAddress> findDevicesWithoutSession(final OmemoContact contact) {
		return findDevicesWithoutSession(contact.getJid().toBareJid());
	}

	public Set<AxolotlAddress> findDevicesWithoutSession(final OmemoJid contactJid) {
		logger.debug(Config.LOGTAG, "{}Finding devices without session for {}", OmemoJid.getLogprefix(account), contactJid);
		Set<AxolotlAddress> addresses = new HashSet<AxolotlAddress>();
		if (deviceIds.get(contactJid) != null) {
			for (Integer foreignId : this.deviceIds.get(contactJid)) {
				AxolotlAddress address = new AxolotlAddress(contactJid.toString(), foreignId);
				if (sessions.get(address) == null) {
					IdentityKey identityKey = axolotlStore.loadSession(address).getSessionState().getRemoteIdentityKey();
					if (identityKey != null) {
						logger.debug(Config.LOGTAG, "{}Already have session for {}, adding to cache...", OmemoJid.getLogprefix(account), address.toString());
						XmppAxolotlSession session = new XmppAxolotlSession(account, axolotlStore, address, identityKey);
						sessions.put(address, session);
					} else {
						logger.debug(Config.LOGTAG, "{}Found device {}:{}", OmemoJid.getLogprefix(account), contactJid, foreignId);
						if (fetchStatusMap.get(address) != FetchStatus.ERROR) {
							addresses.add(address);
						} else {
							logger.debug(Config.LOGTAG, "{}skipping over {} because it's broken", getLogprefix(account), address);
						}
					}
				}
			}
		} else {
			logger.warn(Config.LOGTAG, "{}Have no target devices in PEP!", OmemoJid.getLogprefix(account));
		}
		if (deviceIds.get(account.getJid().toBareJid()) != null) {
			for (Integer ownId : this.deviceIds.get(account.getJid().toBareJid())) {
				AxolotlAddress address = new AxolotlAddress(account.getJid().toBareJid().toString(), ownId);
				if (sessions.get(address) == null) {
					IdentityKey identityKey = axolotlStore.loadSession(address).getSessionState().getRemoteIdentityKey();
					if (identityKey != null) {
						logger.debug(Config.LOGTAG, "{}Already have session for {}, adding to cache...", OmemoJid.getLogprefix(account), address.toString());
						XmppAxolotlSession session = new XmppAxolotlSession(account, axolotlStore, address, identityKey);
						sessions.put(address, session);
					} else {
						logger.debug(Config.LOGTAG, "{}Found device {}:{}", OmemoJid.getLogprefix(account), account.getJid().toBareJid(), ownId);
						if (fetchStatusMap.get(address) != FetchStatus.ERROR) {
							addresses.add(address);
						} else {
							logger.debug(Config.LOGTAG, "{}skipping over {} because it's broken", getLogprefix(account), address);
						}
					}
				}
			}
		}

		return addresses;
	}

	public boolean createSessionsIfNeeded(final OmemoContact contact) {
		logger.info(Config.LOGTAG, "{}Creating axolotl sessions if needed...", OmemoJid.getLogprefix(account));
		boolean newSessions = false;
		Set<AxolotlAddress> addresses = findDevicesWithoutSession(contact);
		for (AxolotlAddress address : addresses) {
			logger.debug(Config.LOGTAG, "{}Processing device: {}", OmemoJid.getLogprefix(account), address.toString());
			FetchStatus status = fetchStatusMap.get(address);
			if (status == null || status == FetchStatus.TIMEOUT) {
				fetchStatusMap.put(address, FetchStatus.PENDING);
				this.buildSessionFromPEP(address);
				newSessions = true;
			} else if (status == FetchStatus.PENDING) {
				newSessions = true;
			} else {
				logger.debug(Config.LOGTAG, "{}Already fetching bundle for {}", OmemoJid.getLogprefix(account), address.toString());
			}
		}

		return newSessions;
	}

	public boolean trustedSessionVerified(final OmemoContact contact) {
		Set<XmppAxolotlSession> sessions = findSessionsforContact(contact);
		sessions.addAll(findOwnSessions());
		boolean verified = false;
		for(XmppAxolotlSession session : sessions) {
			if (session.getTrust().trusted()) {
				if (session.getTrust() == XmppAxolotlSession.Trust.TRUSTED_X509) {
					verified = true;
				} else {
					return false;
				}
			}
		}
		return verified;
	}

	public boolean hasPendingKeyFetches(OmemoAccount account, OmemoContact contact) {
		AxolotlAddress ownAddress = new AxolotlAddress(account.getJid().toBareJid().toString(), 0);
		AxolotlAddress foreignAddress = new AxolotlAddress(contact.getJid().toBareJid().toString(), 0);
		return fetchStatusMap.getAll(ownAddress).containsValue(FetchStatus.PENDING)
				|| fetchStatusMap.getAll(foreignAddress).containsValue(FetchStatus.PENDING);

	}

	@Nullable
	private XmppAxolotlMessage buildHeader(OmemoContact contact) {
		final XmppAxolotlMessage axolotlMessage = new XmppAxolotlMessage(
				contact.getJid().toBareJid(), getOwnDeviceId());

		Set<XmppAxolotlSession> contactSessions = findSessionsforContact(contact);
		Set<XmppAxolotlSession> ownSessions = findOwnSessions();
		if (contactSessions.isEmpty()) {
			return null;
		}
		logger.debug(Config.LOGTAG, "{}Building axolotl foreign keyElements...", OmemoJid.getLogprefix(account));
		for (XmppAxolotlSession session : contactSessions) {
			logger.trace(Config.LOGTAG, OmemoJid.getLogprefix(account), session.getRemoteAddress().toString());
			axolotlMessage.addDevice(session);
		}
		logger.debug(Config.LOGTAG, "{}Building axolotl own keyElements...", OmemoJid.getLogprefix(account));
		for (XmppAxolotlSession session : ownSessions) {
			logger.trace(Config.LOGTAG, "{}{}", OmemoJid.getLogprefix(account), session.getRemoteAddress().toString());
			axolotlMessage.addDevice(session);
		}

		return axolotlMessage;
	}

	@Nullable
	public XmppAxolotlMessage encrypt(OmemoMessage message) {
		XmppAxolotlMessage axolotlMessage = buildHeader(message.getContact());

		if (axolotlMessage != null) {
			final String content;
			if (message.hasFileOnRemoteHost()) {
				content = message.getFileParams().url.toString();
			} else {
				content = message.getBody();
			}
			try {
				axolotlMessage.encrypt(content);
			} catch (CryptoFailedException e) {
				logger.warn(Config.LOGTAG, "{}Failed to encrypt message: {}", getLogprefix(account), e.getMessage());
				return null;
			}
		}

		return axolotlMessage;
	}

	public void preparePayloadMessage(final OmemoMessage message, final boolean delay) {
		executor.execute(new Runnable() {
			@Override
			public void run() {
				XmppAxolotlMessage axolotlMessage = encrypt(message);
				if (axolotlMessage == null) {
					mXmppConnectionService.markMessage(message, OmemoMessage.STATUS_SEND_FAILED);
					//mXmppConnectionService.updateConversationUi();
				} else {
					logger.debug(Config.LOGTAG, "{}Generated message, caching: {}", OmemoJid.getLogprefix(account), message.getUuid());
					messageCache.put(message.getUuid(), axolotlMessage);
					mXmppConnectionService.resendMessage(message, delay);
				}
			}
		});
	}

	public void prepareKeyTransportMessage(final OmemoContact contact, final OnMessageCreatedCallback onMessageCreatedCallback) {
		executor.execute(new Runnable() {
			@Override
			public void run() {
				XmppAxolotlMessage axolotlMessage = buildHeader(contact);
				onMessageCreatedCallback.run(axolotlMessage);
			}
		});
	}

	public XmppAxolotlMessage fetchAxolotlMessageFromCache(OmemoMessage message) {
		XmppAxolotlMessage axolotlMessage = messageCache.get(message.getUuid());
		if (axolotlMessage != null) {
			logger.debug(Config.LOGTAG, "{}Cache hit: {}", OmemoJid.getLogprefix(account), message.getUuid());
			messageCache.remove(message.getUuid());
		} else {
			logger.debug(Config.LOGTAG, "{}Cache miss: {}", OmemoJid.getLogprefix(account), message.getUuid());
		}
		return axolotlMessage;
	}

	private XmppAxolotlSession recreateUncachedSession(AxolotlAddress address) {
		IdentityKey identityKey = axolotlStore.loadSession(address).getSessionState().getRemoteIdentityKey();
		return (identityKey != null)
				? new XmppAxolotlSession(account, axolotlStore, address, identityKey)
				: null;
	}

	private XmppAxolotlSession getReceivingSession(XmppAxolotlMessage message) {
		AxolotlAddress senderAddress = new AxolotlAddress(message.getFrom().toString(),
				message.getSenderDeviceId());
		XmppAxolotlSession session = sessions.get(senderAddress);
		if (session == null) {
			logger.debug(Config.LOGTAG, "{}Account: {} No axolotl session found while parsing received message {}", OmemoJid.getLogprefix(account), account.getJid(), message);
			session = recreateUncachedSession(senderAddress);
			if (session == null) {
				session = new XmppAxolotlSession(account, axolotlStore, senderAddress);
			}
		}
		return session;
	}

	public XmppAxolotlMessage.XmppAxolotlPlaintextMessage processReceivingPayloadMessage(XmppAxolotlMessage message) {
		XmppAxolotlMessage.XmppAxolotlPlaintextMessage plaintextMessage = null;

		XmppAxolotlSession session = getReceivingSession(message);
		try {
			plaintextMessage = message.decrypt(session, getOwnDeviceId());
			Integer preKeyId = session.getPreKeyId();
			if (preKeyId != null) {
				publishBundlesIfNeeded(false, false);
				session.resetPreKeyId();
			}
		} catch (CryptoFailedException e) {
			logger.warn(Config.LOGTAG, "{}Failed to decrypt message: {}", getLogprefix(account), e.getMessage());
		}

		if (session.isFresh() && plaintextMessage != null) {
			putFreshSession(session);
		}

		return plaintextMessage;
	}

	public XmppAxolotlMessage.XmppAxolotlKeyTransportMessage processReceivingKeyTransportMessage(XmppAxolotlMessage message) {
		XmppAxolotlMessage.XmppAxolotlKeyTransportMessage keyTransportMessage;

		XmppAxolotlSession session = getReceivingSession(message);
		keyTransportMessage = message.getParameters(session, getOwnDeviceId());

		if (session.isFresh() && keyTransportMessage != null) {
			putFreshSession(session);
		}

		return keyTransportMessage;
	}

	private void putFreshSession(XmppAxolotlSession session) {
		logger.debug(Config.LOGTAG, "put fresh session");
		sessions.put(session);
		if (Config.X509_VERIFICATION) {
			if (session.getIdentityKey() != null) {
				verifySessionWithPEP(session);
			} else {
				logger.error(Config.LOGTAG, "{}: identity key was empty after reloading for x509 verification", account.getJid().toBareJid());
			}
		}
	}
}
