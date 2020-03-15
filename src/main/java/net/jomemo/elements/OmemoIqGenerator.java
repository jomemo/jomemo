package net.jomemo.elements;

import java.security.cert.X509Certificate;
import java.util.Set;
import org.whispersystems.libaxolotl.IdentityKey;
import org.whispersystems.libaxolotl.state.PreKeyRecord;
import org.whispersystems.libaxolotl.state.SignedPreKeyRecord;

public interface OmemoIqGenerator {

	OmemoIqPacket publishVerification(byte[] signature, X509Certificate[] chain, int ownDeviceId);

	OmemoIqPacket publishBundles(SignedPreKeyRecord signedPreKeyRecord, IdentityKey publicKey, Set<PreKeyRecord> preKeyRecords, int ownDeviceId);

	OmemoIqPacket retrieveVerificationForDevice(OmemoJid fromString, int deviceId);

	OmemoIqPacket retrieveBundlesForDevice(OmemoJid fromString, int deviceId);

	OmemoIqPacket publishDeviceIds(Set<Integer> deviceIdsCopy);

	OmemoIqPacket retrieveDeviceIds(OmemoJid toBareJid);
}
