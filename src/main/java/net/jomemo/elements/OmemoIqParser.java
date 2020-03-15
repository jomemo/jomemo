package net.jomemo.elements;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.whispersystems.libaxolotl.ecc.ECPublicKey;
import org.whispersystems.libaxolotl.state.PreKeyBundle;

public interface OmemoIqParser {

	PreKeyBundle bundle(OmemoIqPacket packet);

	Map<Integer, ECPublicKey> preKeyPublics(OmemoIqPacket packet);

	Map.Entry<X509Certificate[], byte[]> verification(OmemoIqPacket packet);

	OmemoElement getItem(OmemoIqPacket packet);

	Set<Integer> deviceIds(OmemoElement item);

	List<PreKeyBundle> preKeys(OmemoIqPacket packet);
}
