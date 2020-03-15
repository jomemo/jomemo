package net.jomemo.elements;

import java.security.SecureRandom;
import net.jomemo.axolotl.AxolotlService;

public interface OmemoXmppConnectionService {

	void sendIqPacket(OmemoAccount account, OmemoIqPacket publish, OmemoOnIqPacketReceived onIqPacketReceived);

	SecureRandom getRNG();

	void keyStatusUpdated(AxolotlService.FetchStatus report);

	Object getFeatures();

	OmemoIqGenerator getIqGenerator();

	void publishDisplayName(OmemoAccount account);

	OmemoIqParser getIqParser();

	void syncRosterToDisk(OmemoAccount account);

	void resendMessage(OmemoMessage message, boolean delay);

	void markMessage(OmemoMessage message, int STATUS_SEND_FAILED);

	OmemoMemorizingTrustManager getMemorizingTrustManager();

	void updateAccountUi();

	OmemoDatabaseBackend getDatabaseBackend();
}
