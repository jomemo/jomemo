package net.jomemo.elements;

public interface OmemoOnIqPacketReceived {

	void onIqPacketReceived(OmemoAccount account, OmemoIqPacket packet);
}
