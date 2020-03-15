package net.jomemo.elements;

import java.util.List;

public abstract class OmemoElement {

	public static OmemoElement createNew(String KEYTAG) { throw new UnsupportedOperationException("Not supported yet."); }

	public static OmemoElement createNew(String CONTAINERTAG, String PEP_PREFIX) { throw new UnsupportedOperationException("Not supported yet."); }

	public void setAttribute(String SOURCEID, int sourceDeviceId) { throw new UnsupportedOperationException(); }

	public OmemoElement addChild(String HEADER) { throw new UnsupportedOperationException(); }

	public void setContent(String encode) { throw new UnsupportedOperationException(); }

	public OmemoElement findChild(String HEADER) { throw new UnsupportedOperationException(); }

	public String getAttribute(String SOURCEID) { throw new UnsupportedOperationException(); }

	public List<OmemoElement> getChildren() { throw new UnsupportedOperationException(); }

	public String getName() { throw new UnsupportedOperationException(); }

	public String getContent() { throw new UnsupportedOperationException(); }

	public void addChild(OmemoElement keyElement) { throw new UnsupportedOperationException(); }

	public boolean hasChild(String itemnotfound) { throw new UnsupportedOperationException(); }
}
