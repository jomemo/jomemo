package net.jomemo;

import java.util.LinkedHashMap;
import java.util.Map;
import net.jomemo.axolotl.XmppAxolotlSession;

/**
 * Least Recently Used Cache implementation.
 *
 * Discards the least recently used items first.
 *
 * Example:
 * <blockquote><pre>{@code
 * Map<String, String> example = Collections.synchronizedMap(
 *		new LruCache<String, String>(CACHE_SIZE));
 * }</pre></blockquote>
 *
 * @param <K> the type of keys maintained by this map
 * @param <V> the type of mapped values
 */
public class LruCache<K, V> extends LinkedHashMap<K, V> {

    private final int maxEntries;

    public LruCache(final int maxEntries) {
        super(maxEntries + 1, 1.0f, true);
        this.maxEntries = maxEntries;
    }

    /**
     * Returns <tt>true</tt> if this <code>LruCache</code> has more entries than the maximum specified when it was
     * created.
     *
     * <p>
     * This method <em>does not</em> modify the underlying <code>Map</code>; it relies on the implementation of
     * <code>LinkedHashMap</code> to do that, but that behavior is documented in the JavaDoc for
     * <code>LinkedHashMap</code>.
     * </p>
     *
     * @param eldest
     *            the <code>Entry</code> in question; this implementation doesn't care what it is, since the
     *            implementation is only dependent on the size of the cache
     * @return <tt>true</tt> if the oldest
     * @see java.util.LinkedHashMap#removeEldestEntry(Map.Entry)
     */
    @Override
    protected boolean removeEldestEntry(final Map.Entry<K, V> eldest) {
        return super.size() > maxEntries;
    }

	protected XmppAxolotlSession.Trust create(String fingerprint) {
		throw new UnsupportedOperationException(); // TODO
	}
}
