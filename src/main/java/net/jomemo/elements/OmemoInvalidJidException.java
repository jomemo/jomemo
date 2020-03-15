package net.jomemo.elements;

public class OmemoInvalidJidException extends Exception {

    // This is probably not the "Java way", but the "Java way" means we'd have a ton of extra tiny,
    // annoying classes floating around. I like this.
    public static final String INVALID_LENGTH = "JID must be between 0 and 3071 characters";
    public static final String INVALID_PART_LENGTH = "JID part must be between 0 and 1023 characters";
    public static final String INVALID_CHARACTER = "JID contains an invalid character";
    public static final String STRINGPREP_FAIL = "The STRINGPREP operation has failed for the given JID";
	public static final String IS_NULL = "JID can not be NULL";

    /**
     * Constructs a new {@code Exception} that includes the current stack trace.
     */
    public OmemoInvalidJidException() {
    }

    /**
     * Constructs a new {@code Exception} with the current stack trace and the
     * specified detail message.
     *
     * @param detailMessage the detail message for this exception.
     */
    public OmemoInvalidJidException(final String detailMessage) {
        super(detailMessage);
    }

    /**
     * Constructs a new {@code Exception} with the current stack trace, the
     * specified detail message and the specified cause.
     *
     * @param detailMessage the detail message for this exception.
     * @param throwable the cause of this exception.
     */
    public OmemoInvalidJidException(final String detailMessage, final Throwable throwable) {
        super(detailMessage, throwable);
    }

    /**
     * Constructs a new {@code Exception} with the current stack trace and the
     * specified cause.
     *
     * @param throwable the cause of this exception.
     */
    public OmemoInvalidJidException(final Throwable throwable) {
        super(throwable);
    }
}
