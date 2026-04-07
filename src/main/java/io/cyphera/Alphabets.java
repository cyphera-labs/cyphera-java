package io.cyphera;

public final class Alphabets {
    private Alphabets() {}

    public static final String DIGITS = "0123456789";
    public static final String ALPHA_LOWER = "abcdefghijklmnopqrstuvwxyz";
    public static final String ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String ALPHA = ALPHA_LOWER + ALPHA_UPPER;
    public static final String ALPHANUMERIC = DIGITS + ALPHA_LOWER + ALPHA_UPPER;

    /**
     * Safe printable alphabet — alphanumeric plus symbols that don't break
     * SQL, JSON, CSV, XML, URLs, or shell escaping. No spaces, quotes,
     * backslashes, angle brackets, ampersands, pipes, or semicolons.
     *
     * Radix 72 — larger keyspace than alphanumeric (62) while staying safe
     * in every common data format.
     */
    public static final String PRINTABLE_SAFE = ALPHANUMERIC + "!#$%*+-.:=?@^_~";

    public static final String DEFAULT = ALPHANUMERIC;

    public static String resolve(String name) {
        if (name == null) return DEFAULT;
        switch (name.toLowerCase()) {
            case "digits": return DIGITS;
            case "alpha_lower": return ALPHA_LOWER;
            case "alpha_upper": return ALPHA_UPPER;
            case "alpha": return ALPHA;
            case "alphanumeric": return ALPHANUMERIC;
            case "printable_safe": case "printable": return PRINTABLE_SAFE;
            default: return name; // treat as literal custom alphabet
        }
    }
}
