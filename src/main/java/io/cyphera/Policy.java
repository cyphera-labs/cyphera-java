package io.cyphera;

import java.util.Map;

public final class Policy {
    private final String name;
    private final String engine;       // "ff1", "ff3", "aes_gcm", "mask", "hash"
    private final String alphabet;     // resolved alphabet string
    private final String keyRef;       // reference to a key
    private final String tag;          // 3-4 char tag for this policy
    private final boolean tagEnabled;  // default true
    private final int tagLength;       // default 3

    // For mask engine
    private final String pattern;      // e.g. "***-**-{last4}"

    // For hash engine
    private final String algorithm;    // e.g. "sha256"

    private Policy(String name, String engine, String alphabet, String keyRef,
                   String tag, boolean tagEnabled, int tagLength,
                   String pattern, String algorithm) {
        this.name = name;
        this.engine = engine;
        this.alphabet = alphabet;
        this.keyRef = keyRef;
        this.tag = tag;
        this.tagEnabled = tagEnabled;
        this.tagLength = tagLength;
        this.pattern = pattern;
        this.algorithm = algorithm;
    }

    public String name() { return name; }
    public String engine() { return engine; }
    public String alphabet() { return alphabet; }
    public String keyRef() { return keyRef; }
    public String tag() { return tag; }
    public boolean tagEnabled() { return tagEnabled; }
    public int tagLength() { return tagLength; }
    public String pattern() { return pattern; }
    public String algorithm() { return algorithm; }

    @SuppressWarnings("unchecked")
    public static Policy fromMap(String name, Map<String, Object> map) {
        String engine = (String) map.getOrDefault("engine", "ff1");
        String alphabetName = (String) map.get("alphabet");
        String alphabet = Alphabets.resolve(alphabetName);
        String keyRef = (String) map.getOrDefault("key_ref", "");
        String tag = (String) map.get("tag");
        boolean tagEnabled = !Boolean.FALSE.equals(map.get("tag_enabled"));
        int tagLength = 3;
        Object tagLenObj = map.get("tag_length");
        if (tagLenObj instanceof Number) tagLength = ((Number) tagLenObj).intValue();
        String pattern = (String) map.get("pattern");
        String algorithm = (String) map.getOrDefault("algorithm", "sha256");

        // Auto-generate tag if not provided and tag is enabled
        if (tag == null && tagEnabled) {
            tag = generateTag(name, tagLength);
        }

        return new Policy(name, engine, alphabet, keyRef, tag, tagEnabled, tagLength, pattern, algorithm);
    }

    // Generate a deterministic tag from the policy name
    // Use a simple hash of the name to pick chars from ALPHANUMERIC
    private static String generateTag(String name, int length) {
        String chars = Alphabets.ALPHANUMERIC;
        int hash = 0;
        for (int i = 0; i < name.length(); i++) {
            hash = 31 * hash + name.charAt(i);
        }
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            // Mix bits for each position
            int h = hash ^ (hash >>> 16) ^ (i * 0x9e3779b9);
            if (h < 0) h = -h;
            sb.append(chars.charAt(h % chars.length()));
        }
        return sb.toString();
    }

    public boolean isReversible() {
        return "ff1".equals(engine) || "ff3".equals(engine) || "aes_gcm".equals(engine);
    }
}
