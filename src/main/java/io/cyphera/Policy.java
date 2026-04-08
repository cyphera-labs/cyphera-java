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

        // Tag must be provided in policy if tag_enabled is true
        if (tagEnabled && (tag == null || tag.isEmpty())) {
            throw new IllegalArgumentException("Policy '" + name + "' has tag_enabled=true but no tag specified. The tag must be set in the policy.");
        }

        return new Policy(name, engine, alphabet, keyRef, tag, tagEnabled, tagLength, pattern, algorithm);
    }

    public boolean isReversible() {
        return "ff1".equals(engine) || "ff3".equals(engine) || "aes_gcm".equals(engine);
    }
}
