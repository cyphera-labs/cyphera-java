package io.cyphera;

import java.util.Map;

public final class Configuration {
    private final String name;
    private final String engine;          // "ff1", "ff3", "aes_gcm", "mask", "hash"
    private final String alphabet;        // resolved alphabet string
    private final String keyRef;          // reference to a key
    private final String header;          // 3-4 char Data Protection Header for this configuration
    private final boolean headerEnabled;  // default true
    private final int headerLength;       // default 3

    // For mask engine
    private final String pattern;      // e.g. "***-**-{last4}"

    // For hash engine
    private final String algorithm;    // e.g. "sha256"

    private Configuration(String name, String engine, String alphabet, String keyRef,
                          String header, boolean headerEnabled, int headerLength,
                          String pattern, String algorithm) {
        this.name = name;
        this.engine = engine;
        this.alphabet = alphabet;
        this.keyRef = keyRef;
        this.header = header;
        this.headerEnabled = headerEnabled;
        this.headerLength = headerLength;
        this.pattern = pattern;
        this.algorithm = algorithm;
    }

    public String name() { return name; }
    public String engine() { return engine; }
    public String alphabet() { return alphabet; }
    public String keyRef() { return keyRef; }
    public String header() { return header; }
    public boolean headerEnabled() { return headerEnabled; }
    public int headerLength() { return headerLength; }
    public String pattern() { return pattern; }
    public String algorithm() { return algorithm; }

    @SuppressWarnings("unchecked")
    public static Configuration fromMap(String name, Map<String, Object> map) {
        String engine = (String) map.getOrDefault("engine", "ff1");
        String alphabetName = (String) map.get("alphabet");
        String alphabet = Alphabets.resolve(alphabetName);
        String keyRef = (String) map.getOrDefault("key_ref", "");
        String header = (String) map.get("header");
        boolean headerEnabled = !Boolean.FALSE.equals(map.get("header_enabled"));
        int headerLength = 3;
        Object headerLenObj = map.get("header_length");
        if (headerLenObj instanceof Number) headerLength = ((Number) headerLenObj).intValue();
        String pattern = (String) map.get("pattern");
        String algorithm = (String) map.getOrDefault("algorithm", "sha256");

        // Header must be provided in configuration if header_enabled is true
        if (headerEnabled && (header == null || header.isEmpty())) {
            throw new IllegalArgumentException("configuration error: header must be specified");
        }

        return new Configuration(name, engine, alphabet, keyRef, header, headerEnabled, headerLength, pattern, algorithm);
    }

    public boolean isReversible() {
        return "ff1".equals(engine) || "ff3".equals(engine)
            || "ff31".equals(engine) || "aes_gcm".equals(engine);
    }
}
