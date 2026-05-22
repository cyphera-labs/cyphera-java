package io.cyphera;

import io.cyphera.engine.aesgcm.AesGcm;
import io.cyphera.engine.ff1.FF1;
import io.cyphera.engine.ff3.FF3;
import io.cyphera.engine.ff3.FF31;

import java.util.HashMap;
import java.util.Map;

public final class Cyphera {
    private final Map<String, Configuration> configurations = new HashMap<>();
    private final Map<String, Configuration> headerIndex = new HashMap<>(); // header -> configuration
    private final KeyProvider keyProvider;

    private Cyphera(Map<String, Configuration> configurations, KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
        for (Map.Entry<String, Configuration> e : configurations.entrySet()) {
            Configuration cfg = e.getValue();
            this.configurations.put(e.getKey(), cfg);
            if (cfg.headerEnabled() && cfg.header() != null) {
                if (this.headerIndex.containsKey(cfg.header())) {
                    throw new IllegalArgumentException(
                        "Header collision: '" + cfg.header() + "' used by both '" +
                        this.headerIndex.get(cfg.header()).name() + "' and '" + cfg.name() + "'");
                }
                this.headerIndex.put(cfg.header(), cfg);
            }
        }
    }

    /**
     * Build from a native Map -- the zero-dep way.
     * Map structure: { "configurations": { "ssn": { "engine": "ff1", ... } }, "keys": { "my-key": { "material": "hex" } } }
     */
    @SuppressWarnings("unchecked")
    public static Cyphera fromMap(Map<String, Object> config) {
        Map<String, Object> configurationsMap = (Map<String, Object>) config.getOrDefault("configurations", new HashMap<>());
        Map<String, Object> keysMap = (Map<String, Object>) config.getOrDefault("keys", new HashMap<>());

        Map<String, Configuration> configurations = new HashMap<>();
        for (Map.Entry<String, Object> e : configurationsMap.entrySet()) {
            configurations.put(e.getKey(), Configuration.fromMap(e.getKey(), (Map<String, Object>) e.getValue()));
        }

        KeyProvider keyProvider = new MemoryKeyProvider(keysMap);
        return new Cyphera(configurations, keyProvider);
    }

    /**
     * Build with a custom key provider.
     */
    @SuppressWarnings("unchecked")
    public static Cyphera fromMap(Map<String, Object> config, KeyProvider keyProvider) {
        Map<String, Object> configurationsMap = (Map<String, Object>) config.getOrDefault("configurations", new HashMap<>());

        Map<String, Configuration> configurations = new HashMap<>();
        for (Map.Entry<String, Object> e : configurationsMap.entrySet()) {
            configurations.put(e.getKey(), Configuration.fromMap(e.getKey(), (Map<String, Object>) e.getValue()));
        }

        return new Cyphera(configurations, keyProvider);
    }

    /**
     * Load from a JSON file path.
     */
    public static Cyphera fromFile(String path) {
        try {
            String contents = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)));
            Map<String, Object> config = JsonParser.parse(contents);
            return fromMap(config);
        } catch (java.io.IOException e) {
            throw new RuntimeException("Failed to load configuration file: " + path, e);
        }
    }

    /**
     * Auto-discover configuration file using standard precedence:
     * 1. CYPHERA_CONFIG_FILE env var
     * 2. ./cyphera.json
     * 3. /etc/cyphera/cyphera.json
     */
    public static Cyphera load() {
        String envPath = System.getenv("CYPHERA_CONFIG_FILE");
        if (envPath != null && java.nio.file.Files.exists(java.nio.file.Paths.get(envPath))) {
            return fromFile(envPath);
        }

        String localPath = "cyphera.json";
        if (java.nio.file.Files.exists(java.nio.file.Paths.get(localPath))) {
            return fromFile(localPath);
        }

        String systemPath = "/etc/cyphera/cyphera.json";
        if (java.nio.file.Files.exists(java.nio.file.Paths.get(systemPath))) {
            return fromFile(systemPath);
        }

        throw new IllegalStateException(
            "No configuration file found. Checked: CYPHERA_CONFIG_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json");
    }

    /**
     * Protect a value using a named configuration.
     * Returns DPH-prefixed output (unless header is disabled in configuration).
     * Passthrough characters (non-alphabet chars like dashes, spaces) are preserved in place.
     */
    public String protect(String value, String configurationName) {
        Configuration configuration = configurations.get(configurationName);
        if (configuration == null) throw new IllegalArgumentException("Unknown configuration: " + configurationName);

        String engine = configuration.engine();

        switch (engine) {
            case "ff1": case "ff3": case "ff31": return protectFpe(value, configuration, engine);
            case "mask": return protectMask(value, configuration);
            case "hash": return protectHash(value, configuration);
            case "aes_gcm": return protectAesGcm(value, configuration);
            default: throw new IllegalArgumentException("Unknown engine: " + engine);
        }
    }

    /**
     * Reverse a protected value. The SDK uses the loaded configurations to
     * figure out which one applies -- it checks the leading bytes of
     * {@code protectedValue} against the registered headers (longest first
     * to avoid prefix collisions), strips the matched header, and decrypts.
     */
    public String access(String protectedValue) {
        // Walk headers longest-first so a shorter prefix doesn't shadow a longer one.
        java.util.List<Map.Entry<String, Configuration>> headers =
            new java.util.ArrayList<>(headerIndex.entrySet());
        headers.sort((a, b) -> Integer.compare(b.getKey().length(), a.getKey().length()));
        for (Map.Entry<String, Configuration> e : headers) {
            String header = e.getKey();
            if (protectedValue.length() > header.length() && protectedValue.startsWith(header)) {
                Configuration configuration = e.getValue();
                String stripped = protectedValue.substring(header.length());
                return accessWithConfiguration(stripped, configuration);
            }
        }
        throw new IllegalArgumentException("No matching header found");
    }

    /**
     * Decrypt a value using the named configuration. The configuration must
     * have {@code header_enabled = false} -- this lower-level form treats the
     * input as raw headerless ciphertext. For headered configurations, use the
     * high-level {@link #access(String)} which strips the header itself.
     */
    public String decrypt(String ciphertext, String configurationName) {
        Configuration configuration = configurations.get(configurationName);
        if (configuration == null) throw new IllegalArgumentException("Unknown configuration: " + configurationName);
        if (configuration.headerEnabled()) {
            throw new IllegalArgumentException(
                "configuration '" + configurationName + "' has header_enabled=true; use access(value) — the header identifies the configuration. The two-arg decrypt(value, name) form is for header_enabled=false configurations only.");
        }
        return accessWithConfiguration(ciphertext, configuration);
    }

    // -- Internal: FPE protect (FF1 / FF3) --

    private static boolean ff3Warned = false;

    /** Emit the FF3 deprecation warning to stderr, once per process. */
    private static synchronized void warnFf3Deprecated() {
        if (!ff3Warned) {
            ff3Warned = true;
            System.err.println("WARNING: engine 'ff3' is deprecated and cryptographically weak — migrate to 'ff31' (FF3-1).");
        }
    }

    private String protectFpe(String value, Configuration configuration, String engine) {
        try {
            byte[] key = keyProvider.resolve(configuration.keyRef());
            String alphabet = configuration.alphabet();

            // 1. Strip passthroughs, record positions
            int[] ptPositions = new int[value.length()];
            char[] ptChars = new char[value.length()];
            int ptCount = 0;
            StringBuilder encryptable = new StringBuilder();
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (alphabet.indexOf(c) >= 0) {
                    encryptable.append(c);
                } else {
                    ptPositions[ptCount] = i;
                    ptChars[ptCount] = c;
                    ptCount++;
                }
            }

            // 2. Check for zero encryptable chars
            if (encryptable.length() == 0) {
                throw new IllegalArgumentException("No encryptable characters in input");
            }

            // 3. Encrypt
            String encrypted;
            if ("ff3".equals(engine)) {
                warnFf3Deprecated();
                encrypted = new FF3(key, new byte[8], alphabet).encrypt(encryptable.toString());
            } else if ("ff31".equals(engine)) {
                encrypted = new FF31(key, new byte[7], alphabet).encrypt(encryptable.toString());
            } else {
                encrypted = new FF1(key, new byte[0], alphabet).encrypt(encryptable.toString());
            }

            // 3. Reinsert passthroughs at original positions
            StringBuilder withPt = new StringBuilder(encrypted);
            for (int i = 0; i < ptCount; i++) {
                withPt.insert(ptPositions[i], ptChars[i]);
            }

            // 4. Prepend header
            if (configuration.headerEnabled()) {
                return configuration.header() + withPt.toString();
            }
            return withPt.toString();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("FPE encryption failed: " + e.getMessage(), e);
        }
    }

    // -- Internal: Mask protect --

    private String protectMask(String value, Configuration configuration) {
        String pattern = configuration.pattern();
        if (pattern == null) throw new IllegalArgumentException("Mask configuration requires 'pattern'");

        int len = value.length();
        char mask = '*';

        switch (pattern) {
            case "last4": case "last_4":
                return repeat(mask, Math.max(0, len - 4)) + value.substring(Math.max(0, len - 4));
            case "last2": case "last_2":
                return repeat(mask, Math.max(0, len - 2)) + value.substring(Math.max(0, len - 2));
            case "first1": case "first_1":
                return (len >= 1 ? value.substring(0, 1) : "") + repeat(mask, Math.max(0, len - 1));
            case "first3": case "first_3":
                return (len >= 3 ? value.substring(0, 3) : value) + repeat(mask, Math.max(0, len - 3));
            case "full":
            default:
                return repeat(mask, len);
        }
    }

    private static String repeat(char c, int count) {
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) sb.append(c);
        return sb.toString();
    }

    // -- Internal: Hash protect --

    private String protectHash(String value, Configuration configuration) {
        try {
            String algo = configuration.algorithm();
            String javaAlgo;
            switch (algo.toLowerCase()) {
                case "sha256": case "sha-256": javaAlgo = "SHA-256"; break;
                case "sha384": case "sha-384": javaAlgo = "SHA-384"; break;
                case "sha512": case "sha-512": javaAlgo = "SHA-512"; break;
                default: throw new IllegalArgumentException("Unsupported hash algorithm: " + algo);
            }

            // If key_ref is set, do HMAC instead of plain hash
            if (configuration.keyRef() != null && !configuration.keyRef().isEmpty()) {
                byte[] key = keyProvider.resolve(configuration.keyRef());
                javax.crypto.Mac mac = javax.crypto.Mac.getInstance("Hmac" + javaAlgo.replace("-", ""));
                mac.init(new javax.crypto.spec.SecretKeySpec(key, mac.getAlgorithm()));
                byte[] hash = mac.doFinal(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                return bytesToHex(hash);
            }

            java.security.MessageDigest md = java.security.MessageDigest.getInstance(javaAlgo);
            byte[] hash = md.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Hash failed: " + e.getMessage(), e);
        }
    }

    // -- Internal: access with known configuration --
    // {@code protectedValue} is always raw headerless ciphertext at this point;
    // the header (if any) has already been stripped by the caller.

    private String accessWithConfiguration(String protectedValue, Configuration configuration) {
        if (!configuration.isReversible()) {
            throw new IllegalArgumentException("Configuration '" + configuration.name() + "' uses engine '" + configuration.engine() + "' which is not reversible");
        }

        String engine = configuration.engine();
        switch (engine) {
            case "ff1": case "ff3": case "ff31": return accessFpe(protectedValue, configuration, engine);
            case "aes_gcm": return accessAesGcm(protectedValue, configuration);
            default: throw new IllegalArgumentException("Access not supported for engine: " + engine);
        }
    }

    private String accessFpe(String protectedValue, Configuration configuration, String engine) {
        try {
            byte[] key = keyProvider.resolve(configuration.keyRef());
            String alphabet = configuration.alphabet();

            // 1. Strip passthroughs, record positions
            int[] ptPositions = new int[protectedValue.length()];
            char[] ptChars = new char[protectedValue.length()];
            int ptCount = 0;
            StringBuilder encryptable = new StringBuilder();
            for (int i = 0; i < protectedValue.length(); i++) {
                char c = protectedValue.charAt(i);
                if (alphabet.indexOf(c) >= 0) {
                    encryptable.append(c);
                } else {
                    ptPositions[ptCount] = i;
                    ptChars[ptCount] = c;
                    ptCount++;
                }
            }

            // 2. Decrypt
            String decrypted;
            if ("ff3".equals(engine)) {
                warnFf3Deprecated();
                decrypted = new FF3(key, new byte[8], alphabet).decrypt(encryptable.toString());
            } else if ("ff31".equals(engine)) {
                decrypted = new FF31(key, new byte[7], alphabet).decrypt(encryptable.toString());
            } else {
                decrypted = new FF1(key, new byte[0], alphabet).decrypt(encryptable.toString());
            }

            // 3. Reinsert passthroughs at original positions
            StringBuilder result = new StringBuilder(decrypted);
            for (int i = 0; i < ptCount; i++) {
                result.insert(ptPositions[i], ptChars[i]);
            }

            return result.toString();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("FPE decryption failed: " + e.getMessage(), e);
        }
    }

    // -- Internal: AES-GCM protect/access --

    private String protectAesGcm(String value, Configuration configuration) {
        byte[] key = keyProvider.resolve(configuration.keyRef());
        String encrypted = AesGcm.encrypt(value, key);
        if (configuration.headerEnabled()) {
            return configuration.header() + encrypted;
        }
        return encrypted;
    }

    private String accessAesGcm(String protectedValue, Configuration configuration) {
        byte[] key = keyProvider.resolve(configuration.keyRef());
        return AesGcm.decrypt(protectedValue, key);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
