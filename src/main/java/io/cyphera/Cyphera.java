package io.cyphera;

import io.cyphera.engine.aesgcm.AesGcm;
import io.cyphera.engine.ff1.FF1;
import io.cyphera.engine.ff3.FF3;

import java.util.HashMap;
import java.util.Map;

public final class Cyphera {
    private final Map<String, Policy> policies = new HashMap<>();
    private final Map<String, Policy> tagIndex = new HashMap<>(); // tag -> policy
    private final KeyProvider keyProvider;

    private Cyphera(Map<String, Policy> policies, KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
        for (Map.Entry<String, Policy> e : policies.entrySet()) {
            Policy p = e.getValue();
            this.policies.put(e.getKey(), p);
            if (p.tagEnabled() && p.tag() != null) {
                if (this.tagIndex.containsKey(p.tag())) {
                    throw new IllegalArgumentException(
                        "Tag collision: '" + p.tag() + "' used by both '" +
                        this.tagIndex.get(p.tag()).name() + "' and '" + p.name() + "'");
                }
                this.tagIndex.put(p.tag(), p);
            }
        }
    }

    /**
     * Build from a native Map -- the zero-dep way.
     * Map structure: { "policies": { "ssn": { "engine": "ff1", ... } }, "keys": { "my-key": { "material": "hex" } } }
     */
    @SuppressWarnings("unchecked")
    public static Cyphera fromMap(Map<String, Object> config) {
        Map<String, Object> policiesMap = (Map<String, Object>) config.getOrDefault("policies", new HashMap<>());
        Map<String, Object> keysMap = (Map<String, Object>) config.getOrDefault("keys", new HashMap<>());

        Map<String, Policy> policies = new HashMap<>();
        for (Map.Entry<String, Object> e : policiesMap.entrySet()) {
            policies.put(e.getKey(), Policy.fromMap(e.getKey(), (Map<String, Object>) e.getValue()));
        }

        KeyProvider keyProvider = new MemoryKeyProvider(keysMap);
        return new Cyphera(policies, keyProvider);
    }

    /**
     * Build with a custom key provider.
     */
    @SuppressWarnings("unchecked")
    public static Cyphera fromMap(Map<String, Object> config, KeyProvider keyProvider) {
        Map<String, Object> policiesMap = (Map<String, Object>) config.getOrDefault("policies", new HashMap<>());

        Map<String, Policy> policies = new HashMap<>();
        for (Map.Entry<String, Object> e : policiesMap.entrySet()) {
            policies.put(e.getKey(), Policy.fromMap(e.getKey(), (Map<String, Object>) e.getValue()));
        }

        return new Cyphera(policies, keyProvider);
    }

    /**
     * Protect a value using a named policy.
     * Returns tagged ciphertext (unless tag is disabled in policy).
     * Passthrough characters (non-alphabet chars like dashes, spaces) are preserved in place.
     */
    public String protect(String value, String policyName) {
        Policy policy = policies.get(policyName);
        if (policy == null) throw new IllegalArgumentException("Unknown policy: " + policyName);

        String engine = policy.engine();

        switch (engine) {
            case "ff1": return protectFf1(value, policy);
            case "ff3": return protectFf3(value, policy);
            case "mask": return protectMask(value, policy);
            case "hash": return protectHash(value, policy);
            case "aes_gcm": return protectAesGcm(value, policy);
            default: throw new IllegalArgumentException("Unknown engine: " + engine);
        }
    }

    /**
     * Access (decrypt/reverse) a protected value.
     * If tagged, the policy is determined from the tag automatically.
     * If untagged, the policyName must be provided.
     */
    public String access(String protectedValue) {
        // Tag is just the first N chars of the string
        for (Map.Entry<String, Policy> e : tagIndex.entrySet()) {
            String tag = e.getKey();
            if (protectedValue.length() > tag.length() && protectedValue.startsWith(tag)) {
                return accessWithPolicy(protectedValue, e.getValue(), true);
            }
        }
        throw new IllegalArgumentException("No matching tag found. Use access(value, policyName) for untagged values.");
    }

    /**
     * Access with explicit policy name -- for untagged values.
     */
    public String access(String protectedValue, String policyName) {
        Policy policy = policies.get(policyName);
        if (policy == null) throw new IllegalArgumentException("Unknown policy: " + policyName);
        return accessWithPolicy(protectedValue, policy, policy.tagEnabled());
    }

    // -- Internal: FPE protect (FF1 / FF3) --

    private String protectFf1(String value, Policy policy) { return protectFpe(value, policy, false); }
    private String protectFf3(String value, Policy policy) { return protectFpe(value, policy, true); }

    private String protectFpe(String value, Policy policy, boolean ff3) {
        try {
            byte[] key = keyProvider.resolve(policy.keyRef());
            String alphabet = policy.alphabet();

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

            // 2. Encrypt
            String encrypted;
            if (ff3) {
                encrypted = new FF3(key, new byte[8], alphabet).encrypt(encryptable.toString());
            } else {
                encrypted = new FF1(key, new byte[0], alphabet).encrypt(encryptable.toString());
            }

            // 3. Reinsert passthroughs at original positions
            StringBuilder withPt = new StringBuilder(encrypted);
            for (int i = 0; i < ptCount; i++) {
                withPt.insert(ptPositions[i], ptChars[i]);
            }

            // 4. Prepend tag
            if (policy.tagEnabled()) {
                return policy.tag() + withPt.toString();
            }
            return withPt.toString();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("FPE encryption failed: " + e.getMessage(), e);
        }
    }

    // -- Internal: Mask protect --

    private String protectMask(String value, Policy policy) {
        String pattern = policy.pattern();
        if (pattern == null) throw new IllegalArgumentException("Mask policy requires 'pattern'");

        // Simple pattern: replace * with *, {last4} with last 4 chars, {first3} with first 3 chars
        String result = pattern;
        if (result.contains("{last4}")) {
            String last4 = value.length() >= 4 ? value.substring(value.length() - 4) : value;
            result = result.replace("{last4}", last4);
        }
        if (result.contains("{last2}")) {
            String last2 = value.length() >= 2 ? value.substring(value.length() - 2) : value;
            result = result.replace("{last2}", last2);
        }
        if (result.contains("{first3}")) {
            String first3 = value.length() >= 3 ? value.substring(0, 3) : value;
            result = result.replace("{first3}", first3);
        }
        if (result.contains("{first1}")) {
            String first1 = value.length() >= 1 ? value.substring(0, 1) : value;
            result = result.replace("{first1}", first1);
        }
        return result;
    }

    // -- Internal: Hash protect --

    private String protectHash(String value, Policy policy) {
        try {
            String algo = policy.algorithm();
            String javaAlgo;
            switch (algo.toLowerCase()) {
                case "sha256": case "sha-256": javaAlgo = "SHA-256"; break;
                case "sha384": case "sha-384": javaAlgo = "SHA-384"; break;
                case "sha512": case "sha-512": javaAlgo = "SHA-512"; break;
                default: throw new IllegalArgumentException("Unsupported hash algorithm: " + algo);
            }

            // If key_ref is set, do HMAC instead of plain hash
            if (policy.keyRef() != null && !policy.keyRef().isEmpty()) {
                byte[] key = keyProvider.resolve(policy.keyRef());
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

    // -- Internal: access with known policy --

    private String accessWithPolicy(String protectedValue, Policy policy, boolean hasTag) {
        if (!policy.isReversible()) {
            throw new IllegalArgumentException("Policy '" + policy.name() + "' uses engine '" + policy.engine() + "' which is not reversible");
        }

        String engine = policy.engine();
        switch (engine) {
            case "ff1": return accessFf1(protectedValue, policy, hasTag);
            case "ff3": return accessFf3(protectedValue, policy, hasTag);
            case "aes_gcm": return accessAesGcm(protectedValue, policy, hasTag);
            default: throw new IllegalArgumentException("Access not supported for engine: " + engine);
        }
    }

    private String accessFf1(String protectedValue, Policy policy, boolean hasTag) {
        return accessFpe(protectedValue, policy, hasTag, false);
    }

    private String accessFf3(String protectedValue, Policy policy, boolean hasTag) {
        return accessFpe(protectedValue, policy, hasTag, true);
    }

    private String accessFpe(String protectedValue, Policy policy, boolean hasTag, boolean ff3) {
        try {
            byte[] key = keyProvider.resolve(policy.keyRef());
            String alphabet = policy.alphabet();

            // 1. Strip tag (first N chars of the full string)
            String withoutTag = hasTag ? protectedValue.substring(policy.tagLength()) : protectedValue;

            // 2. Strip passthroughs, record positions
            int[] ptPositions = new int[withoutTag.length()];
            char[] ptChars = new char[withoutTag.length()];
            int ptCount = 0;
            StringBuilder encryptable = new StringBuilder();
            for (int i = 0; i < withoutTag.length(); i++) {
                char c = withoutTag.charAt(i);
                if (alphabet.indexOf(c) >= 0) {
                    encryptable.append(c);
                } else {
                    ptPositions[ptCount] = i;
                    ptChars[ptCount] = c;
                    ptCount++;
                }
            }

            // 3. Decrypt
            String decrypted;
            if (ff3) {
                decrypted = new FF3(key, new byte[8], alphabet).decrypt(encryptable.toString());
            } else {
                decrypted = new FF1(key, new byte[0], alphabet).decrypt(encryptable.toString());
            }

            // 4. Reinsert passthroughs at original positions
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

    private String protectAesGcm(String value, Policy policy) {
        byte[] key = keyProvider.resolve(policy.keyRef());
        String encrypted = AesGcm.encrypt(value, key);
        if (policy.tagEnabled()) {
            return policy.tag() + encrypted;
        }
        return encrypted;
    }

    private String accessAesGcm(String protectedValue, Policy policy, boolean hasTag) {
        byte[] key = keyProvider.resolve(policy.keyRef());
        String ciphertext = hasTag ? protectedValue.substring(policy.tagLength()) : protectedValue;
        return AesGcm.decrypt(ciphertext, key);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
