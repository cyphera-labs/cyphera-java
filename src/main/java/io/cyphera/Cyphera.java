package io.cyphera;

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
            default: throw new IllegalArgumentException("Unknown engine: " + engine);
        }
    }

    /**
     * Access (decrypt/reverse) a protected value.
     * If tagged, the policy is determined from the tag automatically.
     * If untagged, the policyName must be provided.
     */
    public String access(String protectedValue) {
        // Try to find a tag match
        for (Map.Entry<String, Policy> e : tagIndex.entrySet()) {
            String tag = e.getKey();
            Policy policy = e.getValue();

            // Extract first N encryptable chars and check if they match the tag
            String extracted = extractTag(protectedValue, policy.alphabet(), tag.length());
            if (tag.equals(extracted)) {
                return accessWithPolicy(protectedValue, policy, true);
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

    // -- Internal: FF1 protect --

    private String protectFf1(String value, Policy policy) {
        try {
            byte[] key = keyProvider.resolve(policy.keyRef());
            String alphabet = policy.alphabet();

            // Separate encryptable chars from passthrough chars
            StringBuilder encryptable = new StringBuilder();
            boolean[] isPassthrough = new boolean[value.length()];
            char[] passthroughChars = new char[value.length()];

            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (alphabet.indexOf(c) >= 0) {
                    encryptable.append(c);
                    isPassthrough[i] = false;
                } else {
                    isPassthrough[i] = true;
                    passthroughChars[i] = c;
                }
            }

            FF1 ff1 = new FF1(key, new byte[0], alphabet);
            String encrypted = ff1.encrypt(encryptable.toString());

            // Prepend tag to encrypted chars
            String taggedCipher = policy.tagEnabled() ? policy.tag() + encrypted : encrypted;

            // Reinsert passthrough chars at original positions
            return reinsertPassthrough(taggedCipher, isPassthrough, passthroughChars, value.length(),
                                       policy.tagEnabled() ? policy.tagLength() : 0);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("FF1 encryption failed: " + e.getMessage(), e);
        }
    }

    // -- Internal: FF3 protect --

    private String protectFf3(String value, Policy policy) {
        try {
            byte[] key = keyProvider.resolve(policy.keyRef());
            String alphabet = policy.alphabet();

            StringBuilder encryptable = new StringBuilder();
            boolean[] isPassthrough = new boolean[value.length()];
            char[] passthroughChars = new char[value.length()];

            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (alphabet.indexOf(c) >= 0) {
                    encryptable.append(c);
                } else {
                    isPassthrough[i] = true;
                    passthroughChars[i] = c;
                }
            }

            // FF3 requires 8-byte tweak -- use zeroes as default
            FF3 ff3 = new FF3(key, new byte[8], alphabet);
            String encrypted = ff3.encrypt(encryptable.toString());

            String taggedCipher = policy.tagEnabled() ? policy.tag() + encrypted : encrypted;

            return reinsertPassthrough(taggedCipher, isPassthrough, passthroughChars, value.length(),
                                       policy.tagEnabled() ? policy.tagLength() : 0);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("FF3 encryption failed: " + e.getMessage(), e);
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
            default: throw new IllegalArgumentException("Access not supported for engine: " + engine);
        }
    }

    private String accessFf1(String protectedValue, Policy policy, boolean hasTag) {
        try {
            byte[] key = keyProvider.resolve(policy.keyRef());
            String alphabet = policy.alphabet();

            // Extract encryptable chars (skip passthrough)
            StringBuilder encryptable = new StringBuilder();
            for (int i = 0; i < protectedValue.length(); i++) {
                char c = protectedValue.charAt(i);
                if (alphabet.indexOf(c) >= 0) {
                    encryptable.append(c);
                }
            }

            String cipherChars = encryptable.toString();

            // Strip tag if present
            if (hasTag && policy.tag() != null) {
                cipherChars = cipherChars.substring(policy.tagLength());
            }

            FF1 ff1 = new FF1(key, new byte[0], alphabet);
            String decrypted = ff1.decrypt(cipherChars);

            // Reinsert passthrough chars at their original positions (minus tag offset)
            return reinsertPassthroughForAccess(decrypted, protectedValue, alphabet,
                                                 hasTag ? policy.tagLength() : 0);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("FF1 decryption failed: " + e.getMessage(), e);
        }
    }

    private String accessFf3(String protectedValue, Policy policy, boolean hasTag) {
        try {
            byte[] key = keyProvider.resolve(policy.keyRef());
            String alphabet = policy.alphabet();

            StringBuilder encryptable = new StringBuilder();
            for (int i = 0; i < protectedValue.length(); i++) {
                char c = protectedValue.charAt(i);
                if (alphabet.indexOf(c) >= 0) {
                    encryptable.append(c);
                }
            }

            String cipherChars = encryptable.toString();
            if (hasTag && policy.tag() != null) {
                cipherChars = cipherChars.substring(policy.tagLength());
            }

            FF3 ff3 = new FF3(key, new byte[8], alphabet);
            String decrypted = ff3.decrypt(cipherChars);

            return reinsertPassthroughForAccess(decrypted, protectedValue, alphabet,
                                                 hasTag ? policy.tagLength() : 0);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("FF3 decryption failed: " + e.getMessage(), e);
        }
    }

    // -- Passthrough helpers --

    /**
     * Extract the first N encryptable characters from a value (skipping passthrough chars).
     */
    private String extractTag(String value, String alphabet, int tagLength) {
        StringBuilder sb = new StringBuilder(tagLength);
        for (int i = 0; i < value.length() && sb.length() < tagLength; i++) {
            if (alphabet.indexOf(value.charAt(i)) >= 0) {
                sb.append(value.charAt(i));
            }
        }
        return sb.toString();
    }

    /**
     * Reinsert passthrough characters from the original value into the cipher output.
     * The output is longer than the input by tagLength chars (the tag adds characters).
     */
    private String reinsertPassthrough(String cipherChars, boolean[] isPassthrough,
                                        char[] passthroughChars, int origLen, int tagExtra) {
        int totalLen = origLen + tagExtra;
        StringBuilder result = new StringBuilder(totalLen);
        int cipherIdx = 0;

        // Build the output: passthrough chars stay in their original positions,
        // cipher chars fill the rest, extra tag chars extend the end
        for (int i = 0; i < origLen; i++) {
            if (isPassthrough[i]) {
                result.append(passthroughChars[i]);
            } else {
                if (cipherIdx < cipherChars.length()) {
                    result.append(cipherChars.charAt(cipherIdx++));
                }
            }
        }
        // Append remaining cipher chars (from the tag extension)
        while (cipherIdx < cipherChars.length()) {
            result.append(cipherChars.charAt(cipherIdx++));
        }

        return result.toString();
    }

    /**
     * For access: reconstruct plaintext with passthrough chars from the protected value.
     * The protected value is longer than the original by tagLength.
     */
    private String reinsertPassthroughForAccess(String decrypted, String protectedValue,
                                                  String alphabet, int tagExtra) {
        // The original had (protectedValue.length - tagExtra) total chars
        int origLen = protectedValue.length() - tagExtra;
        StringBuilder result = new StringBuilder(origLen);
        int decIdx = 0;
        int encCount = 0; // count of encryptable chars seen

        // Walk the protected value, skip tag chars, preserve passthroughs
        for (int i = 0; i < protectedValue.length() && result.length() < origLen; i++) {
            char c = protectedValue.charAt(i);
            if (alphabet.indexOf(c) >= 0) {
                encCount++;
                if (encCount <= tagExtra) {
                    continue; // skip tag chars
                }
                if (decIdx < decrypted.length()) {
                    result.append(decrypted.charAt(decIdx++));
                }
            } else {
                result.append(c); // passthrough
            }
        }

        return result.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
