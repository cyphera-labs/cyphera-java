package io.cyphera;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

public class CypheraTest {

    private static Map<String, Object> buildConfig() {
        Map<String, Object> config = new HashMap<>();

        // Policies
        Map<String, Object> policies = new HashMap<>();

        Map<String, Object> ssn = new HashMap<>();
        ssn.put("engine", "ff1");
        ssn.put("key_ref", "demo-key");
        // defaults: alphabet=alphanumeric, tag_enabled=true, tag_length=3
        policies.put("ssn", ssn);

        Map<String, Object> ssnDigits = new HashMap<>();
        ssnDigits.put("engine", "ff1");
        ssnDigits.put("alphabet", "digits");
        ssnDigits.put("tag_enabled", false);
        ssnDigits.put("key_ref", "demo-key");
        policies.put("ssn_digits", ssnDigits);

        Map<String, Object> ssnMask = new HashMap<>();
        ssnMask.put("engine", "mask");
        ssnMask.put("pattern", "***-**-{last4}");
        policies.put("ssn_mask", ssnMask);

        Map<String, Object> ssnHash = new HashMap<>();
        ssnHash.put("engine", "hash");
        ssnHash.put("algorithm", "sha256");
        ssnHash.put("key_ref", "demo-key");
        policies.put("ssn_hash", ssnHash);

        config.put("policies", policies);

        // Keys
        Map<String, Object> keys = new HashMap<>();
        Map<String, Object> demoKey = new HashMap<>();
        demoKey.put("material", "2B7E151628AED2A6ABF7158809CF4F3C");
        keys.put("demo-key", demoKey);
        config.put("keys", keys);

        return config;
    }

    @Test
    void protectAndAccessWithTag() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        String ssn = "123456789";

        String protectedVal = c.protect(ssn, "ssn");
        assertNotEquals(ssn, protectedVal);
        assertTrue(protectedVal.length() > ssn.length()); // tag adds chars

        String accessed = c.access(protectedVal);
        assertEquals(ssn, accessed);
    }

    @Test
    void protectAndAccessWithPassthrough() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        String ssn = "123-45-6789";

        String protectedVal = c.protect(ssn, "ssn");
        // Dashes should be preserved somewhere in the output
        assertTrue(protectedVal.contains("-"));

        String accessed = c.access(protectedVal);
        assertEquals(ssn, accessed);
    }

    @Test
    void protectAndAccessUntaggedDigits() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        String ssn = "123456789";

        String protectedVal = c.protect(ssn, "ssn_digits");
        assertEquals(ssn.length(), protectedVal.length()); // no tag, same length

        String accessed = c.access(protectedVal, "ssn_digits");
        assertEquals(ssn, accessed);
    }

    @Test
    void protectMask() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        String result = c.protect("123-45-6789", "ssn_mask");
        assertEquals("***-**-6789", result);
    }

    @Test
    void protectHash() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        String result1 = c.protect("123-45-6789", "ssn_hash");
        String result2 = c.protect("123-45-6789", "ssn_hash");
        // Deterministic
        assertEquals(result1, result2);
        // Looks like hex
        assertTrue(result1.matches("[0-9a-f]+"));
    }

    @Test
    void accessNonReversibleThrows() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        String masked = c.protect("123-45-6789", "ssn_mask");
        assertThrows(IllegalArgumentException.class, () -> c.access(masked));
    }

    @Test
    void accessUnknownTagThrows() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        assertThrows(IllegalArgumentException.class, () -> c.access("zzz123456789"));
    }

    @Test
    void tagCollisionThrows() {
        Map<String, Object> config = buildConfig();
        @SuppressWarnings("unchecked")
        Map<String, Object> policies = (Map<String, Object>) config.get("policies");

        // Force two policies with the same tag
        Map<String, Object> p1 = new HashMap<>();
        p1.put("engine", "ff1");
        p1.put("key_ref", "demo-key");
        p1.put("tag", "ABC");
        policies.put("policy_a", p1);

        Map<String, Object> p2 = new HashMap<>();
        p2.put("engine", "ff1");
        p2.put("key_ref", "demo-key");
        p2.put("tag", "ABC");
        policies.put("policy_b", p2);

        assertThrows(IllegalArgumentException.class, () -> Cyphera.fromMap(config));
    }

    @Test
    void protectAndAccessAesGcm() {
        Map<String, Object> config = buildConfig();
        @SuppressWarnings("unchecked")
        Map<String, Object> policies = (Map<String, Object>) config.get("policies");

        Map<String, Object> aesPolicy = new HashMap<>();
        aesPolicy.put("engine", "aes_gcm");
        aesPolicy.put("key_ref", "demo-key");
        policies.put("ssn_aes", aesPolicy);

        Cyphera c = Cyphera.fromMap(config);
        String input = "123-45-6789";

        String protectedVal = c.protect(input, "ssn_aes");
        assertNotEquals(input, protectedVal);

        // AES-GCM is not deterministic (random nonce), so protect twice gives different output
        String protectedVal2 = c.protect(input, "ssn_aes");
        assertNotEquals(protectedVal, protectedVal2);

        // But both decrypt to the same input
        assertEquals(input, c.access(protectedVal));
        assertEquals(input, c.access(protectedVal2));
    }
}
