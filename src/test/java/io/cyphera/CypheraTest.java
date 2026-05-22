package io.cyphera;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

public class CypheraTest {

    private static Map<String, Object> buildConfig() {
        Map<String, Object> config = new HashMap<>();

        // Configurations
        Map<String, Object> configurations = new HashMap<>();

        Map<String, Object> ssn = new HashMap<>();
        ssn.put("engine", "ff1");
        ssn.put("key_ref", "demo-key");
        ssn.put("header", "T01");
        // defaults: alphabet=alphanumeric, header_enabled=true, header_length=3
        configurations.put("ssn", ssn);

        Map<String, Object> ssnDigits = new HashMap<>();
        ssnDigits.put("engine", "ff1");
        ssnDigits.put("alphabet", "digits");
        ssnDigits.put("header_enabled", false);
        ssnDigits.put("key_ref", "demo-key");
        configurations.put("ssn_digits", ssnDigits);

        Map<String, Object> ssnMask = new HashMap<>();
        ssnMask.put("engine", "mask");
        ssnMask.put("pattern", "last4");
        ssnMask.put("header_enabled", false);
        configurations.put("ssn_mask", ssnMask);

        Map<String, Object> ssnHash = new HashMap<>();
        ssnHash.put("engine", "hash");
        ssnHash.put("algorithm", "sha256");
        ssnHash.put("key_ref", "demo-key");
        ssnHash.put("header_enabled", false);
        configurations.put("ssn_hash", ssnHash);

        config.put("configurations", configurations);

        // Keys
        Map<String, Object> keys = new HashMap<>();
        Map<String, Object> demoKey = new HashMap<>();
        demoKey.put("material", "2B7E151628AED2A6ABF7158809CF4F3C");
        keys.put("demo-key", demoKey);
        config.put("keys", keys);

        return config;
    }

    @Test
    void protectAndAccessWithHeader() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        String ssn = "123456789";

        String protectedVal = c.protect(ssn, "ssn");
        assertNotEquals(ssn, protectedVal);
        assertTrue(protectedVal.length() > ssn.length()); // header adds chars

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
    void protectAndAccessUnHeaderedDigits() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        String ssn = "123456789";

        String protectedVal = c.protect(ssn, "ssn_digits");
        assertEquals(ssn.length(), protectedVal.length()); // no header, same length

        // ssn_digits has header_enabled=false, so the 2-arg access overload
        // (escape hatch) is the way to round-trip without a header to key off.
        String accessed = c.access(protectedVal, "ssn_digits");
        assertEquals(ssn, accessed);
    }

    @Test
    void protectMask() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        String result = c.protect("123-45-6789", "ssn_mask");
        assertEquals("*******6789", result);
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
        // ssn_mask has header_enabled=false, so access() will fail to find a
        // matching header rather than dispatching into the mask engine.
        assertThrows(IllegalArgumentException.class, () -> c.access(masked));
    }

    @Test
    void accessUnknownHeaderThrows() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        assertThrows(IllegalArgumentException.class, () -> c.access("zzz123456789"));
    }

    @Test
    void accessTwoArgOnIrreversibleConfigurationThrows() {
        Cyphera c = Cyphera.fromMap(buildConfig());
        // The 2-arg escape hatch is permissive about header_enabled, but
        // still must refuse mask/hash configurations -- those are one-way.
        String masked = c.protect("123-45-6789", "ssn_mask");
        assertThrows(IllegalArgumentException.class, () -> c.access(masked, "ssn_mask"));
    }

    @Test
    void headerCollisionThrows() {
        Map<String, Object> config = buildConfig();
        @SuppressWarnings("unchecked")
        Map<String, Object> configurations = (Map<String, Object>) config.get("configurations");

        // Force two configurations with the same header
        Map<String, Object> c1 = new HashMap<>();
        c1.put("engine", "ff1");
        c1.put("key_ref", "demo-key");
        c1.put("header", "ABC");
        configurations.put("configuration_a", c1);

        Map<String, Object> c2 = new HashMap<>();
        c2.put("engine", "ff1");
        c2.put("key_ref", "demo-key");
        c2.put("header", "ABC");
        configurations.put("configuration_b", c2);

        assertThrows(IllegalArgumentException.class, () -> Cyphera.fromMap(config));
    }

    @Test
    void protectAndAccessAesGcm() {
        Map<String, Object> config = buildConfig();
        @SuppressWarnings("unchecked")
        Map<String, Object> configurations = (Map<String, Object>) config.get("configurations");

        Map<String, Object> aesConfiguration = new HashMap<>();
        aesConfiguration.put("engine", "aes_gcm");
        aesConfiguration.put("key_ref", "demo-key");
        aesConfiguration.put("header", "T02");
        configurations.put("ssn_aes", aesConfiguration);

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
