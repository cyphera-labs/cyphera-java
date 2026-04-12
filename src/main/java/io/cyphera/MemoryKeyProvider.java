package io.cyphera;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public final class MemoryKeyProvider implements KeyProvider {
    private final Map<String, byte[]> keys = new HashMap<>();

    private static final HashSet<String> CLOUD_SOURCES = new HashSet<>(Arrays.asList("aws-kms", "gcp-kms", "azure-kv", "vault"));

    @SuppressWarnings("unchecked")
    public MemoryKeyProvider(Map<String, Object> keysMap) {
        for (Map.Entry<String, Object> entry : keysMap.entrySet()) {
            String name = entry.getKey();
            Object val = entry.getValue();
            if (val instanceof String) {
                keys.put(name, hexToBytes((String) val));
            } else if (val instanceof Map) {
                Map<String, Object> config = (Map<String, Object>) val;
                if (config.containsKey("material")) {
                    keys.put(name, hexToBytes((String) config.get("material")));
                } else if (config.containsKey("source")) {
                    keys.put(name, resolveSource(name, config));
                } else {
                    throw new IllegalArgumentException("Key '" + name + "' must have either 'material' or 'source'");
                }
            }
        }
    }

    @Override
    public byte[] resolve(String keyRef) {
        byte[] key = keys.get(keyRef);
        if (key == null) throw new IllegalArgumentException("Unknown key: " + keyRef);
        return key;
    }

    @SuppressWarnings("unchecked")
    private static byte[] resolveSource(String name, Map<String, Object> config) {
        String source = (String) config.get("source");

        if ("env".equals(source)) {
            String varName = (String) config.get("var");
            if (varName == null) throw new IllegalArgumentException("Key '" + name + "': source 'env' requires 'var' field");
            String val = System.getenv(varName);
            if (val == null || val.isEmpty()) throw new IllegalArgumentException("Key '" + name + "': environment variable '" + varName + "' is not set");
            String encoding = (String) config.getOrDefault("encoding", "hex");
            if ("base64".equals(encoding)) return Base64.getDecoder().decode(val);
            return hexToBytes(val);
        }

        if ("file".equals(source)) {
            String path = (String) config.get("path");
            if (path == null) throw new IllegalArgumentException("Key '" + name + "': source 'file' requires 'path' field");
            try {
                String raw = new String(Files.readAllBytes(Paths.get(path))).trim();
                String encoding = (String) config.get("encoding");
                if (encoding == null) {
                    encoding = (path.endsWith(".b64") || path.endsWith(".base64")) ? "base64" : "hex";
                }
                if ("base64".equals(encoding)) return Base64.getDecoder().decode(raw);
                return hexToBytes(raw);
            } catch (IOException e) {
                throw new IllegalArgumentException("Key '" + name + "': failed to read file '" + path + "': " + e.getMessage());
            }
        }

        if (CLOUD_SOURCES.contains(source)) {
            try {
                Class<?> resolverClass = Class.forName("dev.cyphera.keychain.KeychainResolver");
                java.lang.reflect.Method method = resolverClass.getMethod("resolve", String.class, Map.class);
                return (byte[]) method.invoke(null, source, config);
            } catch (ClassNotFoundException e) {
                throw new IllegalArgumentException(
                    "Key '" + name + "' requires source '" + source + "' but cyphera-keychain is not on the classpath.\n"
                    + "Add dependency: io.cyphera:cyphera-keychain"
                );
            } catch (Exception e) {
                throw new RuntimeException("Key '" + name + "': keychain resolution failed: " + e.getMessage(), e);
            }
        }

        throw new IllegalArgumentException("Key '" + name + "': unknown source '" + source + "'. Valid: env, file, " + String.join(", ", CLOUD_SOURCES));
    }

    private static byte[] hexToBytes(String hex) {
        byte[] r = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2)
            r[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        return r;
    }
}
