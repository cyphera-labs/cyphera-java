package io.cyphera;

import java.util.HashMap;
import java.util.Map;

public final class MemoryKeyProvider implements KeyProvider {
    private final Map<String, byte[]> keys = new HashMap<>();

    @SuppressWarnings("unchecked")
    public MemoryKeyProvider(Map<String, Object> keysMap) {
        for (Map.Entry<String, Object> entry : keysMap.entrySet()) {
            String name = entry.getKey();
            Object val = entry.getValue();
            if (val instanceof Map) {
                String material = (String) ((Map<String, Object>) val).get("material");
                if (material != null) {
                    keys.put(name, hexToBytes(material));
                }
            } else if (val instanceof String) {
                keys.put(name, hexToBytes((String) val));
            }
        }
    }

    @Override
    public byte[] resolve(String keyRef) {
        byte[] key = keys.get(keyRef);
        if (key == null) throw new IllegalArgumentException("Unknown key: " + keyRef);
        return key;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] r = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2)
            r[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        return r;
    }
}
