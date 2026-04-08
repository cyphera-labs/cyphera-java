# cyphera

Data protection SDK for Java — format-preserving encryption (FF1/FF3), AES-GCM, data masking, and hashing. Zero runtime dependencies.

## Install

```xml
<dependency>
    <groupId>io.cyphera</groupId>
    <artifactId>cyphera</artifactId>
    <version>0.0.1-alpha.1</version>
</dependency>
```

Available on [Maven Central](https://central.sonatype.com/artifact/io.cyphera/cyphera).

## Usage

```java
import io.cyphera.Cyphera;
import java.util.HashMap;
import java.util.Map;

Map<String, Object> config = new HashMap<>();

Map<String, Object> policies = new HashMap<>();
Map<String, Object> ssn = new HashMap<>();
ssn.put("engine", "ff1");
ssn.put("key_ref", "my-key");
ssn.put("tag", "T01");
policies.put("ssn", ssn);
config.put("policies", policies);

Map<String, Object> keys = new HashMap<>();
Map<String, Object> key = new HashMap<>();
key.put("material", "2B7E151628AED2A6ABF7158809CF4F3C");
keys.put("my-key", key);
config.put("keys", keys);

Cyphera c = Cyphera.fromMap(config);

// Protect
String encrypted = c.protect("123-45-6789", "ssn");
// → "T01k7R-m2-9xPq" (tagged, dashes preserved)

// Access (tag-based, no policy name needed)
String decrypted = c.access(encrypted);
// → "123-45-6789"
```

## Status

Alpha. API is unstable. Cross-language test vectors validated against Rust implementation.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
