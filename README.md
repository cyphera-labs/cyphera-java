# cyphera

[![CI](https://github.com/cyphera-labs/cyphera-java/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-java/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.cyphera/cyphera)](https://central.sonatype.com/artifact/io.cyphera/cyphera)
[![Java](https://img.shields.io/badge/java-8%2B-orange)](https://www.oracle.com/java/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Data protection SDK for Java — format-preserving encryption (FF1/FF3), AES-GCM, data masking, and hashing.

## Install

```xml
<dependency>
    <groupId>io.cyphera</groupId>
    <artifactId>cyphera</artifactId>
    <version>0.0.1-alpha.2</version>
</dependency>
```

Available on [Maven Central](https://central.sonatype.com/artifact/io.cyphera/cyphera).

## Usage

```java
import io.cyphera.Cyphera;

// Auto-discover: checks CYPHERA_POLICY_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json
Cyphera c = Cyphera.load();

// Or load from a specific file
Cyphera c = Cyphera.fromFile("./config/cyphera.json");

// Protect
String encrypted = c.protect("123-45-6789", "ssn");
// → "T01i6J-xF-07pX" (tagged, dashes preserved)

// Access (tag-based, no policy name needed)
String decrypted = c.access(encrypted);
// → "123-45-6789"
```

## Policy File (cyphera.json)

```json
{
  "policies": {
    "ssn": { "engine": "ff1", "key_ref": "my-key", "tag": "T01" }
  },
  "keys": {
    "my-key": { "material": "2B7E151628AED2A6ABF7158809CF4F3C" }
  }
}
```

## Cross-Language Compatible

Java, Rust, and Node produce identical output for the same inputs:

```
Input:       123-45-6789
Java:        T01i6J-xF-07pX
Rust:        T01i6J-xF-07pX
Node:        T01i6J-xF-07pX
```

## Status

Alpha. API is unstable. Cross-language test vectors validated against Rust and Node implementations.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
