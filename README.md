# cyphera

[![CI](https://github.com/cyphera-labs/cyphera-java/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-java/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/cyphera-java/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-java/actions/workflows/codeql.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.cyphera/cyphera)](https://central.sonatype.com/artifact/io.cyphera/cyphera)
[![Java](https://img.shields.io/badge/java-8%2B-orange)](https://www.oracle.com/java/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Data protection SDK for Java — format-preserving encryption (FF1/FF3), AES-GCM, data masking, and hashing.

## Install

```xml
<dependency>
    <groupId>io.cyphera</groupId>
    <artifactId>cyphera</artifactId>
    <version>0.0.2-alpha.1</version>
</dependency>
```

Available on [Maven Central](https://central.sonatype.com/artifact/io.cyphera/cyphera).

## Usage

```java
import io.cyphera.Cyphera;

// Auto-discover: checks CYPHERA_CONFIG_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json
Cyphera c = Cyphera.load();

// Or load from a specific file
Cyphera c = Cyphera.fromFile("./config/cyphera.json");

// Protect
String encrypted = c.protect("123-45-6789", "ssn");
// → "T01i6J-xF-07pX" (DPH-prefixed, dashes preserved)

// Access (header-based, no configuration name needed)
String decrypted = c.access(encrypted);
// → "123-45-6789"
```

## Configuration File (cyphera.json)

```json
{
  "configurations": {
    "ssn": { "engine": "ff1", "key_ref": "my-key", "header": "T01" }
  },
  "keys": {
    "my-key": { "material": "2B7E151628AED2A6ABF7158809CF4F3C" }
  }
}
```

The `header` (Data Protection Header, DPH) is a short prefix prepended to
protected output that identifies the configuration used. It lets `access()`
reverse a value without the caller naming the configuration.

## Cross-Language Compatible

All SDKs produce identical output for the same inputs:

```
Input:       123-45-6789
Java:        T01i6J-xF-07pX
Rust:        T01i6J-xF-07pX
Node:        T01i6J-xF-07pX
Python:      T01i6J-xF-07pX
Go:          T01i6J-xF-07pX
.NET:        T01i6J-xF-07pX
```

## Status

Alpha. API is unstable. Cross-language test vectors validated against Rust, Node, Python, Go, and .NET implementations.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
