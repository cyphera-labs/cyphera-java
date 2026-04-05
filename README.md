# cyphera-java

Data obfuscation SDK for Java. FPE, AES, masking, hashing.

```xml
<dependency>
    <groupId>io.cyphera</groupId>
    <artifactId>cyphera</artifactId>
    <version>0.1.0</version>
</dependency>
```

```java
import io.cyphera.engine.ff1.FF1;

FF1 cipher = FF1.digits(key, tweak);
String encrypted = cipher.encrypt("0123456789");
String decrypted = cipher.decrypt(encrypted);
```

## Status

Early development. FF1 and FF3 engines with all NIST test vectors.

## License

Apache 2.0
