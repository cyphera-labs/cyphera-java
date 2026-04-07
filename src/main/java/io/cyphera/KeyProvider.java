package io.cyphera;

public interface KeyProvider {
    byte[] resolve(String keyRef);
}
