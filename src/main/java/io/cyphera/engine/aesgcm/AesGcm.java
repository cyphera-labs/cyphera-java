package io.cyphera.engine.aesgcm;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public final class AesGcm {
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int NONCE_LENGTH = 12; // bytes

    private AesGcm() {}

    /**
     * Encrypt with AES-GCM. Returns base64(nonce + ciphertext + tag).
     */
    public static String encrypt(String plaintext, byte[] key) {
        try {
            byte[] nonce = new byte[NONCE_LENGTH];
            new SecureRandom().nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                        new GCMParameterSpec(GCM_TAG_LENGTH, nonce));

            byte[] ct = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            // nonce + ciphertext+tag
            byte[] output = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, output, 0, nonce.length);
            System.arraycopy(ct, 0, output, nonce.length, ct.length);

            return Base64.getEncoder().encodeToString(output);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypt AES-GCM. Input is base64(nonce + ciphertext + tag).
     */
    public static String decrypt(String encoded, byte[] key) {
        try {
            byte[] data = Base64.getDecoder().decode(encoded);

            byte[] nonce = new byte[NONCE_LENGTH];
            System.arraycopy(data, 0, nonce, 0, NONCE_LENGTH);

            byte[] ct = new byte[data.length - NONCE_LENGTH];
            System.arraycopy(data, NONCE_LENGTH, ct, 0, ct.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                        new GCMParameterSpec(GCM_TAG_LENGTH, nonce));

            byte[] pt = cipher.doFinal(ct);
            return new String(pt, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decryption failed: " + e.getMessage(), e);
        }
    }
}
