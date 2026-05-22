package io.cyphera.engine.ff3;

/**
 * FF3-1 Format-Preserving Encryption (NIST SP 800-38G Revision 1).
 *
 * FF3-1 is FF3 with a 56-bit (7-byte) tweak. The tweak is expanded into the
 * 64-bit form the FF3 round function consumes; everything downstream is
 * identical FF3. FF3-1 supersedes the original FF3, which is cryptographically
 * weak.
 */
public class FF31 {
    private final FF3 inner;

    /** Create an FF3-1 cipher. {@code tweak} MUST be exactly 7 bytes (56 bits). */
    public FF31(byte[] key, byte[] tweak, String alphabet) throws Exception {
        if (tweak.length != 7)
            throw new IllegalArgumentException("FF3-1 tweak must be exactly 7 bytes (56 bits)");
        this.inner = new FF3(key, expandTweak(tweak), alphabet);
    }

    /**
     * Expand the 56-bit FF3-1 tweak into the 64-bit tweak the FF3 round
     * function consumes (NIST SP 800-38G Rev 1), with bytes[0..4] = T_L and
     * bytes[4..8] = T_R.
     */
    private static byte[] expandTweak(byte[] t) {
        return new byte[] {
            t[0], t[1], t[2], (byte) (t[3] & 0xF0),
            t[4], t[5], t[6], (byte) ((t[3] & 0x0F) << 4),
        };
    }

    public String encrypt(String plaintext) throws Exception {
        return inner.encrypt(plaintext);
    }

    public String decrypt(String ciphertext) throws Exception {
        return inner.decrypt(ciphertext);
    }
}
