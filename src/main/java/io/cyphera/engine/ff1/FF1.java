package io.cyphera.engine.ff1;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * FF1 Format-Preserving Encryption (NIST SP 800-38G).
 * Ported from cyphera-rust FF1 implementation.
 */
public class FF1 {
    private final int radix;
    private final byte[] key;
    private final byte[] tweak;
    private final String alphabet;
    private final SecretKeySpec keySpec;

    public FF1(byte[] key, byte[] tweak, String alphabet) throws Exception {
        if (alphabet.length() < 2)
            throw new IllegalArgumentException("Alphabet must have >= 2 chars");
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new IllegalArgumentException("Key must be 16, 24, or 32 bytes");

        this.radix = alphabet.length();
        this.alphabet = alphabet;
        this.key = key.clone();
        this.tweak = tweak.clone();
        this.keySpec = new SecretKeySpec(key, "AES");
    }

    public String encrypt(String plaintext) throws Exception {
        if (plaintext.isEmpty())
            throw new IllegalArgumentException("Input must not be empty");
        // NIST SP 800-38G: radix^minlen >= 1,000,000
        double domainSize = Math.pow(radix, plaintext.length());
        if (domainSize < 1_000_000)
            throw new IllegalArgumentException("Input too short: " + plaintext.length()
                + " chars with radix " + radix + " (domain size " + (long) domainSize
                + " < 1,000,000 minimum)");

        int[] digits = toDigits(plaintext);
        int[] result = ff1Encrypt(digits, tweak);
        return fromDigits(result);
    }

    public String decrypt(String ciphertext) throws Exception {
        if (ciphertext.isEmpty())
            throw new IllegalArgumentException("Input must not be empty");
        double domainSize = Math.pow(radix, ciphertext.length());
        if (domainSize < 1_000_000)
            throw new IllegalArgumentException("Input too short: " + ciphertext.length()
                + " chars with radix " + radix + " (domain size " + (long) domainSize
                + " < 1,000,000 minimum)");
        int[] digits = toDigits(ciphertext);
        int[] result = ff1Decrypt(digits, tweak);
        return fromDigits(result);
    }

    private int[] ff1Encrypt(int[] pt, byte[] T) throws Exception {
        int n = pt.length;
        int u = n / 2, v = n - u;
        int[] A = Arrays.copyOfRange(pt, 0, u);
        int[] B = Arrays.copyOfRange(pt, u, n);

        int b = computeB(v);
        int d = 4 * ((b + 3) / 4) + 4;
        byte[] P = buildP(u, n, T.length);

        for (int i = 0; i < 10; i++) {
            BigInteger numB = toNum(B);
            byte[] numBBytes = bigIntToBytes(numB, b);
            byte[] Q = buildQ(T, i, numBBytes, b);
            byte[] PQ = concat(P, Q);
            byte[] R = prf(PQ);
            byte[] S = expandS(R, d);
            BigInteger y = new BigInteger(1, S);

            int m = (i % 2 == 0) ? u : v;
            BigInteger c = toNum(A).add(y).mod(BigInteger.valueOf(radix).pow(m));
            A = B;
            B = fromNum(c, m);
        }

        int[] result = new int[n];
        System.arraycopy(A, 0, result, 0, A.length);
        System.arraycopy(B, 0, result, A.length, B.length);
        return result;
    }

    private int[] ff1Decrypt(int[] ct, byte[] T) throws Exception {
        int n = ct.length;
        int u = n / 2, v = n - u;
        int[] A = Arrays.copyOfRange(ct, 0, u);
        int[] B = Arrays.copyOfRange(ct, u, n);

        int b = computeB(v);
        int d = 4 * ((b + 3) / 4) + 4;
        byte[] P = buildP(u, n, T.length);

        for (int i = 9; i >= 0; i--) {
            BigInteger numA = toNum(A);
            byte[] numABytes = bigIntToBytes(numA, b);
            byte[] Q = buildQ(T, i, numABytes, b);
            byte[] PQ = concat(P, Q);
            byte[] R = prf(PQ);
            byte[] S = expandS(R, d);
            BigInteger y = new BigInteger(1, S);

            int m = (i % 2 == 0) ? u : v;
            BigInteger mod = BigInteger.valueOf(radix).pow(m);
            BigInteger c = toNum(B).subtract(y).mod(mod);
            if (c.signum() < 0) c = c.add(mod);
            B = A;
            A = fromNum(c, m);
        }

        int[] result = new int[n];
        System.arraycopy(A, 0, result, 0, A.length);
        System.arraycopy(B, 0, result, A.length, B.length);
        return result;
    }

    private int computeB(int v) {
        BigInteger pow = BigInteger.valueOf(radix).pow(v).subtract(BigInteger.ONE);
        return (pow.bitLength() + 7) / 8;
    }

    private byte[] buildP(int u, int n, int t) {
        byte[] P = new byte[16];
        P[0] = 1; P[1] = 2; P[2] = 1;
        P[3] = (byte) (radix >> 16); P[4] = (byte) (radix >> 8); P[5] = (byte) radix;
        P[6] = 10; P[7] = (byte) u;
        P[8] = (byte) (n >> 24); P[9] = (byte) (n >> 16); P[10] = (byte) (n >> 8); P[11] = (byte) n;
        P[12] = (byte) (t >> 24); P[13] = (byte) (t >> 16); P[14] = (byte) (t >> 8); P[15] = (byte) t;
        return P;
    }

    private byte[] buildQ(byte[] T, int i, byte[] numBytes, int b) {
        int pad = (16 - ((T.length + 1 + b) % 16)) % 16;
        byte[] Q = new byte[T.length + pad + 1 + b];
        System.arraycopy(T, 0, Q, 0, T.length);
        Q[T.length + pad] = (byte) i;
        int destStart = Q.length - numBytes.length;
        if (destStart >= T.length + pad + 1) {
            System.arraycopy(numBytes, 0, Q, destStart, numBytes.length);
        } else {
            int srcStart = numBytes.length - b;
            if (srcStart < 0) srcStart = 0;
            System.arraycopy(numBytes, srcStart, Q, Q.length - (numBytes.length - srcStart), numBytes.length - srcStart);
        }
        return Q;
    }

    private byte[] prf(byte[] data) throws Exception {
        // NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
        // This is single-block encryption used as a building block, not ECB mode applied to user data.
        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] y = new byte[16];
        for (int off = 0; off < data.length; off += 16) {
            byte[] tmp = new byte[16];
            for (int j = 0; j < 16; j++) tmp[j] = (byte) (y[j] ^ data[off + j]);
            y = aes.doFinal(tmp);
        }
        return y;
    }

    private byte[] expandS(byte[] R, int d) throws Exception {
        // NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
        // This is single-block encryption used as a building block, not ECB mode applied to user data.
        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, keySpec);
        int blocks = (d + 15) / 16;
        byte[] out = new byte[blocks * 16];
        System.arraycopy(R, 0, out, 0, 16);
        for (int j = 1; j < blocks; j++) {
            byte[] x = new byte[16];
            // [j]^16 — j as 16-byte big-endian integer
            x[12] = (byte) (j >> 24); x[13] = (byte) (j >> 16);
            x[14] = (byte) (j >> 8); x[15] = (byte) j;
            // XOR with R (not previous block) per NIST SP 800-38G
            for (int k = 0; k < 16; k++) x[k] ^= R[k];
            byte[] enc = aes.doFinal(x);
            System.arraycopy(enc, 0, out, j * 16, 16);
        }
        return Arrays.copyOf(out, d);
    }

    private byte[] bigIntToBytes(BigInteger x, int b) {
        byte[] bytes = x.toByteArray();
        if (bytes.length >= b) return Arrays.copyOfRange(bytes, bytes.length - b, bytes.length);
        byte[] result = new byte[b];
        System.arraycopy(bytes, 0, result, b - bytes.length, bytes.length);
        return result;
    }

    private int[] toDigits(String s) {
        int[] d = new int[s.length()];
        for (int i = 0; i < s.length(); i++) {
            int idx = alphabet.indexOf(s.charAt(i));
            if (idx == -1) throw new IllegalArgumentException("Invalid char: " + s.charAt(i));
            d[i] = idx;
        }
        return d;
    }

    private String fromDigits(int[] d) {
        StringBuilder sb = new StringBuilder(d.length);
        for (int v : d) sb.append(alphabet.charAt(v));
        return sb.toString();
    }

    private BigInteger toNum(int[] d) {
        BigInteger r = BigInteger.ZERO, b = BigInteger.valueOf(radix);
        for (int v : d) r = r.multiply(b).add(BigInteger.valueOf(v));
        return r;
    }

    private int[] fromNum(BigInteger num, int len) {
        int[] r = new int[len]; BigInteger b = BigInteger.valueOf(radix);
        for (int i = len - 1; i >= 0; i--) { r[i] = num.mod(b).intValue(); num = num.divide(b); }
        return r;
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    // Factory methods
    public static FF1 digits(byte[] key, byte[] tweak) throws Exception {
        return new FF1(key, tweak, "0123456789");
    }

    public static FF1 alphanumeric(byte[] key, byte[] tweak) throws Exception {
        return new FF1(key, tweak, "0123456789abcdefghijklmnopqrstuvwxyz");
    }

    public static byte[] hexToBytes(String hex) {
        byte[] r = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2)
            r[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        return r;
    }
}
