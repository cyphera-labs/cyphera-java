package io.cyphera.engine.ff3;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * FF3-1 Format-Preserving Encryption (NIST SP 800-38G Rev 1).
 * Ported from fpe-arena Java implementation.
 */
public class FF3 {
    private final int radix;
    private final byte[] key;
    private final byte[] tweak;
    private final String alphabet;

    public FF3(byte[] key, byte[] tweak, String alphabet) throws Exception {
        if (alphabet.length() < 2 || alphabet.length() > 62)
            throw new IllegalArgumentException("Alphabet must be 2-62 chars");
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new IllegalArgumentException("Key must be 16, 24, or 32 bytes");
        if (tweak.length != 8)
            throw new IllegalArgumentException("Tweak must be exactly 8 bytes");

        this.radix = alphabet.length();
        this.alphabet = alphabet;
        this.tweak = tweak.clone();
        this.key = new byte[key.length];
        for (int i = 0; i < key.length; i++)
            this.key[i] = key[key.length - 1 - i];
    }

    public String encrypt(String plaintext) throws Exception {
        if (plaintext.isEmpty())
            throw new IllegalArgumentException("Input must not be empty");
        if (plaintext.length() < 2)
            throw new IllegalArgumentException("FF3 requires at least 2 characters");
        double domainSize = Math.pow(radix, plaintext.length());
        if (domainSize < 1_000_000)
            throw new IllegalArgumentException("Input too short: " + plaintext.length()
                + " chars with radix " + radix + " (domain size " + (long) domainSize
                + " < 1,000,000 minimum)");
        int[] digits = toDigits(plaintext);
        int[] result = ff3Encrypt(digits);
        return fromDigits(result);
    }

    public String decrypt(String ciphertext) throws Exception {
        if (ciphertext.isEmpty())
            throw new IllegalArgumentException("Input must not be empty");
        if (ciphertext.length() < 2)
            throw new IllegalArgumentException("FF3 requires at least 2 characters");
        double domainSize = Math.pow(radix, ciphertext.length());
        if (domainSize < 1_000_000)
            throw new IllegalArgumentException("Input too short: " + ciphertext.length()
                + " chars with radix " + radix + " (domain size " + (long) domainSize
                + " < 1,000,000 minimum)");
        int[] digits = toDigits(ciphertext);
        int[] result = ff3Decrypt(digits);
        return fromDigits(result);
    }

    private int[] ff3Encrypt(int[] pt) throws Exception {
        int n = pt.length, u = (n + 1) / 2, v = n - u;
        int[] A = Arrays.copyOfRange(pt, 0, u);
        int[] B = Arrays.copyOfRange(pt, u, n);

        for (int i = 0; i < 8; i++) {
            if (i % 2 == 0) {
                byte[] W = calcW(i); BigInteger P = calcP(i, W, B);
                BigInteger m = BigInteger.valueOf(radix).pow(u);
                BigInteger aNum = toNum(reverse(A));
                int[] c = fromNum(aNum.add(P).mod(m), u);
                A = reverse(c);
            } else {
                byte[] W = calcW(i); BigInteger P = calcP(i, W, A);
                BigInteger m = BigInteger.valueOf(radix).pow(v);
                BigInteger bNum = toNum(reverse(B));
                int[] c = fromNum(bNum.add(P).mod(m), v);
                B = reverse(c);
            }
        }
        int[] result = new int[n];
        System.arraycopy(A, 0, result, 0, u);
        System.arraycopy(B, 0, result, u, v);
        return result;
    }

    private int[] ff3Decrypt(int[] ct) throws Exception {
        int n = ct.length, u = (n + 1) / 2, v = n - u;
        int[] A = Arrays.copyOfRange(ct, 0, u);
        int[] B = Arrays.copyOfRange(ct, u, n);

        for (int i = 7; i >= 0; i--) {
            if (i % 2 == 0) {
                byte[] W = calcW(i); BigInteger P = calcP(i, W, B);
                BigInteger m = BigInteger.valueOf(radix).pow(u);
                BigInteger aNum = toNum(reverse(A));
                int[] c = fromNum(aNum.subtract(P).mod(m), u);
                A = reverse(c);
            } else {
                byte[] W = calcW(i); BigInteger P = calcP(i, W, A);
                BigInteger m = BigInteger.valueOf(radix).pow(v);
                BigInteger bNum = toNum(reverse(B));
                int[] c = fromNum(bNum.subtract(P).mod(m), v);
                B = reverse(c);
            }
        }
        int[] result = new int[n];
        System.arraycopy(A, 0, result, 0, u);
        System.arraycopy(B, 0, result, u, v);
        return result;
    }

    private byte[] calcW(int round) {
        byte[] w = new byte[4];
        System.arraycopy(tweak, round % 2 == 0 ? 4 : 0, w, 0, 4);
        return w;
    }

    private BigInteger calcP(int round, byte[] w, int[] half) throws Exception {
        byte[] input = new byte[16];
        System.arraycopy(w, 0, input, 0, 4);
        input[3] ^= (byte) round;
        BigInteger halfNum = toNum(reverse(half));
        byte[] hb = halfNum.toByteArray();
        if (hb.length <= 12) System.arraycopy(hb, 0, input, 16 - hb.length, hb.length);
        else System.arraycopy(hb, hb.length - 12, input, 4, 12);

        byte[] rev = reverseBytes(input);
        // NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
        // This is single-block encryption used as a building block, not ECB mode applied to user data.
        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return new BigInteger(1, reverseBytes(aes.doFinal(rev)));
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

    private int[] reverse(int[] a) {
        int[] r = new int[a.length];
        for (int i = 0; i < a.length; i++) r[i] = a[a.length - 1 - i];
        return r;
    }

    private byte[] reverseBytes(byte[] a) {
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++) r[i] = a[a.length - 1 - i];
        return r;
    }

    // Factory methods
    public static FF3 digits(byte[] key, byte[] tweak) throws Exception {
        return new FF3(key, tweak, "0123456789");
    }

    public static FF3 alphanumeric(byte[] key, byte[] tweak) throws Exception {
        return new FF3(key, tweak, "0123456789abcdefghijklmnopqrstuvwxyz");
    }

    public static byte[] hexToBytes(String hex) {
        byte[] r = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2)
            r[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        return r;
    }
}
