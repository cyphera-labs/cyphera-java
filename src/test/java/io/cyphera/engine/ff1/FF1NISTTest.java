package io.cyphera.engine.ff1;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class FF1NISTTest {

    static byte[] hex(String h) { return FF1.hexToBytes(h); }

    // NIST SP 800-38G FF1 Test Vectors

    @Test void sample1() throws Exception {
        FF1 c = FF1.digits(hex("2B7E151628AED2A6ABF7158809CF4F3C"), hex(""));
        assertEquals("2433477484", c.encrypt("0123456789"));
        assertEquals("0123456789", c.decrypt("2433477484"));
    }

    @Test void sample2() throws Exception {
        FF1 c = FF1.digits(hex("2B7E151628AED2A6ABF7158809CF4F3C"), hex("39383736353433323130"));
        assertEquals("6124200773", c.encrypt("0123456789"));
        assertEquals("0123456789", c.decrypt("6124200773"));
    }

    @Test void sample3() throws Exception {
        FF1 c = FF1.alphanumeric(hex("2B7E151628AED2A6ABF7158809CF4F3C"), hex("3737373770717273373737"));
        assertEquals("a9tv40mll9kdu509eum", c.encrypt("0123456789abcdefghi"));
        assertEquals("0123456789abcdefghi", c.decrypt("a9tv40mll9kdu509eum"));
    }

    @Test void sample4() throws Exception {
        FF1 c = FF1.digits(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), hex(""));
        assertEquals("2830668132", c.encrypt("0123456789"));
        assertEquals("0123456789", c.decrypt("2830668132"));
    }

    @Test void sample5() throws Exception {
        FF1 c = FF1.digits(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), hex("39383736353433323130"));
        assertEquals("2496655549", c.encrypt("0123456789"));
        assertEquals("0123456789", c.decrypt("2496655549"));
    }

    @Test void sample6() throws Exception {
        FF1 c = FF1.alphanumeric(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), hex("3737373770717273373737"));
        assertEquals("xbj3kv35jrawxv32ysr", c.encrypt("0123456789abcdefghi"));
        assertEquals("0123456789abcdefghi", c.decrypt("xbj3kv35jrawxv32ysr"));
    }

    @Test void sample7() throws Exception {
        FF1 c = FF1.digits(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), hex(""));
        assertEquals("6657667009", c.encrypt("0123456789"));
        assertEquals("0123456789", c.decrypt("6657667009"));
    }

    @Test void sample8() throws Exception {
        FF1 c = FF1.digits(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), hex("39383736353433323130"));
        assertEquals("1001623463", c.encrypt("0123456789"));
        assertEquals("0123456789", c.decrypt("1001623463"));
    }

    @Test void sample9() throws Exception {
        FF1 c = FF1.alphanumeric(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), hex("3737373770717273373737"));
        assertEquals("xs8a0azh2avyalyzuwd", c.encrypt("0123456789abcdefghi"));
        assertEquals("0123456789abcdefghi", c.decrypt("xs8a0azh2avyalyzuwd"));
    }
}
