package io.cyphera;

import java.util.HashMap;
import java.util.Map;

/**
 * Minimal JSON parser for Cyphera policy files.
 * Supports objects, strings, numbers, booleans, null. No arrays.
 * Zero dependencies — pure Java.
 */
final class JsonParser {
    private final String json;
    private int pos;

    private JsonParser(String json) {
        this.json = json;
        this.pos = 0;
    }

    static Map<String, Object> parse(String json) {
        JsonParser p = new JsonParser(json.trim());
        Object result = p.readValue();
        if (!(result instanceof Map)) {
            throw new IllegalArgumentException("Expected JSON object at root");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) result;
        return map;
    }

    private void skipWhitespace() {
        while (pos < json.length() && Character.isWhitespace(json.charAt(pos))) pos++;
    }

    private char peek() {
        skipWhitespace();
        if (pos >= json.length()) throw new IllegalArgumentException("Unexpected end of JSON");
        return json.charAt(pos);
    }

    private char next() {
        skipWhitespace();
        if (pos >= json.length()) throw new IllegalArgumentException("Unexpected end of JSON");
        return json.charAt(pos++);
    }

    private void expect(char c) {
        char actual = next();
        if (actual != c) throw new IllegalArgumentException("Expected '" + c + "' but got '" + actual + "' at pos " + (pos - 1));
    }

    private Object readValue() {
        char c = peek();
        switch (c) {
            case '{': return readObject();
            case '"': return readString();
            case 't': case 'f': return readBoolean();
            case 'n': return readNull();
            default:
                if (c == '-' || Character.isDigit(c)) return readNumber();
                throw new IllegalArgumentException("Unexpected character '" + c + "' at pos " + pos);
        }
    }

    private Map<String, Object> readObject() {
        expect('{');
        Map<String, Object> map = new HashMap<>();
        if (peek() == '}') { next(); return map; }
        while (true) {
            String key = readString();
            expect(':');
            Object value = readValue();
            map.put(key, value);
            char c = next();
            if (c == '}') break;
            if (c != ',') throw new IllegalArgumentException("Expected ',' or '}' but got '" + c + "'");
        }
        return map;
    }

    private String readString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (pos < json.length()) {
            char c = json.charAt(pos++);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                if (pos >= json.length()) throw new IllegalArgumentException("Unexpected end in string escape");
                char esc = json.charAt(pos++);
                switch (esc) {
                    case '"': case '\\': case '/': sb.append(esc); break;
                    case 'n': sb.append('\n'); break;
                    case 't': sb.append('\t'); break;
                    case 'r': sb.append('\r'); break;
                    case 'u':
                        String hex = json.substring(pos, pos + 4);
                        sb.append((char) Integer.parseInt(hex, 16));
                        pos += 4;
                        break;
                    default: sb.append(esc);
                }
            } else {
                sb.append(c);
            }
        }
        throw new IllegalArgumentException("Unterminated string");
    }

    private Boolean readBoolean() {
        if (json.startsWith("true", pos)) { pos += 4; return Boolean.TRUE; }
        if (json.startsWith("false", pos)) { pos += 5; return Boolean.FALSE; }
        throw new IllegalArgumentException("Expected boolean at pos " + pos);
    }

    private Object readNull() {
        if (json.startsWith("null", pos)) { pos += 4; return null; }
        throw new IllegalArgumentException("Expected null at pos " + pos);
    }

    private Number readNumber() {
        int start = pos;
        if (json.charAt(pos) == '-') pos++;
        while (pos < json.length() && (Character.isDigit(json.charAt(pos)) || json.charAt(pos) == '.')) pos++;
        String num = json.substring(start, pos);
        if (num.contains(".")) return Double.parseDouble(num);
        return Integer.parseInt(num);
    }
}
